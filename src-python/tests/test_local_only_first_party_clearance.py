"""Point 7: Local-only legitimate mail with first-party links or clean files.

Local only disables the independent DNS/DKIM verification, so no unlisted
sender was ever "verified" and every unverifiable link or attachment forced
review (89/352 legitimate emails in the v8 replay). The exception accepts the
receiving server's own DMARC pass only for benign, non-sensitive mail whose
requested destinations all belong to the sender's own registrable domain and
whose attachments were inspected clean. Everything else must stay in review.
"""

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fishstop_engine.analyzer import llm_context_analyzer as llm

PASS = {"SPF": {"status": "pass", "source": "Authentication-Results"},
        "DKIM": {"status": "pass", "source": "Authentication-Results"},
        "DMARC": {"status": "pass", "source": "Authentication-Results"}}


def _link(host="www.negozio-esempio.it", registered="negozio-esempio.it", **extra):
    return {"url": f"https://{host}/ordini/1234", "host": host, "registered_domain": registered,
            "scheme": "https", "display_text": "Segui la spedizione", "role": "body_action",
            "actionable": True, "html_call_to_action": True, **extra}


def _pdf(**extra):
    return {"filename": "fattura-1234.pdf", "content_type": "application/pdf", "extension_from_filename": "pdf",
            "actionable": True, "mime_role": "attachment",
            "pdf_security": {"risk_level": "clean", "analysis_complete": True},
            "attachment_security": {"risk_level": "clean"}, **extra}


def _soc(**overrides):
    soc = {
        "from_": "Ordini Negozio <ordini@negozio-esempio.it>",
        "subject": "Conferma ordine 1234",
        "body_for_ai": "Grazie per il tuo ordine 1234. Puoi seguire la spedizione dalla tua area clienti.",
        "links": [_link()], "attachments": [], "flags": [],
        "local_only": True, "domain_authentication": {"status": "disabled"},
        "effective_auth_results": copy.deepcopy(PASS),
    }
    soc.update(overrides)
    return soc


def _raw(**overrides):
    raw = {"verdict": "benign", "quote": "", "explanation": "An ordinary order confirmation from the shop.",
           "action": "visit_link", "channel": "link", "evidence": "Segui la spedizione",
           "signals": [], "ambiguity": "low", "claimed_brand": "Negozio"}
    raw.update(overrides)
    return raw


def _analyze(soc, raw):
    soc["identity_analysis"] = llm._identity_analysis_from_semantic(soc, dict(raw), local_fallback=False)
    return llm.apply_email_risk_policy(soc, dict(raw))


class LocalOnlyFirstPartyClearanceTests(unittest.TestCase):
    def test_order_confirmation_with_first_party_link_is_legitimate(self):
        analysis = _analyze(_soc(), _raw())
        self.assertEqual("legitimate", analysis["final_verdict"])
        self.assertTrue(analysis["local_only_first_party_clearance"])
        self.assertIn(analysis["local_only_first_party_clearance"], analysis["evidence"]["identity"])

    def test_subdomain_of_the_sender_is_first_party(self):
        analysis = _analyze(_soc(links=[_link("track.negozio-esempio.it")]), _raw())
        self.assertEqual("legitimate", analysis["final_verdict"])

    def test_invoice_with_clean_pdf_is_legitimate(self):
        soc = _soc(links=[], attachments=[_pdf()], body_for_ai="In allegato la fattura 1234 del tuo ordine.")
        raw = _raw(action="open_attachment", channel="attachment", evidence="In allegato la fattura 1234")
        analysis = _analyze(soc, raw)
        self.assertEqual("legitimate", analysis["final_verdict"], analysis["evidence"])

    def test_without_local_only_nothing_changes(self):
        soc = _soc(local_only=False, domain_authentication={"status": "unverified", "verified_domains": []})
        analysis = _analyze(soc, _raw())
        self.assertEqual("", analysis["local_only_first_party_clearance"])


class LocalOnlyClearanceStaysNarrowTests(unittest.TestCase):
    def _assert_review(self, soc, raw=None):
        analysis = _analyze(soc, raw or _raw())
        self.assertEqual("", analysis["local_only_first_party_clearance"])
        self.assertNotEqual("legitimate", analysis["final_verdict"])

    def test_link_to_another_domain(self):
        self._assert_review(_soc(links=[_link("click.mailer-esp.com", "mailer-esp.com")]))

    def test_one_of_several_links_elsewhere(self):
        self._assert_review(_soc(links=[_link(), _link("negozio-esempio.example", "negozio-esempio.example")]))

    def test_structurally_suspicious_first_party_link(self):
        self._assert_review(_soc(links=[_link(display_mismatch=True)]))

    def test_dmarc_not_pass(self):
        for status in ("none", "fail", "unknown"):
            with self.subTest(status=status):
                auth = copy.deepcopy(PASS)
                auth["DMARC"]["status"] = status
                self._assert_review(_soc(effective_auth_results=auth))

    def test_dmarc_only_from_a_relayed_arc_claim(self):
        auth = copy.deepcopy(PASS)
        auth["DMARC"]["source"] = "ARC-Authentication-Results"
        self._assert_review(_soc(effective_auth_results=auth))

    def test_spf_or_dkim_failure_despite_dmarc_pass(self):
        auth = copy.deepcopy(PASS)
        auth["DKIM"]["status"] = "fail"
        self._assert_review(_soc(effective_auth_results=auth))

    def test_model_not_benign_or_without_rationale(self):
        self._assert_review(_soc(), _raw(verdict="suspicious", quote="Segui la spedizione"))
        self._assert_review(_soc(), _raw(explanation=""))

    def test_sensitive_request(self):
        self._assert_review(_soc(body_for_ai="Verifica il tuo account dal link qui sotto."),
                            _raw(action="verify_account", evidence="Verifica il tuo account"))

    def test_reply_to_mismatch_or_display_name_spoofing(self):
        self._assert_review(_soc(reply_to_mismatch=True))
        self._assert_review(_soc(display_name_spoofing=True))

    def test_medium_static_flag(self):
        self._assert_review(_soc(flags=[{"level": "MEDIUM", "field": "Link", "message": "Shortened URL"}]))

    def test_forwarded_message(self):
        self._assert_review(_soc(forwarded_identity={"from": "Altro <altro@altrove.example>"}))

    def test_attachment_not_clean_or_not_fully_inspected(self):
        raw = _raw(action="open_attachment", channel="attachment", evidence="In allegato la fattura 1234")
        body = "In allegato la fattura 1234 del tuo ordine."
        for attachment in (
            _pdf(pdf_security={"risk_level": "medium", "analysis_complete": True}),
            _pdf(pdf_security={"risk_level": "clean", "analysis_complete": False}),
            {**_pdf(filename="fattura.docm", extension_from_filename="docm"),
             "office_security": {"risk_level": "clean", "analysis_complete": False}},
            _pdf(anomaly="extension does not match content"),
        ):
            with self.subTest(attachment=attachment.get("filename")):
                self._assert_review(_soc(links=[], attachments=[attachment], body_for_ai=body), raw)


if __name__ == "__main__":
    unittest.main()
