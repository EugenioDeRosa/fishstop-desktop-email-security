import json
import unittest
from unittest.mock import patch

from fishstop_engine.analyzer import llm_context_analyzer as llm


class IdentityExtractionTests(unittest.TestCase):
    def extract(self, report, response):
        response = {"name": response.get("claimed_brand"), "role": response.get("claimed_role"),
                    "source": response.get("source"), "quote": response.get("evidence")}
        with patch.object(llm, "_stream_ollama", return_value=iter([
            {"status": "ok", "text": json.dumps(response)}])):
            return llm._request_identity_extraction(report, model="test", timeout=10)

    def test_names_without_catalogue_and_malformed_sender_punctuation(self):
        for name, sender in [("Binance", "Binance <notice@example.test>"),
                             ("Facebook", "Facebook ,_<notice@example.test>"),
                             ("Unlisted Example", "Unlisted Example <notice@example.test>")]:
            with self.subTest(name=name):
                result = self.extract({"from_": sender}, {
                    "claimed_brand": name, "claimed_role": "representative",
                    "source": "sender", "evidence": name})
                self.assertEqual("ok", result["status"])
                self.assertEqual(name, result["claimed_brand"])

    def test_invented_name_or_quotation_or_source_is_rejected(self):
        base = {"claimed_brand": "Example", "claimed_role": "representative",
                "source": "sender", "evidence": "Example"}
        report = {"from_": "Example <notice@example.test>"}
        for override in [{"claimed_brand": "Other"},
                         {"source": "header"}, {"claimed_brand": "amp", "evidence": "Example"},
                         {"claimed_brand": "", "evidence": "Example"}]:
            self.assertEqual("invalid_evidence", self.extract(report, {**base, **override})["status"])
        self.assertEqual("invalid_evidence", self.extract({"from_": "Person <a@example.test>", "body_clean": "I use Example."},
            {**base, "source": "body", "evidence": "Different security"})["status"])

    def test_paraphrased_quote_can_recover_only_complete_sender_name(self):
        result = self.extract({"from_": "Example <notice@example.test>"}, {
            "claimed_brand": "Example", "claimed_role": "representative", "source": "body",
            "evidence": "Example security says verify your account"})
        self.assertEqual("ok", result["status"])
        self.assertEqual("Example", result["evidence"])
        self.assertEqual("sender", result["source"])
        result = self.extract({"from_": "Person <notice@example.test>", "body_clean": "I use Example."}, {
            "claimed_brand": "Example", "claimed_role": "representative", "source": "body",
            "evidence": "Example security says verify your account"})
        self.assertEqual("invalid_evidence", result["status"])
        result = self.extract({"from_": "Example account team <notice@example.test>"}, {
            "claimed_brand": "Example", "claimed_role": "representative", "source": "body",
            "evidence": "We detected unusual activity"})
        self.assertEqual("ok", result["status"])
        self.assertEqual("Example account team", result["evidence"])
        result = self.extract({"from_": "Example account team <notice@example.test>"}, {
            "claimed_brand": "Example", "claimed_role": "mention", "source": "sender", "evidence": "Example"})
        self.assertEqual("representative", result["claimed_role"])
        result = self.extract({"from_": "Example account team <notice@example.test>"}, {
            "claimed_brand": "Example", "claimed_role": "third_party", "source": "sender", "evidence": "Example"})
        self.assertEqual("third_party", result["claimed_role"])

    def test_line_wrapping_and_wrong_source_recover_original_quote(self):
        report = {"from_": "Example <notice@example.test>", "body_clean": "Your account\nExample"}
        result = self.extract(report, {"claimed_brand": "Example", "claimed_role": "representative",
            "source": "sender", "evidence": "Your account Example"})
        self.assertEqual("ok", result["status"])
        self.assertEqual("body", result["source"])
        self.assertEqual("Your account Example", result["evidence"])

    def test_mentions_and_absent_identity_remain_separate(self):
        result = self.extract({"body_clean": "I bought this at Example."}, {
            "claimed_brand": "Example", "claimed_role": "mention",
            "source": "body", "evidence": "I bought this at Example."})
        self.assertEqual("mention", result["claimed_role"])
        self.assertEqual("", self.extract({}, {"claimed_brand": "", "claimed_role": "unclear",
                                              "source": "none", "evidence": ""})["claimed_brand"])

    def test_backend_failure_is_explicit(self):
        with patch.object(llm, "_stream_ollama", return_value=iter([{"status": "error"}])):
            self.assertEqual("unavailable", llm._request_identity_extraction({}, model="test", timeout=10)["status"])

    def test_domain_fragments_do_not_supply_identity_evidence(self):
        report = {"body_clean": "Visit https://www.example.com/login"}
        self.assertEqual([], llm._claimed_brand_occurrences(report, "Example"))
        response = {"claimed_brand": "Example", "claimed_role": "mention", "source": "body",
                    "evidence": "Visit https://www.example.com/login"}
        self.assertEqual("invalid_evidence", self.extract(report, response)["status"])
        report["subject"] = "[Example] Login details"
        result = self.extract(report, response)
        self.assertEqual("ok", result["status"])
        self.assertEqual("subject", result["source"])
        self.assertEqual("Example", result["evidence"])

    def test_identity_and_requested_action_can_be_grounded_in_selected_pdf(self):
        report = {"body_clean": "", "attachments": [{"actionable": True, "pdf_security": {
            "text_excerpt": "Your Example account is restricted. Verify your account. The Example Security Team"}}]}
        result = self.extract(report, {"claimed_brand": "Example", "claimed_role": "representative",
            "source": "attachment", "evidence": "The Example Security Team"})
        self.assertEqual("ok", result["status"])
        self.assertEqual("attachment", result["source"])
        self.assertEqual("Verify your account", llm._validated_evidence(report, "Verify your account"))
        self.assertEqual("attachment", llm._claimed_brand_occurrences(report, "Example")[0]["source"])
        report["attachments"][0]["actionable"] = False
        self.assertEqual([], llm._claimed_brand_occurrences(report, "Example"))

    def test_explicit_branded_security_signature_recovers_representation(self):
        report = {"attachments": [{"actionable": True, "pdf_security": {
            "text_excerpt": "Your Example account is limited. Safely yours, The Example Security Team"}}]}
        response = {"claimed_brand": "Example", "claimed_role": "mention", "source": "attachment", "evidence": "Your Example account is limited."}
        result = self.extract(report, response)
        self.assertEqual("representative", result["claimed_role"])
        self.assertEqual("Safely yours, The Example Security Team", result["evidence"])
        report["attachments"][0]["pdf_security"]["text_excerpt"] = "I talked to The Example Security Team"
        response["evidence"] = "The Example Security Team"
        self.assertEqual("mention", self.extract(report, response)["claimed_role"])

    def test_invalid_field_types_and_cancellation(self):
        self.assertEqual("invalid_response", self.extract({}, {
            "claimed_brand": "Example", "claimed_role": [], "source": {}, "evidence": "Example"})["status"])
        with patch.object(llm, "_stream_ollama") as stream:
            self.assertEqual("cancelled", llm._request_identity_extraction(
                {}, model="test", timeout=10, cancellation_requested=lambda: True)["status"])
            stream.assert_not_called()

    def test_empty_dedicated_identity_clears_primary_claim_without_catalogue_fallback(self):
        with patch.object(llm, "_stream_ollama", return_value=iter([{
                "status": "ok", "text": json.dumps({"action": "informational",
                "channel": "none", "claimed_brand": "Microsoft", "claimed_role": "representative"})}])), \
             patch.object(llm, "_request_identity_extraction", return_value={
                 "status": "ok", "claimed_brand": "", "claimed_role": "unclear"}), \
             patch.object(llm, "_use_ollama", return_value=True), \
             patch.object(llm, "ANALYSIS_MODE", "fast"), \
             patch.object(llm, "_visible_identity_fallback", side_effect=AssertionError("No dictionary")):
            result = list(llm.stream_phi4_email_analysis({
                "from_": "Microsoft <notice@example.test>", "body_clean": "An update."}))[-1]
        self.assertEqual("ok", result["status"])
        self.assertEqual([], result["identity_analysis"]["entities"])
        self.assertEqual("", result["analysis"]["claimed_brand"])

    def test_pipeline_uses_dedicated_identity_and_records_timing(self):
        models = []
        def stream(messages, model, timeout, **kwargs):
            stage = kwargs.get("request_stage")
            models.append((stage, model))
            response = ({"name": "Unlisted Example", "role": "representative",
                         "source": "sender", "quote": "Unlisted Example"}
                        if stage == "identity" else
                        {"summary": "The message provides an update.", "action": "informational",
                         "channel": "none", "claimed_brand": "", "confidence": .9})
            kwargs["telemetry"].append({"stage": stage, "wall_duration_ms": 5})
            yield {"status": "ok", "text": json.dumps(response)}
        with patch.object(llm, "_stream_ollama", side_effect=stream), \
             patch.object(llm, "_use_ollama", return_value=True), \
             patch.object(llm, "ANALYSIS_MODE", "fast"), \
             patch.object(llm, "IDENTITY_MODEL", "identity-test"), \
             patch.object(llm, "_visible_identity_fallback", side_effect=AssertionError("No brand dictionary")), \
             patch("fishstop_engine.brand_intelligence.assess_brand_coherence", return_value=[]):
            result = list(llm.stream_phi4_email_analysis({
                "from_": "Unlisted Example <notice@example.test>", "body_clean": "An update."}, model="risk-test"))[-1]
        self.assertEqual("ok", result["status"])
        self.assertEqual("Unlisted Example", result["identity_analysis"]["entities"][0]["name"])
        self.assertEqual("representative", result["identity_analysis"]["impersonation"]["claimed_role"])
        self.assertEqual("ok", result["identity_analysis"]["extraction"]["status"])
        self.assertGreaterEqual(result["performance"]["identity_extraction_seconds"], 0)
        self.assertEqual(["primary:1", "identity"], [call["stage"] for call in result["performance"]["calls"]])
        self.assertEqual([("primary:1", "risk-test"), ("identity", "identity-test")], models)
        self.assertEqual("identity-test", result["identity_analysis"]["model"])


if __name__ == "__main__":
    unittest.main()
