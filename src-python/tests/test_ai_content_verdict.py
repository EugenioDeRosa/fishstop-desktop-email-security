import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fishstop_engine.analyzer import llm_context_analyzer as llm


class AIContentVerdictTests(unittest.TestCase):
    def setUp(self):
        # Synthetic evidence, deliberately unrelated to a particular campaign.
        self.body = "An unexpected benefit is waiting. Your supplied account is ready."
        self.soc = {"body_for_ai": self.body, "links": [], "attachments": []}
        self.raw = {
            "summary": "The email announces a benefit and supplies account access.",
            "action": "info", "channel": "none", "evidence": "", "signals": [],
            "ambiguity": "low", "risk_assessment": "phishing",
            "risk_evidence": "An unexpected benefit is waiting.",
            "risk_rationale": "The unexplained benefit and supplied account access together form a deceptive lure.",
        }

    def test_grounded_ai_verdict_does_not_require_action_or_channel(self):
        result = llm.apply_email_risk_policy(self.soc, self.raw)
        self.assertEqual("phishing", result["final_verdict"])
        self.assertEqual("informational", result["requested_action"])
        self.assertEqual("none", result["action_channel"])
        self.assertEqual(self.raw["risk_rationale"], result["ai_content_rationale"])
        self.assertIn(self.raw["risk_rationale"], llm.format_email_risk_analysis(result))
        self.assertTrue(llm._needs_content_risk_verifier(self.soc, self.raw))

    def test_successful_authentication_does_not_erase_content_verdict(self):
        self.soc["effective_auth_results"] = {name: {"status": "pass"} for name in ("SPF", "DKIM", "DMARC")}
        self.assertEqual("phishing", llm.apply_email_risk_policy(self.soc, self.raw)["final_verdict"])

    def test_suspicion_without_channel_requires_review(self):
        self.raw["risk_assessment"] = "suspicious"
        self.assertEqual("review", llm.apply_email_risk_policy(self.soc, self.raw)["final_verdict"])

    def test_verbatim_but_unexplained_warning_requires_review(self):
        self.raw.pop("risk_rationale")
        self.assertEqual("review", llm.apply_email_risk_policy(self.soc, self.raw)["final_verdict"])

    def test_fabricated_or_approximately_matching_risk_quote_cannot_convict(self):
        for quote in ("A phrase absent from the email", "An unexpected benefit is waiting for you.", ""):
            with self.subTest(quote=quote):
                self.raw["risk_evidence"] = quote
                result = llm.apply_email_risk_policy(self.soc, self.raw)
                self.assertEqual("review", result["final_verdict"])
                self.assertEqual("", result["ai_content_evidence"])
                self.assertTrue(llm._needs_content_risk_verifier(self.soc, self.raw))

    def test_normalization_preserves_independent_risk(self):
        normalized = llm.normalize_semantic_extraction(self.raw, soc=self.soc)
        result = llm.apply_email_risk_policy(self.soc, normalized)
        self.assertEqual("phishing", result["final_verdict"])
        self.assertEqual(self.raw["risk_rationale"], result["ai_content_rationale"])

    def test_plain_judgement_fields_survive_normalization_and_section_merge(self):
        raw = dict(self.raw)
        raw["verdict"] = raw.pop("risk_assessment")
        raw["quote"] = raw.pop("risk_evidence")
        raw["explanation"] = raw.pop("risk_rationale")
        for candidate in (raw, llm.normalize_semantic_extraction(raw, soc=self.soc)):
            with self.subTest(candidate=candidate):
                merged = llm._merge_semantic_candidates([candidate], self.soc)
                result = llm.apply_email_risk_policy(self.soc, merged)
                self.assertEqual("phishing", result["final_verdict"])
                self.assertEqual(raw["quote"], result["ai_content_evidence"])

    def test_another_sections_generic_benign_alias_cannot_shadow_the_risk_winner(self):
        benign = dict(self.raw, verdict="benign", quote="", explanation="A routine update.")
        merged = llm._merge_semantic_candidates([benign, self.raw], self.soc)
        self.assertEqual("phishing", llm.apply_email_risk_policy(self.soc, merged)["final_verdict"])

    def test_verified_organisation_conflict_triggers_second_assessment(self):
        with patch.object(llm, "_requested_links_match_verified_organisation", return_value=True):
            self.assertTrue(llm._needs_content_risk_verifier(self.soc, self.raw))

    def test_cancelled_second_assessment_does_not_call_model(self):
        with patch.object(llm, "_stream_ollama") as stream:
            result = llm._request_content_risk_verification(self.soc, model="test", timeout=5,
                                                          cancellation_requested=lambda: True)
        self.assertEqual("unavailable", result["status"])
        stream.assert_not_called()

    def test_independent_malicious_evidence_does_not_add_redundant_verification(self):
        with patch.object(llm, "_technical_risk", return_value=("malicious", ["Confirmed malicious attachment"])):
            self.assertFalse(llm._needs_content_risk_verifier(self.soc, self.raw))

    def test_unsubstantiated_impersonation_tag_cannot_bypass_content_reasoning(self):
        body = "Please enable camera permission in the attached setup guide."
        soc = dict(self.soc, body_for_ai=body, attachments=[{"filename": "guide.pdf", "actionable": True}])
        raw = dict(self.raw, action="change_settings", channel="attachment", evidence=body,
                   signals=["impersonation"], risk_assessment="suspicious", risk_evidence=body)
        with patch.object(llm, "_deterministic_identity_deception", return_value=False):
            result = llm.apply_email_risk_policy(soc, raw)
        self.assertEqual("review", result["final_verdict"])
        with patch.object(llm, "_deterministic_identity_deception", return_value=True):
            result = llm.apply_email_risk_policy(soc, raw)
        self.assertEqual("phishing", result["final_verdict"])

    def test_supported_narrative_survives_real_verification_without_an_action(self):
        def stream(messages, model, timeout, **kwargs):
            if kwargs["request_stage"] == "content-risk-verification":
                response = {"verdict": "phishing", "quote": self.raw["risk_evidence"],
                            "explanation": self.raw["risk_rationale"], "basis": "contextual_deception"}
            else:
                response = self.raw
            yield {"status": "ok", "text": json.dumps(response)}
        with patch.object(llm, "ANALYSIS_MODE", "fast"), patch.object(llm, "_use_ollama", return_value=True), \
                patch.object(llm, "_request_identity_extraction", return_value={"status": "unavailable"}), \
                patch.object(llm, "_stream_ollama", side_effect=stream):
            result = list(llm.stream_ai_email_analysis(dict(self.soc)))[-1]["analysis"]
        self.assertEqual("phishing", result["final_verdict"])
        self.assertEqual("informational", result["requested_action"])
        trace = result["ai_content_trace"]
        self.assertEqual("confirmed", trace["verification"]["status"])
        self.assertEqual(64, len(trace["primary_sections"][0]["body_sha256"]))
        self.assertEqual("informational", trace["primary_sections"][0]["after_action_audits"]["requested_action"])

    def test_action_winner_cannot_erase_risk_in_another_section(self):
        self.soc["body_for_ai"] += " Please review the attachment."
        self.soc["attachments"] = [{"filename": "handbook.pdf", "actionable": True}]
        benign = dict(self.raw, action="open_attachment", channel="attachment",
                      evidence="Please review the attachment.", risk_assessment="benign",
                      risk_evidence="", risk_rationale="An ordinary document request.")
        for candidates in ([self.raw, benign], [benign, self.raw]):
            merged = llm._merge_semantic_candidates(candidates, self.soc)
            self.assertEqual("open_attachment", merged["action"])
            self.assertEqual("phishing", llm.apply_email_risk_policy(self.soc, merged)["final_verdict"])

    def test_unresolved_verification_retains_warning(self):
        for status in ("disagreement", "unavailable"):
            with self.subTest(status=status):
                self.raw["risk_verification"] = {"status": status}
                result = llm.apply_email_risk_policy(self.soc, self.raw)
                self.assertEqual("review", result["final_verdict"])
                self.assertEqual(status, result["ai_content_verification"]["status"])

    def test_malicious_technical_evidence_overrides_benign_ai(self):
        self.raw.update(risk_assessment="benign", risk_evidence="", risk_rationale="A routine notification.")
        with patch.object(llm, "_technical_risk", return_value=("malicious", ["Confirmed malicious attachment"])):
            self.assertEqual("phishing", llm.apply_email_risk_policy(self.soc, self.raw)["final_verdict"])

    def test_ordinary_receipt_and_account_delivery_remain_benign(self):
        for body in ("Your payment was received. Thank you.", "Your requested account is ready. Your temporary password is 123abc."):
            with self.subTest(body=body):
                raw = dict(self.raw, risk_assessment="benign", risk_evidence="", risk_rationale="A routine requested notification.")
                soc = dict(self.soc, body_for_ai=body)
                self.assertEqual("legitimate", llm.apply_email_risk_policy(soc, raw)["final_verdict"])

    def test_second_assessment_does_not_receive_first_vote(self):
        seen = []
        def stream(messages, model, timeout, **kwargs):
            seen.extend(messages)
            self.assertEqual("content-risk-verification", kwargs["request_stage"])
            yield {"status": "ok", "text": json.dumps({"verdict": self.raw["risk_assessment"], "quote": self.raw["risk_evidence"], "explanation": self.raw["risk_rationale"], "basis": "contextual_deception"})}
        with patch.object(llm, "_stream_ollama", side_effect=stream):
            result = llm._request_content_risk_verification(self.soc, model="test", timeout=5)
        self.assertEqual("confirmed", result["status"])
        self.assertNotIn(self.raw["risk_rationale"], str(seen))
        self.assertIn("<UNTRUSTED_EMAIL>", str(seen))

    def test_second_assessment_disagreement_and_errors(self):
        responses = [
            ({"risk_assessment": "benign", "risk_evidence": "", "risk_rationale": "A routine notification."}, "disagreement"),
            ({"risk_assessment": "phishing", "risk_evidence": "fabricated quotation", "risk_rationale": "A lure."}, "unavailable"),
            ({"risk_assessment": "invalid", "risk_evidence": "", "risk_rationale": "A lure."}, "unavailable"),
            ({}, "unavailable"),
        ]
        for raw, expected in responses:
            response = {alias: raw[key] for key, alias in (("risk_assessment", "verdict"), ("risk_evidence", "quote"), ("risk_rationale", "explanation")) if key in raw}
            response["basis"] = "ordinary_context" if raw.get("risk_assessment") == "benign" else "contextual_deception"
            with self.subTest(raw=raw), patch.object(llm, "_stream_ollama", return_value=iter([{"status": "ok", "text": json.dumps(response)}])):
                self.assertEqual(expected, llm._request_content_risk_verification(self.soc, model="test", timeout=5)["status"])
        with patch.object(llm, "_stream_ollama", return_value=iter([{"status": "error"}])):
            self.assertEqual("unavailable", llm._request_content_risk_verification(self.soc, model="test", timeout=5)["status"])

    def test_pipeline_uses_ai_verdict_in_each_mode_and_model(self):
        for mode in ("fast", "balanced", "thorough"):
            for model in ("pro-test", "fast-test"):
                with self.subTest(mode=mode, model=model), patch.object(llm, "ANALYSIS_MODE", mode), patch.object(llm, "_use_ollama", return_value=True), patch.object(llm, "_request_identity_extraction", return_value={"status": "unavailable"}), patch.object(llm, "_request_content_risk_verification", return_value={"status": "confirmed", "evidence": self.raw["risk_evidence"], "rationale": self.raw["risk_rationale"]}), patch.object(llm, "_stream_ollama", return_value=iter([{"status": "ok", "text": json.dumps(self.raw)}])):
                    events = list(llm.stream_ai_email_analysis(dict(self.soc), model=model))
                    self.assertEqual("ok", events[-1]["status"])
                    self.assertEqual("phishing", events[-1]["analysis"]["final_verdict"])

    def test_pipeline_verifies_a_corrected_action_and_exposes_disagreement(self):
        body = "Your security code is 654321. Enter it in your independently opened login screen."
        soc = dict(self.soc, body_for_ai=body)
        raw = dict(self.raw, action="provide_credentials", channel="known_procedure",
                   evidence="Enter it in your independently opened login screen.",
                   risk_evidence="Your security code is 654321.")
        for status, expected in (("confirmed", "phishing"), ("disagreement", "review"), ("unavailable", "review")):
            with self.subTest(status=status), patch.object(llm, "ANALYSIS_MODE", "fast"), patch.object(llm, "_use_ollama", return_value=True), patch.object(llm, "_request_identity_extraction", return_value={"status": "unavailable"}), patch.object(llm, "_stream_ollama", return_value=iter([{"status": "ok", "text": json.dumps(raw)}])), patch.object(llm, "_request_content_risk_verification", return_value={"status": status}) as verify:
                verify.return_value.update(evidence=raw["risk_evidence"], rationale=raw["risk_rationale"])
                result = list(llm.stream_ai_email_analysis(dict(soc)))[-1]
                self.assertEqual("ok", result["status"])
                self.assertEqual(expected, result["analysis"]["final_verdict"])
                verify.assert_called_once()

    def test_pipeline_recovers_a_bad_quote_without_changing_the_ai_vote(self):
        raw = dict(self.raw, risk_evidence="A fabricated quotation")
        verification = {"status": "confirmed", "assessment": "phishing",
                        "evidence": self.raw["risk_evidence"], "rationale": self.raw["risk_rationale"]}
        with patch.object(llm, "ANALYSIS_MODE", "fast"), patch.object(llm, "_use_ollama", return_value=True), patch.object(llm, "_request_identity_extraction", return_value={"status": "unavailable"}), patch.object(llm, "_stream_ollama", return_value=iter([{"status": "ok", "text": json.dumps(raw)}])), patch.object(llm, "_request_content_risk_verification", return_value=verification) as verify:
            result = list(llm.stream_ai_email_analysis(dict(self.soc)))[-1]
        self.assertEqual("phishing", result["analysis"]["final_verdict"])
        self.assertEqual(self.raw["risk_evidence"], result["analysis"]["ai_content_evidence"])
        verify.assert_called_once()

    def test_unverifiable_quote_remains_review_if_retry_fails(self):
        raw = dict(self.raw, risk_evidence="A fabricated quotation", risk_verification={"status": "unavailable"})
        result = llm.apply_email_risk_policy(self.soc, raw)
        self.assertEqual("review", result["final_verdict"])
        self.assertEqual("phishing", result["ai_content_assessment"])
        self.assertEqual("", result["ai_content_evidence"])

    def test_verbatim_quote_and_phishing_vote_are_insufficient_without_mechanism(self):
        for basis in ("isolated_feature", "ordinary_context", "uncertain"):
            response = {"verdict": "phishing", "quote": self.raw["risk_evidence"],
                        "explanation": "A supplied account alone does not establish deception.", "basis": basis}
            with self.subTest(basis=basis), patch.object(llm, "_stream_ollama", return_value=iter([
                {"status": "ok", "text": json.dumps(response)}
            ])):
                verification = llm._request_content_risk_verification(self.soc, model="test", timeout=5)
            self.assertEqual("disagreement", verification["status"])
            self.assertEqual(basis, verification["sections"][0]["basis"])
            self.assertEqual(1, verification["sections"][0]["section"])
            result = llm.apply_email_risk_policy(self.soc, dict(self.raw, risk_verification=verification))
            self.assertEqual("review", result["final_verdict"])
            self.assertEqual("phishing", result["ai_content_assessment"])

    def test_failed_verification_records_the_actual_failure(self):
        responses = [
            ({"verdict": "phishing", "quote": "invented", "explanation": "A lure.",
              "basis": "contextual_deception"}, "invalid_quote"),
            ({"verdict": "phishing", "quote": self.raw["risk_evidence"], "explanation": "",
              "basis": "contextual_deception"}, "missing_rationale"),
            ({"verdict": "phishing"}, "invalid_structured_response"),
        ]
        for response, reason in responses:
            with self.subTest(reason=reason), patch.object(llm, "_stream_ollama", return_value=iter([
                {"status": "ok", "text": json.dumps(response)}
            ])):
                verification = llm._request_content_risk_verification(self.soc, model="test", timeout=5)
            self.assertEqual("unavailable", verification["status"])
            self.assertEqual(reason, verification["reason"])

    def test_trace_preserves_initial_action_when_policy_corrects_it(self):
        body = "Your temporary password is example123."
        soc = dict(self.soc, body_for_ai=body)
        raw = dict(self.raw, action="provide_credentials", risk_evidence=body, evidence=body)
        verification = {"status": "disagreement", "reason": "no_supported_deceptive_mechanism",
                        "basis": "isolated_feature", "assessment": "benign"}
        with patch.object(llm, "ANALYSIS_MODE", "fast"), patch.object(llm, "_use_ollama", return_value=True), \
                patch.object(llm, "_request_identity_extraction", return_value={"status": "unavailable"}), \
                patch.object(llm, "_stream_ollama", return_value=iter([{"status": "ok", "text": json.dumps(raw)}])), \
                patch.object(llm, "_request_content_risk_verification", return_value=verification):
            result = list(llm.stream_ai_email_analysis(soc))[-1]["analysis"]
        trace = result["ai_content_trace"]
        self.assertEqual("provide_credentials", trace["primary_sections"][0]["requested_action"])
        self.assertEqual("informational", trace["final_action"])
        self.assertEqual("phishing", trace["primary_sections"][0]["assessment"])
        self.assertEqual("review", trace["final_verdict"])
        self.assertIn("action_corrected_to_information", trace["verification_reasons"])
        self.assertEqual(verification, trace["verification"])

    def test_weak_technical_anomaly_cannot_convict_unresolved_ai_warning(self):
        for status in ("disagreement", "unavailable"):
            raw = dict(self.raw, risk_verification={"status": status})
            with self.subTest(status=status), patch.object(llm, "_technical_risk", return_value=("uncertain", ["Unknown destination"])):
                result = llm.apply_email_risk_policy(self.soc, raw)
                self.assertEqual("review", result["final_verdict"])


if __name__ == "__main__":
    unittest.main()
