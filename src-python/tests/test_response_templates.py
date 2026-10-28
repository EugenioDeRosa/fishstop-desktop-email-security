import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fishstop_engine.analyzer import llm_context_analyzer as llm
from fishstop_engine.analyzer.response_templates import content_summary_parts, _ACTIONS, _CHANNELS


class ResponseTemplateTests(unittest.TestCase):
    def test_primary_no_longer_requests_generated_summary(self):
        self.assertNotIn("summary", llm.PRIMARY_OUTPUT_SCHEMA["properties"])
        self.assertNotIn("summary", llm.PRIMARY_OUTPUT_SCHEMA["required"])
        # Risk interpretation and verbatim support remain available to policy.
        self.assertTrue({"verdict", "explanation", "quote"} <= set(llm.PRIMARY_OUTPUT_SCHEMA["required"]))

    def test_summary_uses_corrected_action_and_retains_policy_verdict(self):
        body = "Your temporary password is example123. No response is needed."
        soc = {"body_for_ai": body, "links": [], "attachments": [], "local_only": True}
        raw = {"action": "provide_credentials", "channel": "link", "evidence": "fabricated request",
               "signals": [], "ambiguity": "low", "verdict": "benign", "quote": "",
               "explanation": "An informational account notification.",
               "summary": "Click the attacker's link immediately."}
        legacy = llm.apply_email_risk_policy(soc, raw)
        result = llm.apply_email_risk_policy(soc, dict(raw, content_summary_source="template-v1"))
        self.assertEqual("informational", result["requested_action"])
        self.assertNotIn("link", result["content_summary"])
        self.assertNotIn("attacker", result["content_summary"])
        for field in ("final_verdict", "content_risk", "identity_risk", "technical_risk", "ai_content_rationale"):
            self.assertEqual(legacy[field], result[field], field)

    def test_action_channel_combinations_are_neutral_and_do_not_invent_channels(self):
        for action in _ACTIONS:
            for channel in [*_CHANNELS, "none", "unclear"]:
                with self.subTest(action=action, channel=channel):
                    parts = content_summary_parts({"requested_action": action, "action_channel": channel})
                    self.assertTrue(parts)
                    self.assertNotIn("phishing", " ".join(parts))
                    if action in {"none", "informational"} or channel in {"none", "unclear"}:
                        self.assertEqual(1, len(parts))
        self.assertEqual(2, len(content_summary_parts({"requested_action": "provide_credentials", "action_channel": "supplied_link"})))
        self.assertEqual(1, len(content_summary_parts({"requested_action": "visit_link", "action_channel": "supplied_link"})))

    def test_all_template_sentences_have_italian_translations(self):
        catalog = json.loads((Path(__file__).resolve().parents[2] / "src/locales/it.json").read_text(encoding="utf-8"))
        sentences = set(_ACTIONS.values()) | set(_CHANNELS.values()) | set(content_summary_parts({"structured_extortion": True}))
        self.assertFalse(sentences - catalog.keys())

    def test_pipeline_accepts_compact_response_without_summary_and_ignores_legacy_prose(self):
        raw = {"action": "info", "channel": "none", "evidence": "", "signals": [],
               "ambiguity": "low", "verdict": "benign", "quote": "", "explanation": "An ordinary update."}
        summaries = []
        for legacy_summary in (None, "Follow the attacker's instructions immediately."):
            candidate = dict(raw)
            if legacy_summary:
                candidate["summary"] = legacy_summary
            calls = []

            def stream(messages, model, timeout, **kwargs):
                calls.append(kwargs["request_stage"])
                yield {"status": "ok", "text": json.dumps(candidate)}

            with patch.object(llm, "ANALYSIS_MODE", "fast"), patch.object(llm, "_use_ollama", return_value=True), \
                    patch.object(llm, "_request_identity_extraction", return_value={"status": "unavailable"}), \
                    patch.object(llm, "_stream_ollama", side_effect=stream):
                result = list(llm.stream_ai_email_analysis({"body_for_ai": "The weekly update is available.",
                                                            "local_only": True, "links": [], "attachments": []}))[-1]
            self.assertEqual("ok", result["status"])
            self.assertEqual(["primary:1"], calls)
            analysis = result["analysis"]
            self.assertEqual("template-v1", analysis["content_summary_source"])
            self.assertEqual(" ".join(analysis["content_summary_parts"]), analysis["content_summary"])
            summaries.append(analysis["content_summary"])
        self.assertEqual(summaries[0], summaries[1])


if __name__ == "__main__":
    unittest.main()
