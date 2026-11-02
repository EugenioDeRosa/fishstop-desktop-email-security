"""The security_lure audit must see the identity/domain coherence.

Regression: ``claimed_identity_domain_mismatch`` was read from
``soc["identity_analysis"]``, which is only built after every section and
audit has run, so the observation given to the model was always ``false``.
"""

import json
import re
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fishstop_engine.analyzer import llm_context_analyzer as llm

EVIDENCE = "Your account has been locked. Verify your account using the button below."

MISMATCH = [{
    "brand": "Microsoft",
    "status": "mismatch",
    "official_domain": "microsoft.com",
    "official_domains": ["microsoft.com"],
    "associated_domains": [],
    "reference_status": "registry",
    "mismatches": [{"source": "From"}],
}]
ALIGNED = [{
    "brand": "Microsoft",
    "status": "aligned",
    "official_domain": "microsoft.com",
    "official_domains": ["microsoft.com"],
    "associated_domains": [],
}]


def _soc(**overrides):
    soc = {
        "from_": "Microsoft Security <alerts@example.net>",
        "subject": "Microsoft security alert",
        "body_for_ai": EVIDENCE,
        "links": [{
            "url": "https://example.net/review",
            "host": "example.net",
            "display_text": "Verify your account",
            "role": "body_action",
            "actionable": True,
        }],
        "attachments": [],
    }
    soc.update(overrides)
    return soc


def _primary():
    return {
        "summary": "The email presents a security alert and asks the reader to use a link.",
        "action": "visit_link",
        "channel": "link",
        "evidence": EVIDENCE,
        "signals": ["impersonation"],
        "signal_evidence": "Microsoft Security",
        "credential_type": "none",
        "payment_method": "none",
        "payment_asset": "",
        "amount": "",
        "payment_destination_change": False,
        "payment_change_evidence": "",
        "coercion": False,
        "threat_type": "none",
        "scam_type": "none",
        "claimed_brand": "Microsoft",
        "confidence": 0.7,
        "ambiguity": "none",
        "risk_assessment": "suspicious",
        "risk_evidence": "",
    }


def _security_lure_answer():
    return {
        "security_alert": True,
        "requested_external_action": True,
        "identity_deception": True,
        "claimed_brand": "Microsoft",
        "evidence": EVIDENCE,
    }


IDENTITY_ANSWER = {
    "name": "Microsoft",
    "role": "representative",
    "source": "sender",
    "quote": "Microsoft Security",
}


class SecurityLureSeesIdentityCoherenceTests(unittest.TestCase):
    def _run(self, mode, coherence, soc=None):
        calls: list[str] = []
        prompts: dict[str, str] = {}

        def fake_stream(messages, model, timeout, output_schema=None, *,
                        request_stage="unspecified", telemetry=None, num_predict=None):
            calls.append(request_stage)
            prompts[request_stage] = messages[-1]["content"]
            if request_stage == "identity":
                result = IDENTITY_ANSWER
            elif request_stage.startswith("audit:"):
                checks = request_stage.split(":", 1)[1].split("+")
                result = {}
                if "security_lure" in checks:
                    result["security_lure"] = _security_lure_answer()
                if "intent" in checks:
                    result["intent"] = {
                        "action": "verify_account", "channel": "link", "evidence": EVIDENCE,
                        "payment_method": "none", "payment_asset": "", "amount": "",
                        "coercion": False, "threat_type": "account_loss", "scam_type": "account_takeover",
                    }
            elif request_stage == "verifier:security_lure":
                result = _security_lure_answer()
            elif request_stage.startswith("verifier:"):
                result = {}
            else:
                result = _primary()
            if telemetry is not None:
                telemetry.append({"stage": request_stage, "wall_duration_ms": 1})
            yield {"status": "ok", "model": model, "backend": "ollama",
                   "text": json.dumps(result), "metrics": {"stage": request_stage}}

        with (
            patch.object(llm, "ANALYSIS_MODE", mode),
            patch.object(llm, "_use_ollama", return_value=True),
            patch.object(llm, "_stream_ollama", side_effect=fake_stream),
            patch("fishstop_engine.brand_intelligence.assess_brand_coherence",
                  return_value=coherence) as coherence_lookup,
        ):
            events = list(llm.stream_ai_email_analysis(soc or _soc()))
        self.assertEqual("ok", events[-1]["status"], events[-1])
        return events[-1], calls, prompts, coherence_lookup

    @staticmethod
    def _observation(prompt: str) -> dict:
        match = re.search(r"APPLICATION_OBSERVATIONS: (\{.*?\})\n", prompt)
        assert match, prompt
        return json.loads(match.group(1))

    def _security_lure_prompt(self, prompts):
        stage = next(stage for stage in prompts if "security_lure" in stage)
        return prompts[stage]

    def test_balanced_audit_receives_the_domain_mismatch(self):
        result, calls, prompts, lookup = self._run("balanced", MISMATCH)
        self.assertLess(calls.index("identity"), next(i for i, c in enumerate(calls) if "security_lure" in c))
        self.assertEqual(1, calls.count("identity"), "identity extraction must not be repeated")
        observation = self._observation(self._security_lure_prompt(prompts))
        self.assertTrue(observation["claimed_identity_domain_mismatch"])
        self.assertEqual("example.net", observation["sender_domain"])
        # Lookups and baseline updates run once; the final report reuses them.
        self.assertEqual(1, lookup.call_count)
        self.assertEqual(MISMATCH, result["identity_analysis"]["coherence"])
        self.assertTrue(result["analysis"]["semantic_extraction"].get("identity_deception"))

    def test_thorough_verifier_receives_the_domain_mismatch(self):
        _, calls, prompts, lookup = self._run("thorough", MISMATCH)
        self.assertIn("verifier:security_lure", calls)
        self.assertLess(calls.index("identity"), calls.index("verifier:security_lure"))
        self.assertEqual(1, calls.count("identity"))
        observation = self._observation(prompts["verifier:security_lure"])
        self.assertTrue(observation["claimed_identity_domain_mismatch"])
        self.assertEqual(1, lookup.call_count)

    def test_aligned_identity_is_not_reported_as_a_mismatch(self):
        _, _, prompts, _ = self._run("balanced", ALIGNED)
        self.assertFalse(self._observation(self._security_lure_prompt(prompts))["claimed_identity_domain_mismatch"])

    def test_local_only_mode_performs_no_lookup(self):
        _, _, prompts, lookup = self._run("balanced", MISMATCH, soc=_soc(local_only=True))
        self.assertEqual(0, lookup.call_count)
        self.assertFalse(self._observation(self._security_lure_prompt(prompts))["claimed_identity_domain_mismatch"])

    def test_pre_audit_view_does_not_leak_into_the_report(self):
        soc = _soc()
        result, _, _, _ = self._run("balanced", MISMATCH, soc=soc)
        self.assertNotIn("pre_audit_identity", soc)
        self.assertNotIn("pre_audit_identity", result)


if __name__ == "__main__":
    unittest.main()
