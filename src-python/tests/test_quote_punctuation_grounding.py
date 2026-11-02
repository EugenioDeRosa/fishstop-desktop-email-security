"""Model quotations must not be rejected for typographic punctuation alone.

Regression (E027, "Your Bank Account has been blocked"): the verifier quoted
``Click on 'Reactivate Your Account`` while the email used typographic
quotation marks.  The quote was discarded as ``invalid_quote``, the verifier
was marked unavailable and the message stayed in review although both passes
said phishing.  The verbatim-substring requirement itself must still hold.
"""

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fishstop_engine.analyzer import llm_context_analyzer as llm

E027_BODY = (
    "Dear Customer,\n"
    "Your Bank Account has been blocked due to unusual activity.\n"
    "Click on ‘Reactivate Your Account’ to restore access within 24 hours.\n"
    "Année « compte bloqué » – service clients.\n"
    "Don’t ignore this “final notice”.\n"
)


def _soc(body=E027_BODY):
    return {"subject": "Your Bank Account has been blocked", "body_for_ai": body,
            "links": [], "attachments": []}


class QuotePunctuationGroundingTests(unittest.TestCase):
    def test_typographic_and_ascii_quotes_are_interchangeable(self):
        soc = _soc()
        for quote in (
            "Click on 'Reactivate Your Account",          # E027: cut through the quote
            "Click on 'Reactivate Your Account'",
            "Click on \"Reactivate Your Account\"",
            "Don't ignore this \"final notice\"",
            "compte bloqué \" - service",              # guillemet and en dash retyped
            "'Reactivate Your Account'",                    # whole quote wrapped in quotes
            "“final notice”",
        ):
            with self.subTest(quote=quote):
                self.assertTrue(llm._validated_evidence(soc, quote), quote)

    def test_typographic_quote_matches_ascii_email_text(self):
        soc = _soc("Click on 'Reactivate Your Account' now. Don't wait - act today.")
        for quote in ("Click on ‘Reactivate Your Account’", "Don’t wait – act today"):
            with self.subTest(quote=quote):
                self.assertTrue(llm._validated_evidence(soc, quote))

    def test_edge_punctuation_added_or_dropped_by_the_model(self):
        soc = _soc()
        for quote in (
            "Your Bank Account has been blocked.",          # period not in the source
            "restore access within 24 hours",               # period dropped
            "(Reactivate Your Account)",
            "blocked due to unusual activity!",
        ):
            with self.subTest(quote=quote):
                evidence = llm._validated_evidence(soc, quote)
                self.assertTrue(evidence, quote)
                self.assertFalse(evidence.endswith(("!", ")")), evidence)

    def test_substring_requirement_is_preserved(self):
        soc = _soc()
        for quote in (
            "Click on 'Reset Your Password'",               # different words
            "Your Bank Account has been blocked forever.",  # extra word
            "Reactivate Your Account today",
            "'...'",                                        # punctuation only
            "!!!",
        ):
            with self.subTest(quote=quote):
                self.assertEqual("", llm._validated_evidence(soc, quote))

    def test_e027_verifier_quote_is_accepted(self):
        soc = _soc()
        answer = {
            "verdict": "phishing",
            "quote": "Click on 'Reactivate Your Account",
            "explanation": "An unexpected account block is paired with a reactivation instruction under time pressure.",
            "basis": "contextual_deception",
        }

        def fake_stream(messages, model, timeout, output_schema=None, *, request_stage="", telemetry=None, num_predict=None):
            yield {"status": "ok", "text": json.dumps(answer)}

        with patch.object(llm, "_stream_ollama", side_effect=fake_stream):
            result = llm._request_content_risk_verification(soc, model="test", timeout=5)
        self.assertEqual("confirmed", result["status"], result)
        self.assertEqual("phishing", result["assessment"])
        self.assertTrue(result["evidence"])


if __name__ == "__main__":
    unittest.main()
