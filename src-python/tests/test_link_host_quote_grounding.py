"""A quoted link destination host is grounded email data.

Regression (E020, "Liberação de IRPF"): the prompt lists each link's host in
the ``LINK DESTINATIONS OBSERVED IN EMAIL`` block inside the email boundary.
The model quoted that host as its evidence, but validation accepted only the
subject, body and link text, so the quote was dropped and the verdict became
review with "its supporting quotation could not be validated".

The prompt layout is unchanged on purpose: FAST v7.1/v8 were trained on it.
"""

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fishstop_engine.analyzer import llm_context_analyzer as llm

HOST = "okokoaksoa.z13.web.core.windows.net"


def _soc():
    return {
        "from_": "Receita Federal <noreply@receita-aviso.com.br>",
        "subject": "Liberação de IRPF",
        "body_for_ai": "Sua restituição do IRPF foi liberada. Consulte o extrato para receber o valor.",
        "links": [
            {"url": f"https://{HOST}/irpf/index.html", "host": HOST,
             "display_text": "Consultar extrato", "role": "body_action", "actionable": True},
            {"url": "mailto:atendimento@receita-aviso.com.br", "host": "receita-aviso.com.br",
             "display_text": "Fale conosco", "role": "body_action", "actionable": True},
        ],
        "attachments": [],
    }


class LinkHostQuoteGroundingTests(unittest.TestCase):
    def test_host_shown_in_the_prompt_is_in_the_link_block(self):
        self.assertIn(f'"host":"{HOST}"', llm.build_fast_email_prompt(_soc()))

    def test_quoted_link_host_is_accepted(self):
        soc = _soc()
        for quote, expected in (
            (HOST, HOST),
            (HOST.upper(), HOST),
            (f"https://{HOST}", HOST),
            (f"https://{HOST}/", HOST),
            (f"'{HOST}'", HOST),
            ("z13.web.core.windows.net", "z13.web.core.windows.net"),   # registrable part
            ("atendimento@receita-aviso.com.br", "atendimento@receita-aviso.com.br"),  # mailto recipient
        ):
            with self.subTest(quote=quote):
                self.assertEqual(expected, llm._validated_evidence(soc, quote))

    def test_unrelated_or_partial_domains_are_rejected(self):
        soc = _soc()
        for quote in (
            "evil.example.com",                 # not a link in the email
            "windows.net",                      # public suffix only
            "core.windows.net",
            "kokoaksoa.z13.web.core.windows.net",  # not on a label boundary
            f"https://{HOST}/irpf/index.html",  # the path is not shown to the model
            "receita.gov.br",
        ):
            with self.subTest(quote=quote):
                self.assertEqual("", llm._validated_evidence(soc, quote))

    def test_e020_primary_quote_keeps_its_evidence(self):
        soc = _soc()
        raw = {
            "verdict": "suspicious", "quote": HOST,
            "explanation": "A tax refund notice sends the recipient to an unrelated cloud storage host.",
            "action": "visit_link", "channel": "link", "evidence": "Consultar extrato",
            "signals": ["incentive"], "ambiguity": "low",
        }
        normalized = llm.normalize_semantic_extraction(raw, soc=soc)
        self.assertEqual(HOST, normalized["model_risk_evidence"])
        analysis = llm.apply_email_risk_policy(soc, raw)
        self.assertEqual(HOST, analysis["ai_content_evidence"])
        self.assertNotIn("could not be validated", json.dumps(analysis))

    def test_e020_verifier_quote_is_not_invalid(self):
        soc = _soc()
        answer = {"verdict": "phishing", "quote": HOST, "basis": "contextual_deception",
                  "explanation": "A government refund is redirected to an unrelated cloud storage host."}

        def fake_stream(messages, model, timeout, output_schema=None, *, request_stage="", telemetry=None, num_predict=None):
            yield {"status": "ok", "text": json.dumps(answer)}

        with patch.object(llm, "_stream_ollama", side_effect=fake_stream):
            result = llm._request_content_risk_verification(soc, model="test", timeout=5)
        self.assertEqual("confirmed", result["status"], result)
        self.assertEqual(HOST, result["evidence"])


if __name__ == "__main__":
    unittest.main()
