"""Point 10: very long emails are compacted and capped before the AI.

E041 (213 KB) needed 17 AI calls and 272 s. Long catalog/list runs are now
shortened deterministically and, in fast/balanced mode, at most
AI_MAX_ANALYZED_SECTIONS sections reach the model: first, last and the
middle sections with the most action/risk cues. Short emails are unchanged.
"""

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fishstop_engine.analyzer import llm_context_analyzer as llm

PROSE = ("Questo mese abbiamo rinnovato il negozio con nuove collezioni e consigli di stagione "
         "per tutta la famiglia, con articoli dedicati alla casa e al tempo libero. ")
LURE = "Il tuo account verrà sospeso: verifica la password tramite il link qui sotto entro oggi."


def _catalog(rows=60):
    return "\n".join(f"Articolo {i} Linea Casa — €{i}9,99 — https://shop.esempio.it/p/{i}" for i in range(rows))


def _long_body(paragraphs=120, lure_at=None):
    parts = [f"Sezione {i}. " + PROSE * 2 for i in range(paragraphs)]
    if lure_at is not None:
        parts[lure_at] = LURE
    return "\n\n".join(parts)


def _soc(body):
    return {"from_": "Negozio <news@esempio.it>", "subject": "Novità di novembre",
            "body_for_ai": body, "links": [], "attachments": []}


class ListCollapseTests(unittest.TestCase):
    def test_catalog_run_keeps_first_and_last_rows(self):
        text, omitted = llm._collapse_list_runs(_catalog(60))
        self.assertEqual(55, omitted)
        self.assertIn("Articolo 0 Linea Casa", text)
        self.assertIn("Articolo 59 Linea Casa", text)
        self.assertNotIn("Articolo 30 Linea Casa", text)
        self.assertIn("55 similar list rows omitted", text)

    def test_risk_row_inside_a_catalog_is_kept(self):
        rows = _catalog(40).split("\n")
        rows[20] = "Articolo 20 — verifica la password del tuo account: https://shop.esempio.it/login"
        text, _ = llm._collapse_list_runs("\n".join(rows))
        self.assertIn(rows[20], text)

    def test_prose_and_short_lists_are_untouched(self):
        prose = "\n".join(PROSE for _ in range(30))
        self.assertEqual((prose, 0), llm._collapse_list_runs(prose))
        short = _catalog(7)
        self.assertEqual((short, 0), llm._collapse_list_runs(short))


class SectionSelectionTests(unittest.TestCase):
    def _prompts(self, soc, mode="balanced"):
        with patch.object(llm, "ANALYSIS_MODE", mode):
            return llm._build_complete_email_prompts(soc)

    def test_short_email_is_sent_whole_and_unchanged(self):
        soc = _soc("Ciao, ci vediamo venerdì alle 10 in ufficio.\n" + _catalog(10))
        prompts = self._prompts(soc)
        self.assertEqual(1, len(prompts))
        self.assertEqual(llm._prepared_email_prompt_parts(soc)[1], prompts[0][0])
        self.assertEqual(0, soc["ai_section_selection"]["skipped_sections"])

    def test_long_email_is_capped_and_keeps_the_risky_section(self):
        soc = _soc(_long_body(160, lure_at=95))
        prompts = self._prompts(soc)
        selection = soc["ai_section_selection"]
        self.assertGreater(selection["total_sections"], llm.AI_MAX_ANALYZED_SECTIONS)
        self.assertEqual(llm.AI_MAX_ANALYZED_SECTIONS, len(prompts))
        self.assertIn(1, selection["analyzed_sections"])
        self.assertIn(selection["total_sections"], selection["analyzed_sections"])
        self.assertTrue(any(LURE in body for body, _ in prompts))
        # Each prompt still states its real position in the email.
        self.assertIn(f"section=1/{selection['total_sections']}", prompts[0][1])

    def test_more_than_twelve_sections_no_longer_disables_the_ai(self):
        soc = _soc(_long_body(300))
        prompts = self._prompts(soc)
        self.assertGreater(soc["ai_section_selection"]["total_sections"], llm.MAX_AI_SECTIONS)
        self.assertEqual(llm.AI_MAX_ANALYZED_SECTIONS, len(prompts))

    def test_thorough_mode_keeps_every_section(self):
        soc = _soc(_long_body(60))  # 8 sections: above the fast/balanced budget
        prompts = self._prompts(soc, mode="thorough")
        self.assertGreater(len(prompts), llm.AI_MAX_ANALYZED_SECTIONS)
        self.assertEqual(soc["ai_section_selection"]["total_sections"], len(prompts))
        with self.assertRaises(llm.EmailAnalysisLimitError):
            self._prompts(_soc(_long_body(300)), mode="thorough")

    def test_catalog_newsletter_needs_fewer_sections(self):
        body = PROSE + "\n" + "\n".join(_catalog(400).split("\n")) + "\n" + PROSE
        soc = _soc(body)
        self._prompts(soc)
        self.assertGreater(soc["ai_section_selection"]["collapsed_list_rows"], 300)
        self.assertEqual(1, soc["ai_section_selection"]["total_sections"])


class E041LikePipelineTests(unittest.TestCase):
    def test_primary_calls_are_bounded(self):
        calls = []

        def fake(messages, model, timeout, output_schema=None, *, request_stage="", telemetry=None, num_predict=None):
            calls.append(request_stage)
            payload = ({"name": "", "role": "unclear", "source": "none", "quote": ""} if request_stage == "identity"
                       else {"verdict": "benign", "quote": "", "explanation": "A long newsletter.", "action": "info",
                             "channel": "none", "evidence": "", "signals": [], "ambiguity": "none"})
            yield {"status": "ok", "text": json.dumps(payload)}

        soc = _soc(_long_body(250) + "\n\n" + _catalog(300))
        with (patch.object(llm, "ANALYSIS_MODE", "balanced"), patch.object(llm, "_use_ollama", return_value=True),
              patch.object(llm, "_stream_ollama", side_effect=fake),
              patch("fishstop_engine.brand_intelligence.assess_brand_coherence", return_value=[])):
            events = list(llm.stream_ai_email_analysis(soc))
        self.assertEqual("ok", events[-1]["status"], events[-1])
        primary = [c for c in calls if c.startswith("primary:")]
        self.assertEqual(llm.AI_MAX_ANALYZED_SECTIONS, len(primary))
        self.assertIn("section_selection", events[-1]["performance"])


if __name__ == "__main__":
    unittest.main()
