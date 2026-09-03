import tempfile
import unittest
from pathlib import Path

from fishstop_engine.analyzer.soc_analyzer import EmlSOCAnalyzer
from fishstop_engine.analyzer.llm_context_analyzer import _return_path_mismatch_context


class ReturnPathDmarcPolicyTests(unittest.TestCase):
    def analyze(self, dmarc_status: str | None) -> dict:
        authentication = (
            "Authentication-Results: mx.example; spf=pass smtp.mailfrom=mailer.test; "
            "dkim=pass header.d=brand.example; "
            f"dmarc={dmarc_status} header.from=brand.example\n"
            if dmarc_status
            else ""
        )
        message = (
            "From: Brand <notice@brand.example>\n"
            "To: user@example.net\n"
            "Return-Path: <bounce@mailer.test>\n"
            f"{authentication}"
            "Subject: Account notice\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "\n"
            "This is an informational message.\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "message.eml"
            path.write_text(message, encoding="utf-8")
            return EmlSOCAnalyzer().analyze(str(path))

    @staticmethod
    def return_path_flags(report: dict) -> list[dict]:
        return [flag for flag in report["flags"] if flag["field"] == "Return-Path"]

    def test_dmarc_pass_keeps_mismatch_without_verdict_flag(self):
        report = self.analyze("pass")
        self.assertTrue(report["return_path_domain_mismatch"])
        self.assertEqual([], self.return_path_flags(report))

    def test_dmarc_fail_keeps_mismatch_as_technical_context(self):
        report = self.analyze("fail")
        flags = self.return_path_flags(report)
        self.assertEqual("MEDIUM", flags[0]["level"])
        self.assertIn("relevant technical context", flags[0]["message"])

    def test_unavailable_dmarc_keeps_mismatch_as_weak_signal(self):
        report = self.analyze(None)
        flags = self.return_path_flags(report)
        self.assertEqual("LOW", flags[0]["level"])
        self.assertIn("weak evidence", flags[0]["message"])

    def test_qwen_context_omits_mismatch_when_dmarc_passes(self):
        self.assertEqual("", _return_path_mismatch_context(self.analyze("pass")))

    def test_qwen_context_labels_unavailable_dmarc_as_weak(self):
        context = _return_path_mismatch_context(self.analyze(None))
        self.assertIn("weak evidence", context)
        self.assertIn("correlate", context)


if __name__ == "__main__":
    unittest.main()
