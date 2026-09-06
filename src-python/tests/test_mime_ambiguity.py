import tempfile
import unittest
from pathlib import Path

from fishstop_engine.analyzer.llm_context_analyzer import _technical_risk
from fishstop_engine.analyzer.soc_analyzer import EmlSOCAnalyzer


class MimeAmbiguityTests(unittest.TestCase):
    def test_duplicate_singleton_headers_are_reported(self):
        report = self._analyze(
            b"From: first@example.com\r\n"
            b"From: second@evil.example\r\n"
            b"Subject: First subject\r\n"
            b"Subject: Second subject\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"Hello.\r\n"
        )

        duplicate_headers = {
            finding.get("header")
            for finding in report["mime_findings"]
            if finding["kind"] == "duplicate_header"
        }
        self.assertEqual({"From", "Subject"}, duplicate_headers)
        self.assertEqual(2, report["mime_duplicate_header_count"])
        self.assertEqual("review", report["mime_status"])
        self.assertTrue(any(
            flag["level"] == "MEDIUM" and flag["field"] == "MIME structure"
            for flag in report["flags"]
        ))

    def test_malformed_base64_defects_are_reported(self):
        report = self._analyze(
            b"From: sender@example.com\r\n"
            b"To: recipient@example.net\r\n"
            b"Subject: Encoded body\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n"
            b"SGVsbG8$%%%%\r\n"
        )

        defect_codes = {
            finding["code"]
            for finding in report["mime_findings"]
            if finding["kind"] == "parser_defect"
        }
        self.assertIn("InvalidBase64CharactersDefect", defect_codes)
        self.assertIn("InvalidBase64PaddingDefect", defect_codes)
        self.assertEqual(len(defect_codes), report["mime_defect_count"])

    def test_missing_multipart_boundary_is_reported(self):
        report = self._analyze(
            b"From: sender@example.com\r\n"
            b"Subject: Broken multipart\r\n"
            b"Content-Type: multipart/alternative; boundary=missing\r\n"
            b"\r\n"
            b"This payload has no declared boundary markers.\r\n"
        )

        defect_codes = {finding["code"] for finding in report["mime_findings"]}
        self.assertIn("StartBoundaryNotFoundDefect", defect_codes)
        self.assertIn("MultipartInvariantViolationDefect", defect_codes)

    def test_divergent_alternatives_are_both_sent_to_ai(self):
        report = self._analyze(self._multipart_message(
            "Hello, this is the ordinary monthly company newsletter.",
            "<html><body><h1>Urgent security warning</h1>"
            "<p>Your account is suspended. Send your password immediately and "
            "visit https://evil.example/login now.</p></body></html>",
        ))

        alternative_analysis = report["mime_alternative_analysis"]
        self.assertEqual("divergent", alternative_analysis["status"])
        self.assertEqual(1, alternative_analysis["divergent_group_count"])
        self.assertIn("ordinary monthly company newsletter", report["body_for_ai"])
        self.assertIn("Send your password immediately", report["body_for_ai"])
        self.assertEqual("mime_alternatives", report["body_context"])
        self.assertTrue(any(
            link["url"] == "https://evil.example/login"
            for link in report["links"]
        ))
        self.assertTrue(any(
            flag["level"] == "MEDIUM" and flag["field"] == "MIME alternatives"
            for flag in report["flags"]
        ))
        technical_status, reasons = _technical_risk(report)
        self.assertEqual("uncertain", technical_status)
        self.assertIn(
            "the visible MIME alternatives contain substantially different content",
            reasons,
        )

    def test_equivalent_alternatives_do_not_create_a_risk_flag(self):
        text = "Hello customer, your monthly statement is now available."
        report = self._analyze(self._multipart_message(text, f"<p>{text}</p>"))

        self.assertEqual("consistent", report["mime_alternative_analysis"]["status"])
        self.assertEqual("clean", report["mime_status"])
        self.assertFalse(any(
            flag["field"] == "MIME alternatives"
            for flag in report["flags"]
        ))
        self.assertNotIn("[MIME alternative:", report["body_for_ai"])

    def test_empty_plain_alternative_cannot_hide_html_content(self):
        report = self._analyze(self._multipart_message(
            "",
            "<p>Urgent account verification is required. Enter your password "
            "and recovery code in the linked portal immediately.</p>",
        ))

        analysis = report["mime_alternative_analysis"]
        self.assertEqual("divergent", analysis["status"])
        self.assertEqual(2, analysis["groups"][0]["alternative_count"])
        self.assertIn("Enter your password", report["body_for_ai"])

    @staticmethod
    def _multipart_message(plain: str, html: str) -> bytes:
        return (
            "From: Sender <sender@example.com>\r\n"
            "To: recipient@example.net\r\n"
            "Subject: Alternative content\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: multipart/alternative; boundary=alt\r\n"
            "\r\n"
            "--alt\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "\r\n"
            f"{plain}\r\n"
            "--alt\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "\r\n"
            f"{html}\r\n"
            "--alt--\r\n"
        ).encode("utf-8")

    @staticmethod
    def _analyze(raw: bytes) -> dict:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "message.eml"
            path.write_bytes(raw)
            return EmlSOCAnalyzer().analyze(str(path))


if __name__ == "__main__":
    unittest.main()
