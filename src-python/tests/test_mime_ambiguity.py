import tempfile
import unittest
from pathlib import Path

from fishstop_engine.analyzer.llm_context_analyzer import _technical_context_lines, _technical_risk
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
        self.assertTrue(all(
            finding.get("category") == "security_ambiguity"
            for finding in report["mime_findings"]
            if finding["kind"] == "duplicate_header"
        ))
        self.assertEqual(2, report["mime_duplicate_header_count"])
        self.assertEqual("review", report["mime_status"])
        self.assertTrue(any(
            flag["level"] == "MEDIUM" and flag["field"] == "MIME structure"
            for flag in report["flags"]
        ))

    def test_equivalent_duplicate_sender_is_informational(self):
        report = self._analyze(
            b"From: Example Sender <sender@example.com>\r\n"
            b"From: sender@example.com\r\n"
            b"Subject: Duplicate but equivalent sender\r\n"
            b"\r\n"
            b"Hello.\r\n"
        )

        finding = next(
            finding for finding in report["mime_findings"]
            if finding["kind"] == "duplicate_header"
        )
        self.assertEqual("INFO", finding["level"])
        self.assertEqual("compatibility_notice", finding["category"])
        self.assertFalse(finding["values_diverge"])
        self.assertFalse(finding["domains_diverge"])
        self.assertEqual("notice", report["mime_status"])

    def test_duplicate_sender_on_different_domains_is_security_ambiguity(self):
        report = self._analyze(
            b"From: sender@example.com\r\n"
            b"From: sender@evil.example\r\n"
            b"Subject: Conflicting sender\r\n"
            b"\r\n"
            b"Hello.\r\n"
        )

        finding = next(
            finding for finding in report["mime_findings"]
            if finding["kind"] == "duplicate_header"
        )
        self.assertEqual("MEDIUM", finding["level"])
        self.assertEqual("security_ambiguity", finding["category"])
        self.assertTrue(finding["values_diverge"])
        self.assertTrue(finding["domains_diverge"])
        self.assertIn("example.com", finding["distinct_domains"])
        self.assertIn("evil.example", finding["distinct_domains"])

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
        self.assertEqual("review", report["mime_status"])
        levels = {finding["code"]: finding["level"] for finding in report["mime_findings"]}
        self.assertEqual("MEDIUM", levels["InvalidBase64CharactersDefect"])
        self.assertEqual("LOW", levels["InvalidBase64PaddingDefect"])
        self.assertTrue(all(
            finding.get("category") == "damaged_content"
            for finding in report["mime_findings"]
        ))
        technical_status, reasons = _technical_risk(report)
        self.assertEqual("clean", technical_status)
        self.assertEqual(["no strong technical threat was detected"], reasons)

    def test_metadata_only_defect_is_a_notice_not_phishing_evidence(self):
        report = self._analyze(
            b"From: sender@example.com\r\n"
            b"To: recipient@example.net\r\n"
            b"Date: definitely-not-a-date\r\n"
            b"Subject: Ordinary message\r\n"
            b"\r\n"
            b"Hello.\r\n"
        )

        date_finding = next(
            finding for finding in report["mime_findings"]
            if finding["code"] == "InvalidDateDefect"
        )
        self.assertEqual("INFO", date_finding["level"])
        self.assertEqual("notice", report["mime_status"])
        self.assertEqual(0, report["mime_review_finding_count"])
        technical_status, reasons = _technical_risk(report)
        self.assertEqual("clean", technical_status)
        self.assertEqual(["no strong technical threat was detected"], reasons)

    def test_truncated_closing_boundary_is_visible_but_not_verdict_changing(self):
        report = self._analyze(
            b"From: sender@example.com\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=part\r\n"
            b"\r\n"
            b"--part\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"A message truncated in transit.\r\n"
        )

        finding = next(
            finding for finding in report["mime_findings"]
            if finding["code"] == "CloseBoundaryNotFoundDefect"
        )
        self.assertEqual("LOW", finding["level"])
        self.assertEqual("damaged_content", finding["category"])
        self.assertEqual("notice", report["mime_status"])
        self.assertIn("truncated in transit", report["body_for_ai"])

    def test_security_relevant_source_repair_is_included_in_mime_status(self):
        raw = (
            b"From: sender@example.com\r\n"
            b"Subject: Repaired source\r\n"
            b"\r\n"
            b"Hello.\r\n"
        )
        source_finding = {
            "kind": "source_normalization",
            "code": "DiscardedLeadingNonHeaderLines",
            "level": "MEDIUM",
            "part_path": "1",
            "count": 1,
            "message": "One leading source line was ignored.",
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "message.eml"
            path.write_bytes(raw)
            report = EmlSOCAnalyzer().analyze(
                str(path), source_mime_findings=[source_finding]
            )

        self.assertEqual("review", report["mime_status"])
        self.assertEqual("security_ambiguity", report["mime_findings"][0]["category"])
        self.assertEqual(1, report["mime_review_finding_count"])
        self.assertTrue(any(
            finding["code"] == "DiscardedLeadingNonHeaderLines"
            for finding in report["mime_findings"]
        ))

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

    def test_link_difference_is_strong_even_when_alternative_text_matches(self):
        text = "Hello customer, review your account status in the secure portal today."
        report = self._analyze(self._multipart_message(
            f"{text} https://paypal.com/login",
            f'<p>{text}</p><a class="button" href="https://paypa1.com/login">Open portal</a>',
        ))

        analysis = report["mime_alternative_analysis"]
        group = analysis["groups"][0]
        difference = group["link_differences"][0]
        self.assertEqual("divergent", analysis["status"])
        self.assertTrue(group["link_mismatch"])
        self.assertGreater(group["minimum_similarity"], 0.70)
        self.assertIn("paypa1.com", difference["right_only_domains"])
        self.assertIn("paypa1.com", difference["lookalike_domains"])
        self.assertIn("text/html alternative introduces link domain(s) paypa1.com", analysis["message"])
        self.assertIn("lookalike infrastructure", analysis["message"])
        self.assertTrue(any(
            flag["field"] == "MIME alternatives" and "paypa1.com" in flag["message"]
            for flag in report["flags"]
        ))
        self.assertTrue(any(
            "paypa1.com" in line and "lookalike infrastructure" in line
            for line in _technical_context_lines(report)
        ))

    def test_reordered_equivalent_alternatives_are_not_marked_divergent(self):
        report = self._analyze(self._multipart_message(
            "Invoice 42 is available. Contact accounting for questions.",
            "<p>Contact accounting for questions.</p><p>Invoice 42 is available.</p>",
        ))

        self.assertEqual("consistent", report["mime_alternative_analysis"]["status"])
        self.assertEqual("clean", report["mime_status"])

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
