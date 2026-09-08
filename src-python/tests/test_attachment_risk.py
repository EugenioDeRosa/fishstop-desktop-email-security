import io
import tempfile
import unittest
import zipfile
from pathlib import Path

from fishstop_engine.analyzer.attachment import (
    _static_pdf_indicators,
    analyze_attachment,
    analyze_pdf_security,
)
from fishstop_engine.analyzer.soc_analyzer import EmlSOCAnalyzer


class AttachmentRiskTests(unittest.TestCase):
    @staticmethod
    def finding_keys(result: dict) -> set[str]:
        security = result.get("attachment_security") or {}
        return {str(item.get("key")) for item in security.get("findings") or []}

    def test_consistent_executable_and_script_types_are_high_risk(self):
        cases = [
            (
                "payload.exe",
                "application/x-msdownload",
                b"MZ\x90\x00executable",
                {"dangerous_extension", "dangerous_mime_type", "dangerous_magic_bytes"},
            ),
            (
                "payload.js",
                "application/javascript",
                b"alert('test');",
                {"dangerous_extension", "dangerous_mime_type"},
            ),
            (
                "run.ps1",
                "text/plain",
                b"Write-Host 'test'",
                {"dangerous_extension"},
            ),
        ]

        for filename, content_type, payload, expected_findings in cases:
            with self.subTest(filename=filename):
                result = analyze_attachment(filename, content_type, "8bit", payload)
                self.assertTrue(result["extension_match"])
                self.assertEqual("high", result["attachment_security"]["risk_level"])
                self.assertTrue(expected_findings.issubset(self.finding_keys(result)))
                self.assertIn("High-risk attachment", result["anomaly"])

    def test_executable_magic_is_high_risk_without_dangerous_extension(self):
        result = analyze_attachment(
            "payload.bin",
            "application/octet-stream",
            "base64",
            b"MZ\x90\x00executable",
        )
        self.assertEqual("high", result["attachment_security"]["risk_level"])
        self.assertIn("dangerous_magic_bytes", self.finding_keys(result))

    def test_double_extension_and_bidirectional_control_are_high_risk(self):
        double_extension = analyze_attachment(
            "invoice.pdf.exe",
            "application/x-msdownload",
            "base64",
            b"MZ\x90\x00executable",
        )
        bidi_name = analyze_attachment(
            "invoice\u202egnp.txt",
            "text/plain",
            "8bit",
            b"plain text",
        )

        self.assertIn("double_extension", self.finding_keys(double_extension))
        self.assertIn("bidirectional_filename_control", self.finding_keys(bidi_name))
        self.assertEqual("high", bidi_name["attachment_security"]["risk_level"])

    def test_benign_text_attachment_remains_clean(self):
        result = analyze_attachment(
            "notes.txt",
            "text/plain",
            "8bit",
            b"ordinary notes",
        )
        self.assertEqual("clean", result["attachment_security"]["risk_level"])
        self.assertEqual([], result["attachment_security"]["findings"])
        self.assertIsNone(result["anomaly"])

    def test_decoded_attachment_size_is_reported_in_bytes(self):
        payload = b"small test payload"
        result = analyze_attachment(
            "document.txt",
            "text/plain",
            "8bit",
            payload,
        )

        self.assertEqual(result["size_bytes"], len(payload))

    def test_binary_stream_bytes_are_not_interpreted_as_pdf_names(self):
        raw = (
            b"%PDF-1.4\n1 0 obj\n<</Length 24>>\nstream\n"
            b"binary#fb/JavaScript data\nendstream\nendobj\n%%EOF"
        )
        indicators, stats = _static_pdf_indicators(raw)

        self.assertEqual(stats["suspicious_name_escapes"], 0)
        self.assertNotIn("javascript", indicators)

    def test_pdf_features_are_not_double_counted_and_empty_form_is_ignored(self):
        from pypdf import PdfWriter
        from pypdf.generic import ArrayObject, DictionaryObject, NameObject

        writer = PdfWriter()
        writer.add_blank_page(width=100, height=100)
        writer.add_uri(0, "https://example.com", (0, 0, 50, 20))
        writer.root_object[NameObject("/AcroForm")] = DictionaryObject({
            NameObject("/Fields"): ArrayObject(),
        })
        output = io.BytesIO()
        writer.write(output)

        security = analyze_pdf_security(output.getvalue())
        indicator_counts = {
            item["key"]: item["count"] for item in security["indicators"]
        }

        self.assertEqual(indicator_counts["uri"], 1)
        self.assertNotIn("acroform", indicator_counts)
        self.assertEqual(security["field_count"], 0)
        self.assertEqual(security["uri_evidence"]["uri_action_url_count"], 1)

    def test_archive_uses_the_same_dangerous_extension_policy(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("payload.py", "print('test')")

        result = analyze_attachment(
            "sources.zip",
            "application/zip",
            "base64",
            buffer.getvalue(),
        )
        finding_keys = {
            item["key"] for item in result["archive_security"]["findings"]
        }
        self.assertIn("dangerous_file", finding_keys)
        self.assertEqual("high", result["archive_security"]["risk_level"])

    def test_soc_report_emits_high_flag_for_consistent_script(self):
        raw = (
            b"From: sender@example.com\r\n"
            b"To: recipient@example.net\r\n"
            b"Subject: Script\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=fishstop\r\n"
            b"\r\n"
            b"--fishstop\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"See attachment.\r\n"
            b"--fishstop\r\n"
            b"Content-Type: application/javascript\r\n"
            b"Content-Disposition: attachment; filename=payload.js\r\n"
            b"Content-Transfer-Encoding: 8bit\r\n"
            b"\r\n"
            b"alert('test');\r\n"
            b"--fishstop--\r\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            eml_path = Path(directory) / "script.eml"
            eml_path.write_bytes(raw)
            report = EmlSOCAnalyzer().analyze(str(eml_path))

        attachment = report["attachments"][0]
        self.assertEqual("high", attachment["attachment_security"]["risk_level"])
        self.assertTrue(any(
            flag["level"] == "HIGH" and flag["field"] == "Attachment"
            for flag in report["flags"]
        ))


if __name__ == "__main__":
    unittest.main()
