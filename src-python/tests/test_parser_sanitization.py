import hashlib
import tempfile
import unittest
from email import policy
from email.parser import BytesParser
from pathlib import Path

from fishstop_engine.analyzer.soc_analyzer import (
    EmlSOCAnalyzer,
    _redacted_eml_preview,
)
from fishstop_engine.parser import _sanitize_eml_bytes, _sanitize_eml_bytes_with_findings


class EmlSanitizationTests(unittest.TestCase):
    def test_binary_attachment_is_preserved_byte_for_byte(self):
        attachment = b"\x00\xc2\xa0\xe2\x80\x83\xffbinary\r\ncontent"
        raw = (
            b"From: sender@example.com\r\n"
            b"To: recipient@example.net\r\n"
            b"Subject: Binary attachment\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=fishstop\r\n"
            b"\r\n"
            b"--fishstop\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Transfer-Encoding: binary\r\n"
            b"Content-Disposition: attachment; filename=sample.bin\r\n"
            b"\r\n"
            + attachment
            + b"\r\n--fishstop--\r\n"
        )

        sanitized = _sanitize_eml_bytes(raw)
        original_body = raw.split(b"\r\n\r\n", 1)[1]
        sanitized_body = sanitized.split(b"\r\n\r\n", 1)[1]
        self.assertEqual(original_body, sanitized_body)

        message = BytesParser(policy=policy.default).parsebytes(sanitized)
        parsed_attachment = next(message.iter_attachments()).get_payload(decode=True)
        self.assertEqual(attachment, parsed_attachment)
        self.assertEqual(
            hashlib.sha256(attachment).hexdigest(),
            hashlib.sha256(parsed_attachment).hexdigest(),
        )

        with tempfile.TemporaryDirectory() as directory:
            eml_path = Path(directory) / "attachment.eml"
            eml_path.write_bytes(sanitized)
            report = EmlSOCAnalyzer().analyze(str(eml_path))
        self.assertEqual(
            hashlib.sha256(attachment).hexdigest(),
            report["attachments"][0]["hash_sha256"],
        )

    def test_unicode_whitespace_is_only_normalized_in_headers(self):
        body = b"First line\n\xc2\xa0body NBSP\n\xe2\x80\x83body EM SPACE\n"
        raw = (
            b"From: sender@example.com\n"
            b"X-Trace: first\xc2\xa0value\n"
            b"\xe2\x80\x83continued\n"
            b"\n"
            + body
        )

        sanitized = _sanitize_eml_bytes(raw)
        headers, sanitized_body = sanitized.split(b"\n\n", 1)
        self.assertIn(b"X-Trace: first value", headers)
        self.assertIn(b" continued", headers)
        self.assertEqual(body, sanitized_body)

    def test_existing_crlf_separator_and_body_are_preserved(self):
        raw = b"From: sender@example.com\r\nSubject: Test\r\n\r\nline1\nline2\xc2\xa0\r\n"
        self.assertEqual(raw, _sanitize_eml_bytes(raw))

    def test_header_only_message_gets_one_blank_line(self):
        self.assertEqual(
            b"From: sender@example.com\r\nSubject: Test\r\n\r\n",
            _sanitize_eml_bytes(b"From: sender@example.com\r\nSubject: Test\r\n"),
        )

    def test_repairs_are_reported_with_proportional_severity(self):
        raw = (
            b"Created at export time\r\n"
            b"From: sender@example.com\r\n"
            b"X-Trace: first\r\n"
            b"\xe2\x80\x83continued\r\n"
        )

        sanitized, findings = _sanitize_eml_bytes_with_findings(raw)

        self.assertIn(b"From: sender@example.com", sanitized)
        levels = {finding["code"]: finding["level"] for finding in findings}
        self.assertEqual("MEDIUM", levels["DiscardedLeadingNonHeaderLines"])
        self.assertEqual("LOW", levels["UnicodeHeaderFoldingNormalized"])
        self.assertEqual("INFO", levels["MissingHeaderBodySeparatorRepaired"])

    def test_raw_preview_keeps_message_source_and_omits_attachment_payload(self):
        raw = (
            b"From: sender@example.com\r\n"
            b"To: recipient@example.net\r\n"
            b"Subject: Source preview\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=fishstop\r\n"
            b"\r\n"
            b"--fishstop\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"Visible message body.\r\n"
            b"--fishstop\r\n"
            b"Content-Type: application/pdf\r\n"
            b"Content-Disposition: attachment; filename=document.pdf\r\n"
            b"Content-Transfer-Encoding: base64\r\n\r\n"
            b"U0VDUkVUX0JJTkFSWV9QQVlMT0FE\r\n"
            b"--fishstop--\r\n"
        )

        preview = _redacted_eml_preview(raw)

        self.assertIn("Subject: Source preview", preview)
        self.assertIn("Visible message body.", preview)
        self.assertIn("filename=document.pdf", preview)
        self.assertIn("decoded-size=0.00 MB", preview)
        self.assertIn("X-FishStop-Attachment-Payload: omitted", preview)
        self.assertNotIn("U0VDUkVUX0JJTkFSWV9QQVlMT0FE", preview)
        self.assertNotIn("SECRET_BINARY_PAYLOAD", preview)


if __name__ == "__main__":
    unittest.main()
