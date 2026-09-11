import io
import tempfile
import unittest
import zipfile
from email.message import EmailMessage
from pathlib import Path

from fishstop_engine.analyzer.archive_analysis import (
    ArchiveAnalysisBudget,
    analyze_archive_security,
)
from fishstop_engine.analyzer.soc_analyzer import EmlSOCAnalyzer


def make_zip(entries: list[tuple[str, bytes]]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, contents in entries:
            archive.writestr(name, contents)
    return buffer.getvalue()


class ArchiveLimitTests(unittest.TestCase):
    @staticmethod
    def finding_keys(result: dict) -> set[str]:
        return {str(item.get("key")) for item in result.get("findings") or []}

    def test_entry_limit_stops_before_inspecting_members(self):
        payload = make_zip([(f"entry-{index}.txt", b"") for index in range(251)])

        result = analyze_archive_security(payload, "many.zip")

        self.assertTrue(result["budget_exhausted"])
        self.assertFalse(result["analysis_complete"])
        self.assertEqual(0, result["inspected_entry_count"])
        self.assertIn("entry_limit", self.finding_keys(result))
        self.assertIn("global_budget_exhausted", self.finding_keys(result))

    def test_budget_is_shared_across_separate_attachments(self):
        budget = ArchiveAnalysisBudget(max_entries=2)
        first = analyze_archive_security(
            make_zip([("one.bin", b"1")]),
            "first.zip",
            budget=budget,
        )
        second = analyze_archive_security(
            make_zip([("two.bin", b"2"), ("three.bin", b"3")]),
            "second.zip",
            budget=budget,
        )

        self.assertTrue(first["analysis_complete"])
        self.assertTrue(second["budget_exhausted"])
        self.assertEqual(0, second["inspected_entry_count"])
        self.assertEqual(1, budget.entries_seen)

    def test_soc_uses_one_archive_budget_for_the_whole_email(self):
        first_archive = make_zip(
            [(f"first-{index}.bin", b"1") for index in range(200)]
        )
        second_archive = make_zip(
            [(f"second-{index}.bin", b"2") for index in range(51)]
        )
        message = EmailMessage()
        message["From"] = "sender@example.test"
        message["To"] = "recipient@example.test"
        message["Subject"] = "Shared archive budget"
        message.set_content("Inspect the attachments.")
        message.add_attachment(
            first_archive,
            maintype="application",
            subtype="zip",
            filename="first.zip",
        )
        message.add_attachment(
            second_archive,
            maintype="application",
            subtype="zip",
            filename="second.zip",
        )

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "archives.eml"
            path.write_bytes(message.as_bytes())
            report = EmlSOCAnalyzer().analyze(str(path))

        first, second = [
            item["archive_security"] for item in report["attachments"]
        ]
        self.assertTrue(first["analysis_complete"])
        self.assertTrue(second["budget_exhausted"])
        self.assertEqual(0, second["inspected_entry_count"])

    def test_decompression_limit_cancels_the_current_archive(self):
        budget = ArchiveAnalysisBudget(max_decompressed_bytes=16)

        result = analyze_archive_security(
            make_zip([("document.txt", b"A" * 128), ("later.txt", b"DDEAUTO")]),
            "read-limit.zip",
            budget=budget,
        )

        self.assertTrue(result["budget_exhausted"])
        self.assertEqual(1, result["inspected_entry_count"])
        self.assertIn("decompression_limit", self.finding_keys(result))
        self.assertNotIn("dde_instruction", self.finding_keys(result))

    def test_zip_bomb_ratio_stops_before_later_members(self):
        result = analyze_archive_security(
            make_zip(
                [
                    ("compressed.bin", b"\x00" * (128 * 1024)),
                    ("later.txt", b"DDEAUTO"),
                ]
            ),
            "ratio.zip",
        )

        self.assertTrue(result["budget_exhausted"])
        self.assertEqual(1, result["inspected_entry_count"])
        self.assertIn("high_compression_ratio", self.finding_keys(result))
        self.assertNotIn("dde_instruction", self.finding_keys(result))

    def test_time_limit_stops_before_opening_archive(self):
        budget = ArchiveAnalysisBudget(max_seconds=0)

        result = analyze_archive_security(
            make_zip([("document.txt", b"content")]),
            "timeout.zip",
            budget=budget,
        )

        self.assertTrue(result["budget_exhausted"])
        self.assertEqual(0, result["entry_count"])
        self.assertIn("analysis_time_limit", self.finding_keys(result))

    def test_member_is_decompressed_only_once_for_all_checks(self):
        relation = (
            b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            b'<Relationship TargetMode="External" '
            b'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
            b'Target="https://example.test/template.dotm"/></Relationships>'
        )
        budget = ArchiveAnalysisBudget()

        result = analyze_archive_security(
            make_zip([("_rels/document.rels", relation)]),
            "document.docx",
            budget=budget,
        )

        self.assertEqual(len(relation), budget.decompressed_bytes)
        self.assertIn("external_relationship", self.finding_keys(result))

    def test_normal_office_hyperlink_is_not_an_archive_threat(self):
        relation = (
            b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            b'<Relationship TargetMode="External" '
            b'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" '
            b'Target="https://example.test/report"/></Relationships>'
        )

        result = analyze_archive_security(
            make_zip([("word/_rels/document.xml.rels", relation)]),
            "document.docx",
        )

        self.assertEqual("clean", result["risk_level"])
        self.assertNotIn("external_relationship", self.finding_keys(result))
        self.assertEqual(["https://example.test/report"], result["urls"])
        self.assertFalse(any("schemas.openxmlformats.org" in url for url in result["urls"]))

    def test_dde_word_in_document_prose_is_not_a_dde_instruction(self):
        document = (
            b'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            b'<w:body><w:p><w:r><w:t>This thesis explains DDE detection.</w:t>'
            b'</w:r></w:p></w:body></w:document>'
        )

        result = analyze_archive_security(
            make_zip([("word/document.xml", document)]),
            "thesis.docx",
        )

        self.assertEqual("clean", result["risk_level"])
        self.assertNotIn("dde_instruction", self.finding_keys(result))

    def test_real_ooxml_dde_field_is_high_risk(self):
        document = (
            b'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            b'<w:body><w:p><w:r><w:instrText>DDEAUTO cmd | calc</w:instrText>'
            b'</w:r></w:p></w:body></w:document>'
        )

        result = analyze_archive_security(
            make_zip([("word/document.xml", document)]),
            "document.docx",
        )

        self.assertEqual("high", result["risk_level"])
        self.assertIn("dde_instruction", self.finding_keys(result))

    def test_ooxml_hyperlink_field_is_reported_as_an_attachment_link(self):
        document = (
            b'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            b'<w:body><w:p><w:r><w:instrText>'
            b'HYPERLINK "https://example.test/from-field?source=docx"'
            b'</w:instrText></w:r></w:p></w:body></w:document>'
        )
        docx = make_zip([("word/document.xml", document)])
        message = EmailMessage()
        message["From"] = "sender@example.test"
        message["To"] = "recipient@example.test"
        message["Subject"] = "Document hyperlink"
        message.set_content("The link is inside the attached document.")
        message.add_attachment(
            docx,
            maintype="application",
            subtype="vnd.openxmlformats-officedocument.wordprocessingml.document",
            filename="report.docx",
        )

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "document-link.eml"
            path.write_bytes(message.as_bytes())
            report = EmlSOCAnalyzer().analyze(str(path))

        link = next(
            item for item in report["links"]
            if item.get("url") == "https://example.test/from-field?source=docx"
        )
        self.assertEqual("attachment", link["source"])
        self.assertFalse(link["display_mismatch"])

    def test_depth_limit_cancels_remaining_nested_work(self):
        nested = make_zip([("payload.py", b"print('unsafe')")])
        nested = make_zip([("level-three.zip", nested)])
        nested = make_zip([("level-two.zip", nested)])
        root = make_zip([("level-one.zip", nested), ("later.txt", b"DDEAUTO")])

        result = analyze_archive_security(root, "root.zip")

        self.assertTrue(result["budget_exhausted"])
        self.assertIn("nested_risky_content", self.finding_keys(result))
        self.assertEqual(1, result["inspected_entry_count"])


if __name__ == "__main__":
    unittest.main()
