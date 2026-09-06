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
            b'<Relationship TargetMode="External" '
            b'Target="https://example.test"/> DDEAUTO'
        )
        budget = ArchiveAnalysisBudget()

        result = analyze_archive_security(
            make_zip([("_rels/document.rels", relation)]),
            "document.docx",
            budget=budget,
        )

        self.assertEqual(len(relation), budget.decompressed_bytes)
        self.assertIn("external_relationship", self.finding_keys(result))
        self.assertIn("dde_instruction", self.finding_keys(result))

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
