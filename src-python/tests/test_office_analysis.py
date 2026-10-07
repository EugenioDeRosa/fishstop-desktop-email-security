"""Office parsing, bounded worker and verdict regression tests."""
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fishstop_engine import office_analysis as office
from fishstop_engine.analyzer.attachment import analyze_attachment
from fishstop_engine.analyzer.archive_analysis import analyze_archive_security
from fishstop_engine.analyzer.llm_context_analyzer import _technical_context_lines, _technical_risk
from fishstop_engine.analyzer.soc_analyzer import EmlSOCAnalyzer


def package(document=None, extra=None):
    document = document or '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Ordinary report</w:t></w:r></w:p></w:body></w:document>'
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("[Content_Types].xml", '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
        archive.writestr("word/document.xml", document)
        for name, data in extra or []:
            archive.writestr(name, data)
    return buffer.getvalue()


class OfficeAnalysisTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("FISHSTOP_TEST_ENGINE"), "Optional packaged Windows engine smoke test")
    def test_packaged_engine_spawns_office_worker(self):
        message = EmailMessage()
        message["From"] = "sender@example.test"
        message["To"] = "recipient@example.test"
        message["Subject"] = "Packaging test"
        message.set_content("Ordinary report")
        message.add_attachment(package(), maintype="application", subtype="octet-stream", filename="report.docx")
        message.add_attachment(b'{\\rtf1{\\field{\\*\\fldinst DDEAUTO cmd | calc}{\\fldrslt text}}}', maintype="application", subtype="rtf", filename="dde-test.rtf")
        env = {**os.environ, "VIRUSTOTAL_API_KEY": "", "ABUSEIPDB_API_KEY": "", "OTX_API_KEY": ""}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mail.eml"
            path.write_bytes(message.as_bytes())
            completed = subprocess.run([os.environ["FISHSTOP_TEST_ENGINE"], "static", str(path)], capture_output=True, timeout=45, env=env, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        self.assertEqual(0, completed.returncode, completed.stderr.decode(errors="replace"))
        response = json.loads(completed.stdout)
        self.assertTrue(response["ok"], response)
        result = response["report"]["attachments"][0]["office_security"]
        self.assertEqual("ok", result["status"], result)
        self.assertTrue(result["analysis_complete"])
        self.assertEqual("clean", result["risk_level"])

        dde_result = response["report"]["attachments"][1]["office_security"]
        self.assertEqual("ok", dde_result["status"], dde_result)
        self.assertEqual("high", dde_result["risk_level"], dde_result)
        self.assertTrue(any(flag["field"] == "Office content" and flag["level"] == "HIGH" for flag in response["report"]["flags"]))

    def test_real_worker_clean_docx(self):
        result = office.analyze_office_security(package(), "report.docx")
        self.assertEqual("ok", result["status"], result)
        self.assertTrue(result["analysis_complete"])
        self.assertEqual("clean", result["risk_level"])
        self.assertFalse(result["vba_macros"])

    def test_real_dde_command(self):
        document = '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText>DDEAUTO cmd | calc</w:instrText></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p></w:body></w:document>'
        result = office.analyze_office_security(package(document), "invoice.docx")
        self.assertEqual("ok", result["status"], result)
        self.assertEqual("high", result["risk_level"], result)
        self.assertIn("dde", [finding["key"] for finding in result["findings"]])

    def test_prose_dde_and_hyperlink_are_not_active_threats(self):
        document = '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>DDEAUTO cmd is described in this thesis.</w:t></w:r></w:p><w:p><w:r><w:instrText>HYPERLINK "https://example.test"</w:instrText></w:r></w:p></w:body></w:document>'
        result = office.analyze_office_security(package(document), "thesis.docx")
        self.assertEqual("clean", result["risk_level"], result)

    def test_xlm_ooxml_fallback(self):
        result = office.analyze_office_security(package(extra=[("xl/macrosheets/sheet1.xml", "<worksheet/>")]), "sheet.xlsm")
        self.assertTrue(result["xlm_macros"], result)
        self.assertEqual("medium", result["risk_level"])

    def test_real_vba_scanner_autoexec_shell(self):
        from oletools.olevba import VBA_Scanner
        rows = VBA_Scanner('Sub AutoOpen()\nShell "cmd /c echo demo"\nEnd Sub').scan()
        result = office._result()
        result["vba_macros"] = True
        office._apply_macro_indicators(result, rows)
        result = office._finish(result)
        self.assertEqual("high", result["risk_level"])
        self.assertIn("AutoOpen", result["autoexec"])
        self.assertIn("Shell", result["suspicious_keywords"])

    def test_macro_presence_alone_not_malware(self):
        result = office._result()
        result["vba_macros"] = True
        office._apply_macro_indicators(result, [])
        result = office._finish(result)
        self.assertEqual("low", result["risk_level"])
        self.assertEqual("clean", _technical_risk({"attachments": [{"office_security": result}]})[0])
        archive = analyze_archive_security(package(extra=[("word/vbaProject.bin", b"benign placeholder")]), "template.docm")
        self.assertEqual("low", archive["risk_level"])

    def test_non_office_untouched(self):
        with patch.object(office.subprocess, "Popen") as worker:
            self.assertIsNone(office.analyze_office_security(b"%PDF-1.7\n", "report.pdf"))
            self.assertIsNone(office.analyze_office_security(b"notes", "notes.txt"))
            worker.assert_not_called()

    def test_extension_spoof_not_clean(self):
        result = office.analyze_office_security(b'Sub AutoOpen()\nShell "cmd"\nEnd Sub', "fake.doc")
        self.assertEqual("unsupported", result["status"], result)
        self.assertFalse(result["analysis_complete"])
        self.assertEqual("unknown", result["risk_level"])

    def test_non_office_zip_disguised_as_docx_not_clean(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("notes.txt", "ordinary text")
        result = office.analyze_office_security(buffer.getvalue(), "fake.docx")
        self.assertEqual("unsupported", result["status"], result)
        self.assertEqual("unknown", result["risk_level"])

    def test_real_rtf_clean_and_dde(self):
        clean = office.analyze_office_security(b"{\\rtf1 ordinary text}", "notes.rtf")
        self.assertEqual("ok", clean["status"], clean)
        self.assertEqual("clean", clean["risk_level"])
        dde = office.analyze_office_security(b'{\\rtf1{\\field{\\*\\fldinst DDEAUTO cmd | calc}{\\fldrslt text}}}', "invoice.rtf")
        self.assertEqual("high", dde["risk_level"], dde)

    def test_url_evidence_not_truncated_for_reputation(self):
        url = "https://example.test/" + "a" * 500
        result = office._result()
        office._apply_macro_indicators(result, [("IOC", url, "")])
        self.assertEqual([url], result["urls"])

    def test_partial_without_findings_is_unknown_not_clean(self):
        result = office._result()
        result.update(status="partial", analysis_complete=False)
        self.assertEqual("unknown", office._finish(result)["risk_level"])

    def test_parser_error_does_not_skip_dde(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.docx"
            path.write_bytes(package())
            with patch("oletools.olevba.VBA_Parser", side_effect=ValueError("bad macro")), patch("oletools.msodde.process_file", return_value="DDEAUTO cmd | calc"):
                result = office._inspect_file(path)
        self.assertEqual("partial", result["status"])
        self.assertEqual("high", result["risk_level"])
        self.assertFalse(result["analysis_complete"])

    def test_oversize_and_zip_bomb_skip_without_worker(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("word/document.xml", b"A" * (512 * 1024))
        with patch.object(office.subprocess, "Popen") as worker:
            self.assertEqual("skipped", office.analyze_office_security(b"A" * (office.MAX_OFFICE_BYTES + 1), "big.doc")["status"])
            self.assertEqual("skipped", office.analyze_office_security(buffer.getvalue(), "bomb.docx")["status"])
            worker.assert_not_called()

    def test_shared_budget(self):
        budget = office.OfficeAnalysisBudget(max_files=1)
        first = office.analyze_office_security(package(), "one.docx", budget=budget)
        second = office.analyze_office_security(package(), "two.docx", budget=budget)
        self.assertEqual("ok", first["status"])
        self.assertEqual("skipped", second["status"])
        self.assertEqual(1, budget.files_seen)
        self.assertGreater(budget.elapsed_seconds, 0)
        with patch.object(office.subprocess, "Popen") as worker:
            exhausted = office.OfficeAnalysisBudget(max_seconds=0)
            self.assertEqual("skipped", office.analyze_office_security(package(), "third.docx", budget=exhausted)["status"])
            worker.assert_not_called()

    def test_timeout_stops_worker_and_is_not_clean(self):
        process = Mock()
        process.wait.side_effect = subprocess.TimeoutExpired("worker", 8)
        with patch.object(office.subprocess, "Popen", return_value=process), patch.object(office, "_stop_worker") as stop:
            result = office.analyze_office_security(package(), "slow.docx")
            stop.assert_called_once_with(process)
        self.assertEqual("timeout", result["status"])
        self.assertFalse(result["analysis_complete"])
        self.assertEqual("unknown", result["risk_level"])

    def test_encrypted_and_missing_dependency_are_explicit(self):
        with patch("oletools.crypto.is_encrypted", return_value=True):
            result = office._inspect_file(Path("unused.doc"))
        self.assertEqual("encrypted", result["status"])
        with patch.dict(sys.modules, {"oletools": None}):
            result = office._inspect_file(Path("unused.doc"))
        self.assertEqual("unavailable", result["status"])
        self.assertFalse(result["analysis_complete"])

    def test_partial_analysis_preserves_macro_evidence(self):
        parser = Mock(contains_vba_macros=True, contains_xlm_macros=False)
        parser.analyze_macros.return_value = [("AutoExec", "AutoOpen", ""), ("Suspicious", "Shell", "")]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "document.docx"
            path.write_bytes(package())
            with patch("oletools.olevba.VBA_Parser", return_value=parser), patch("oletools.msodde.process_file", side_effect=ValueError("bad field")):
                result = office._inspect_file(path)
        self.assertEqual("partial", result["status"])
        self.assertEqual("high", result["risk_level"])
        self.assertFalse(result["analysis_complete"])
        parser.close.assert_called_once()

    def test_attachment_report_and_ai_policy(self):
        result = analyze_attachment("report.docm", "application/vnd.ms-word.document.macroenabled.12", "base64", package())
        self.assertTrue(result["extension_match"], result)
        self.assertEqual("ok", result["office_security"]["status"])
        office_result = office._result("timeout", "Timeout")
        soc = {"attachments": [{"office_security": office_result}]}
        self.assertEqual("uncertain", _technical_risk(soc)[0])
        context = "\n".join(_technical_context_lines(soc))
        self.assertIn("complete=False", context)
        office_result.update(analysis_complete=True, risk_level="high")
        self.assertEqual("uncertain", _technical_risk(soc)[0])

    def test_soc_shares_budget_and_exposes_flags(self):
        message = EmailMessage()
        message["From"] = "sender@example.test"
        message["To"] = "recipient@example.test"
        message["Subject"] = "Office report"
        message.set_content("Please review the document.")
        for name in ("first.docx", "second.docx"):
            message.add_attachment(package(), maintype="application", subtype="octet-stream", filename=name)
        budgets = []
        def inspect(data, filename, content_type, budget):
            # Archive inspection also visits the XML inside each DOCX. Preserve
            # real format detection there; only simulate the two Office scans.
            if filename not in {"first.docx", "second.docx"}:
                return office.analyze_office_security(data, filename, content_type, budget)
            budgets.append(budget)
            return office._result("timeout", "Office inspection timed out")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mail.eml"
            path.write_bytes(message.as_bytes())
            with patch("fishstop_engine.analyzer.attachment.analyze_office_security", side_effect=inspect):
                result = EmlSOCAnalyzer().analyze(str(path))
        self.assertEqual(2, len(budgets))
        self.assertIs(budgets[0], budgets[1])
        self.assertTrue(any(flag["field"] == "Office inspection incomplete" for flag in result["flags"]))
        json.dumps(result, default=str)


if __name__ == "__main__":
    unittest.main()
