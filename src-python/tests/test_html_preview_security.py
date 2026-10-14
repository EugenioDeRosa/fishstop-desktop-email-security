import html
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fishstop_engine.analyzer import html_utils
from fishstop_engine.analyzer.html_utils import (
    sanitize_html_for_js_preview,
    sanitize_html_for_preview,
)
from fishstop_engine.analyzer.soc_analyzer import EmlSOCAnalyzer


TRACKER_HTML = """
<!doctype html>
<html style="background:url(https://tracker.example/body)">
  <head>
    <meta http-equiv="refresh" content="0;url=https://tracker.example/refresh">
    <link rel="stylesheet" href="https://tracker.example/site.css">
    <style>
      @import url("https://tracker.example/import.css");
      .hero { background-image: url(https://tracker.example/css-pixel); }
    </style>
  </head>
  <body background="https://tracker.example/background">
    <div class="hero" style="background:url(https://tracker.example/inline)">Visible message</div>
    <img src="https://tracker.example/pixel.gif" srcset="https://tracker.example/2x.gif 2x" alt="Company logo">
    <a href="https://tracker.example/click" ping="https://tracker.example/ping" onclick="fetch('https://tracker.example/event')">Open account</a>
    <video poster="https://tracker.example/poster.jpg"><source src="https://tracker.example/movie.mp4"></video>
    <iframe src="https://tracker.example/frame"></iframe>
    <form action="https://tracker.example/submit"><input name="password"></form>
    <svg><image xlink:href="https://tracker.example/vector.png"></image></svg>
  </body>
</html>
"""


class HtmlPreviewSecurityTests(unittest.TestCase):
    def test_sanitizer_removes_active_css_and_every_remote_resource(self):
        preview = sanitize_html_for_preview(TRACKER_HTML)
        normalized = preview.lower()

        self.assertNotIn("tracker.example", normalized)
        self.assertNotRegex(normalized, r"<\s*(?:script|style|iframe|object|embed|form|input|meta|link|svg)\b")
        self.assertNotRegex(normalized, r"\s(?:href|src|srcset|xlink:href|action|poster|background|ping)\s*=")
        self.assertIn("visible message", normalized)
        self.assertIn("remote image blocked: company logo", normalized)

    def test_fallback_escapes_markup_after_removing_remote_sources(self):
        with patch.object(html_utils, "_BS4_AVAILABLE", False):
            preview = sanitize_html_for_preview(TRACKER_HTML)

        self.assertNotIn("tracker.example", preview.lower())
        self.assertIn("&lt;", preview)
        self.assertNotIn(" style=", preview.lower())

    def test_complete_preview_document_has_deny_all_csp_and_no_script(self):
        document = html.unescape(sanitize_html_for_js_preview(TRACKER_HTML))

        self.assertIn("Content-Security-Policy", document)
        self.assertIn("default-src 'none'", document)
        self.assertIn("img-src 'none'", document)
        self.assertIn("style-src 'unsafe-inline'", document)
        self.assertIn("script-src 'none'", document)
        self.assertIn('name="referrer" content="no-referrer"', document)
        self.assertNotRegex(document.lower(), r"<\s*(?:script|style)\b")
        self.assertNotIn("tracker.example", document.lower())

    def test_soc_report_only_exposes_sanitized_preview_markup(self):
        raw = (
            "From: Sender <sender@example.com>\r\n"
            "To: recipient@example.net\r\n"
            "Subject: Preview\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "\r\n"
            f"{TRACKER_HTML}\r\n"
        ).encode("utf-8")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "preview.eml"
            path.write_bytes(raw)
            report = EmlSOCAnalyzer().analyze(str(path))

        preview = report["body_html_safe"]
        self.assertNotIn("tracker.example", preview.lower())
        self.assertNotIn("url(", preview.lower())

    def test_preserves_email_canvas_table_typography_and_safe_local_rules(self):
        preview = sanitize_html_for_preview('''<html><head><style>
            @import "https://tracker.example/styles";
            .card { background-color:#123456; color:white; padding:24px; margin:0 auto; }
            td { font-size:16px; text-align:center; }
            #heading { font-weight:bold; }
            .card { background-image:url(https://tracker.example/pixel); }
        </style></head><body bgcolor="#eee"><table width="100%" cellpadding="12"><tr>
        <td class="card" id="heading" style="font-size:18px">Invoice details</td>
        </tr></table></body></html>''')
        for expected in ['background-color:#eee', 'background-color:#123456', 'color:white',
                         'padding:24px', 'margin:0 auto', 'font-size:18px', 'font-weight:bold', 'text-align:center',
                         'width="100%"', 'cellpadding="12"', 'Invoice details']:
            self.assertIn(expected, preview)
        self.assertNotIn('font-size:16px', preview)
        self.assertNotIn('tracker.example', preview)
        self.assertNotIn('<style', preview)

    def test_blocks_css_exfiltration_obfuscation_and_unbounded_layout(self):
        preview = sanitize_html_for_preview(r'''<div style="color:red;
          background:u\72l(https://tracker.example/pixel);
          width:expression(alert(1)); font-family:url(https://tracker.example/font);
          --secret:url(https://tracker.example/variable); position:fixed; z-index:999;
          behavior:url(https://tracker.example/code); height:999999px;
          animation:spin 1s infinite; color:var(--secret); padding:12px">Visible</div>
          <link href="https://tracker.example/css"><img src="data:image/svg+xml,evil">
          <iframe srcdoc="evil"></iframe><script>alert(1)</script>''')
        self.assertIn('color:red', preview)
        self.assertIn('padding:12px', preview)
        for forbidden in ['tracker.example', 'url(', 'expression', 'position:', 'z-index:',
                          'behavior', '999999', 'animation:', 'var(', 'data:image', 'srcdoc=']:
            self.assertNotIn(forbidden, preview)

    def test_stylesheet_important_specificity_and_inline_cascade(self):
        preview = sanitize_html_for_preview('''<style>.card { color:red !important }
          #content { background-color:blue } div { background-color:green }</style>
          <div id="content" class="card" style="color:white;background-color:black">Text</div>''')
        self.assertIn('color:red', preview)
        self.assertIn('background-color:black', preview)
        self.assertNotIn('color:white', preview)

    def test_missing_css_parser_drops_styling_without_losing_text(self):
        with patch('fishstop_engine.analyzer.preview_css.tinycss2', None):
            preview = sanitize_html_for_preview('<div style="color:red;background:url(evil)">Visible</div>')
        self.assertIn('Visible', preview)
        self.assertNotIn('style=', preview)
        self.assertNotIn('evil', preview)

    def test_tauri_main_webview_has_a_restrictive_csp(self):
        project_root = Path(__file__).resolve().parents[2]
        config = json.loads(
            (project_root / "src-tauri" / "tauri.conf.json").read_text(encoding="utf-8")
        )
        csp = config["app"]["security"]["csp"]

        self.assertIsInstance(csp, str)
        self.assertIn("default-src 'self'", csp)
        self.assertIn("object-src 'none'", csp)
        self.assertIn("base-uri 'none'", csp)
        self.assertNotIn("img-src 'self' data: blob: https:", csp)


if __name__ == "__main__":
    unittest.main()
