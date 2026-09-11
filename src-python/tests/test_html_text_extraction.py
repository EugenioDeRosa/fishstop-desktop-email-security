import unittest

from fishstop_engine.analyzer.html_utils import strip_html


class HtmlTextExtractionTests(unittest.TestCase):
    def test_zero_font_layout_container_preserves_visible_descendants(self):
        html = """
        <table><tr><td style="font-size: 0; padding: 24px">
          <div style="font-size:0; text-align:left">
            <p style="font-size:16px; line-height:24px">Account backup required</p>
            <a style="font-size:14px">Back up data</a>
          </div>
        </td></tr></table>
        """

        extracted = strip_html(html)

        self.assertIn("Account backup required", extracted)
        self.assertIn("Back up data", extracted)

    def test_text_inheriting_zero_font_size_remains_hidden(self):
        html = """
        <div style="font-size:0">
          concealed direct text
          <span>concealed inherited text</span>
          <span style="font-size: 0.5px">tiny but nonzero text</span>
          <span style="font-size:14px">visible restored text</span>
        </div>
        <p>ordinary visible text</p>
        """

        extracted = strip_html(html)

        self.assertNotIn("concealed direct text", extracted)
        self.assertNotIn("concealed inherited text", extracted)
        self.assertIn("tiny but nonzero text", extracted)
        self.assertIn("visible restored text", extracted)
        self.assertIn("ordinary visible text", extracted)

    def test_hidden_subtrees_are_still_excluded(self):
        html = """
        <div style="display:none"><span style="font-size:16px">display secret</span></div>
        <div style="visibility:hidden"><span style="font-size:16px">visibility secret</span></div>
        <div style="opacity:0%"><span style="font-size:16px">opacity secret</span></div>
        <div hidden><span style="font-size:16px">attribute secret</span></div>
        <p>visible message</p>
        """

        extracted = strip_html(html)

        self.assertNotIn("display secret", extracted)
        self.assertNotIn("visibility secret", extracted)
        self.assertNotIn("opacity secret", extracted)
        self.assertNotIn("attribute secret", extracted)
        self.assertEqual("visible message", extracted)

if __name__ == "__main__":
    unittest.main()
