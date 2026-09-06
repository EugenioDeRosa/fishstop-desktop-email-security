import tempfile
import unittest
from pathlib import Path

from fishstop_engine.analyzer.link_extractor import extract_links
from fishstop_engine.analyzer.soc_analyzer import EmlSOCAnalyzer


class LinkExtractionUrlTests(unittest.TestCase):
    @staticmethod
    def one_link(text: str) -> dict:
        links = extract_links(text, "")
        if len(links) != 1:
            raise AssertionError(f"Expected one link, found {len(links)}: {links}")
        return links[0]

    def test_ipv4_url_with_single_digit_final_octet_is_extracted(self):
        link = self.one_link("Open https://8.8.8.8/path")
        self.assertEqual("https://8.8.8.8/path", link["url"])
        self.assertEqual("8.8.8.8", link["host"])
        self.assertTrue(link["is_ip"])

    def test_bracketed_ipv6_url_is_extracted(self):
        link = self.one_link("Open https://[2001:4860:4860::8888]/dns")
        self.assertEqual(
            "https://[2001:4860:4860::8888]/dns",
            link["url"],
        )
        self.assertEqual("2001:4860:4860::8888", link["host"])
        self.assertTrue(link["is_ip"])

    def test_query_without_slash_is_preserved_and_analyzed(self):
        url = (
            "https://safe.example?"
            "next=https%3A%2F%2Fevil.example%2Fdropper.exe"
        )
        link = self.one_link(f"Download: {url}")
        self.assertEqual(url, link["url"])
        self.assertEqual(1, link["nested_redirect_count"])
        self.assertEqual(["evil.example"], link["redirect_hosts"])
        self.assertEqual("dropper.exe", link["download_filename"])
        self.assertEqual("exe", link["download_extension"])
        self.assertEqual("redirect", link["download_source"])
        self.assertTrue(link["dangerous_download"])

    def test_prose_punctuation_is_not_part_of_url(self):
        link = self.one_link("Visit https://example.com/path?item=1, then continue.")
        self.assertEqual("https://example.com/path?item=1", link["url"])

    def test_balanced_parenthesis_in_path_is_preserved(self):
        link = self.one_link("Documentation: https://example.com/a_(b)")
        self.assertEqual("https://example.com/a_(b)", link["url"])

    def test_www_url_can_have_query_without_path(self):
        link = self.one_link("Visit www.example.com?item=1")
        self.assertEqual("http://www.example.com?item=1", link["url"])
        self.assertEqual("item=1", link["url"].split("?", 1)[1])

    def test_fragment_without_path_is_preserved(self):
        link = self.one_link("Visit https://example.com#security")
        self.assertEqual("https://example.com#security", link["url"])

    def test_incomplete_url_is_ignored(self):
        self.assertEqual([], extract_links("Broken link https://", ""))

    def test_dangerous_nested_download_emits_high_soc_flag(self):
        url = (
            "https://safe.example?"
            "next=https%3A%2F%2Fevil.example%2Fdropper.exe"
        )
        raw = (
            "From: sender@example.com\r\n"
            "To: recipient@example.net\r\n"
            "Subject: Download\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "\r\n"
            f"Download from {url}\r\n"
        ).encode("utf-8")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "redirect.eml"
            path.write_bytes(raw)
            report = EmlSOCAnalyzer().analyze(str(path))

        self.assertTrue(any(
            flag["level"] == "HIGH"
            and flag["field"] == "Link"
            and "dropper.exe" in flag["message"]
            for flag in report["flags"]
        ))


if __name__ == "__main__":
    unittest.main()
