import tempfile
import unittest
from pathlib import Path

from fishstop_engine.analyzer.link_extractor import extract_links
from fishstop_engine.analyzer.lookalike import check_lookalike_domains
from fishstop_engine.analyzer.soc_analyzer import EmlSOCAnalyzer
from fishstop_engine.domain_utils import (
    is_public_suffix,
    registered_domain,
    registrable_label,
    same_registered_domain,
)


class DomainPolicyTests(unittest.TestCase):
    def test_public_suffix_list_handles_multilevel_suffixes(self):
        self.assertEqual("paypal.co.uk", registered_domain("login.paypal.co.uk"))
        self.assertEqual("paypal", registrable_label("login.paypal.co.uk"))
        self.assertTrue(
            same_registered_domain("login.paypal.co.uk", "www.paypal.co.uk")
        )
        self.assertFalse(same_registered_domain("evil.co.uk", "paypal.co.uk"))

    def test_private_suffixes_are_kept_separate(self):
        self.assertEqual("alice.blogspot.com", registered_domain("alice.blogspot.com"))
        self.assertFalse(
            same_registered_domain("alice.blogspot.com", "paypal.blogspot.com")
        )
        self.assertTrue(is_public_suffix("blogspot.com"))
        self.assertFalse(is_public_suffix("alice.blogspot.com"))

    def test_unknown_suffix_fails_closed(self):
        self.assertEqual(
            "mail.brand.example",
            registered_domain("mail.brand.example"),
        )
        self.assertFalse(
            same_registered_domain("evil.example", "paypal.example")
        )

    def test_unicode_and_punycode_hosts_compare_equally(self):
        self.assertEqual(
            "xn--bcher-kva.de",
            registered_domain("bücher.de"),
        )
        self.assertTrue(
            same_registered_domain("bücher.de", "xn--bcher-kva.de")
        )

    def test_masked_co_uk_link_is_detected(self):
        links = extract_links(
            "",
            '<a href="https://evil.co.uk/login">https://paypal.co.uk</a>',
        )
        clickable = next(link for link in links if link["host"] == "evil.co.uk")
        self.assertEqual("evil.co.uk", clickable["registered_domain"])
        self.assertEqual("paypal.co.uk", clickable["display_registered_domain"])
        self.assertTrue(clickable["display_mismatch"])

    def test_subdomains_of_same_registered_domain_are_not_a_mismatch(self):
        links = extract_links(
            "",
            '<a href="https://login.paypal.co.uk/">https://www.paypal.co.uk</a>',
        )
        clickable = next(
            link for link in links if link["host"] == "login.paypal.co.uk"
        )
        self.assertFalse(clickable["display_mismatch"])

    def test_attachment_filename_is_not_treated_as_visible_link_text(self):
        links = extract_links(
            "",
            "",
            embedded_urls=[{
                "url": "https://sites.google.com/view/10931222245678/home/",
                "label": "pdf.pdf",
                "source": "attachment",
            }],
        )

        extracted = links[0]
        self.assertEqual("attachment", extracted["source"])
        self.assertEqual("", extracted["display_text"])
        self.assertEqual("", extracted["display_host"])
        self.assertFalse(extracted["display_mismatch"])

    def test_co_uk_lookalike_uses_registrable_label(self):
        alerts = check_lookalike_domains(
            [{"url": "https://paypa1.co.uk", "host": "paypa1.co.uk"}],
            known_brands=["paypal.com"],
        )
        self.assertTrue(any(
            alert["matched_brand"] == "paypal.com"
            and alert["technique"] == "edit_distance"
            for alert in alerts
        ))

    def test_sender_and_return_path_use_psl_policy(self):
        report = self._analyze(
            from_domain="paypal.co.uk",
            return_path_domain="evil.co.uk",
        )
        self.assertEqual("paypal.co.uk", report["from_registered_domain"])
        self.assertTrue(report["return_path_domain_mismatch"])

        same_domain_report = self._analyze(
            from_domain="mail.paypal.co.uk",
            return_path_domain="bounce.paypal.co.uk",
        )
        self.assertFalse(same_domain_report["return_path_domain_mismatch"])

    @staticmethod
    def _analyze(from_domain: str, return_path_domain: str) -> dict:
        raw = (
            f"From: Brand <notice@{from_domain}>\r\n"
            "To: recipient@example.net\r\n"
            f"Return-Path: <bounce@{return_path_domain}>\r\n"
            "Subject: Account notice\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "\r\n"
            "Informational message.\r\n"
        ).encode("utf-8")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "message.eml"
            path.write_bytes(raw)
            return EmlSOCAnalyzer().analyze(str(path))


if __name__ == "__main__":
    unittest.main()
