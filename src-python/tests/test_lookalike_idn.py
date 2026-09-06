import tempfile
import unittest
from pathlib import Path

from fishstop_engine.analyzer.llm_context_analyzer import (
    _technical_context_lines,
    _technical_risk,
)
from fishstop_engine.analyzer.lookalike import check_lookalike_domains
from fishstop_engine.analyzer.soc_analyzer import EmlSOCAnalyzer


def _alerts_for(host: str) -> list[dict]:
    return check_lookalike_domains([
        {"url": f"https://{host}/", "host": host},
    ])


class InternationalizedDomainTests(unittest.TestCase):
    def test_valid_idn_is_informational(self):
        alerts = _alerts_for("xn--bcher-kva.de")

        self.assertEqual(1, len(alerts))
        self.assertEqual("INFO", alerts[0]["level"])
        self.assertEqual("punycode_idna", alerts[0]["technique"])
        self.assertIn("bücher.de", alerts[0]["detail"])

    def test_accented_latin_idn_is_not_brand_impersonation(self):
        alerts = _alerts_for("xn--caf-dma.fr")

        self.assertTrue(alerts)
        self.assertTrue(all(alert["level"] == "INFO" for alert in alerts))
        self.assertFalse(any(
            alert["technique"] == "punycode_homograph"
            for alert in alerts
        ))

    def test_punycode_brand_homograph_is_high_risk(self):
        alerts = _alerts_for("xn--pple-43d.com")  # Cyrillic 'a' + pple.com

        self.assertTrue(any(
            alert["level"] == "HIGH"
            and alert["technique"] == "punycode_homograph"
            and alert["matched_brand"] == "apple.com"
            for alert in alerts
        ))
        self.assertFalse(any(alert["level"] == "INFO" for alert in alerts))

    def test_mixed_script_idn_without_brand_is_reviewable(self):
        decoded = "аabc.example"
        host = decoded.encode("idna").decode("ascii")
        alerts = _alerts_for(host)

        self.assertTrue(any(
            alert["level"] == "MEDIUM"
            and alert["technique"] == "mixed_script_idn"
            for alert in alerts
        ))

    def test_soc_preserves_info_level_instead_of_promoting_to_high(self):
        report = self._analyze_url("https://xn--bcher-kva.de/catalog")
        idn_flags = [
            flag for flag in report["flags"]
            if flag["field"] == "Lookalike Domain"
        ]

        self.assertTrue(idn_flags)
        self.assertTrue(all(flag["level"] == "INFO" for flag in idn_flags))

    def test_informational_idn_does_not_influence_llm_risk(self):
        alert = _alerts_for("xn--bcher-kva.de")[0]
        soc = {"lookalike_alerts": [alert]}

        self.assertFalse(any(
            "Lookalike/domain check did not pass" in line
            for line in _technical_context_lines(soc)
        ))
        status, reasons = _technical_risk(soc)
        self.assertEqual("clean", status)
        self.assertNotIn("a lookalike or deceptive domain was detected", reasons)

    def test_high_risk_homograph_influences_llm_risk(self):
        alert = next(
            item for item in _alerts_for("xn--pple-43d.com")
            if item["technique"] == "punycode_homograph"
        )
        status, reasons = _technical_risk({"lookalike_alerts": [alert]})

        self.assertEqual("uncertain", status)
        self.assertIn("a lookalike or deceptive domain was detected", reasons)

    @staticmethod
    def _analyze_url(url: str) -> dict:
        raw = (
            "From: Newsletter <news@example.org>\r\n"
            "To: recipient@example.net\r\n"
            "Subject: Catalogue\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "\r\n"
            f"Read the catalogue at {url}\r\n"
        ).encode("utf-8")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "message.eml"
            path.write_bytes(raw)
            return EmlSOCAnalyzer().analyze(str(path))


if __name__ == "__main__":
    unittest.main()
