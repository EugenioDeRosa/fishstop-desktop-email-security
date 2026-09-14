import unittest
from unittest.mock import patch

import dns.resolver

from fishstop_engine.analyzer.llm_context_analyzer import _abuse_reputation_label
from fishstop_engine.reputation import check_hop_ip, check_spamhaus


class SpamhausReputationTests(unittest.TestCase):
    @patch("fishstop_engine.reputation.dns.resolver.resolve")
    def test_nxdomain_means_not_listed(self, resolve):
        resolve.side_effect = dns.resolver.NXDOMAIN

        result = check_spamhaus("8.8.8.8")

        self.assertEqual("clean", result["status"])
        self.assertEqual("not_listed", result["classification"])
        resolve.assert_called_once_with("8.8.8.8.zen.spamhaus.org", "A", lifetime=4)

    @patch("fishstop_engine.reputation.dns.resolver.resolve")
    def test_sbl_and_xbl_codes_are_threat_listing(self, resolve):
        resolve.return_value = ["127.0.0.2", "127.0.0.4"]

        result = check_spamhaus("8.8.8.8")

        self.assertEqual("listed", result["status"])
        self.assertEqual("threat", result["classification"])
        self.assertEqual(["SBL", "XBL"], result["categories"])
        self.assertEqual(
            "suspicious",
            _abuse_reputation_label({"status": "skipped", "spamhaus": result}),
        )

    @patch("fishstop_engine.reputation.dns.resolver.resolve")
    def test_pbl_only_is_policy_not_threat(self, resolve):
        resolve.return_value = ["127.0.0.10"]

        result = check_spamhaus("8.8.8.8")

        self.assertEqual("listed", result["status"])
        self.assertEqual("policy", result["classification"])
        self.assertEqual("", _abuse_reputation_label({"status": "skipped", "spamhaus": result}))

    @patch("fishstop_engine.reputation.dns.resolver.resolve")
    def test_public_resolver_response_is_error_not_listing(self, resolve):
        resolve.return_value = ["127.255.255.254"]

        result = check_spamhaus("8.8.8.8")

        self.assertEqual("error", result["status"])
        self.assertIn("public/open DNS resolver", result["message"])

    @patch("fishstop_engine.reputation.check_spamhaus")
    @patch("fishstop_engine.reputation.check_ip")
    def test_spamhaus_runs_when_abuseipdb_key_is_missing(self, check_ip, check_spamhaus_mock):
        check_ip.return_value = {"ip": "8.8.8.8", "status": "skipped"}
        check_spamhaus_mock.return_value = {"ip": "8.8.8.8", "status": "clean", "provider": "spamhaus"}

        result = check_hop_ip("", "8.8.8.8")

        self.assertEqual("clean", result["spamhaus"]["status"])
        check_spamhaus_mock.assert_called_once_with("8.8.8.8")

    @patch("fishstop_engine.reputation.check_spamhaus")
    @patch("fishstop_engine.reputation.check_ip")
    def test_spamhaus_is_not_queried_when_abuseipdb_is_configured(self, check_ip, check_spamhaus_mock):
        check_ip.return_value = {"ip": "8.8.8.8", "status": "ok", "abuseConfidenceScore": 0}

        result = check_hop_ip("secret", "8.8.8.8")

        self.assertEqual("skipped", result["spamhaus"]["status"])
        check_spamhaus_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
