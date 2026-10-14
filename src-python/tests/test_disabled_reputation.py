import os
import unittest
from unittest.mock import patch

from fishstop_engine import reputation


class DisabledReputationTests(unittest.TestCase):
    def test_disabled_providers_never_make_api_or_fallback_calls(self):
        report = {
            "links": [{"url": "https://example.test", "scheme": "https"}],
            "received_hops": [{"sender_ip": "8.8.8.8"}],
            "from_": "sender@example.test",
            "attachments": [{"hash_sha256": "a" * 64}],
        }
        with patch.object(reputation, "check_url") as url, \
             patch.object(reputation, "check_file") as file, \
             patch.object(reputation, "check_vt_domain") as domain, \
             patch.object(reputation, "check_hop_ip") as ip, \
             patch.object(reputation, "check_spamhaus") as fallback, \
             patch.object(reputation, "geolocate", return_value={}), \
             patch.object(reputation, "check_rdap_domain", return_value={}):
            reputation.enrich(report, "stored-vt", "stored-abuse", disabled_providers={"virustotal", "abuseipdb"})
            for service in [url, file, domain, ip, fallback]:
                service.assert_not_called()
        self.assertEqual(report["link_reputation"]["https://example.test"]["status"], "disabled")
        self.assertEqual(report["hop_reputation"]["8.8.8.8"]["status"], "disabled")
        self.assertEqual(report["attachments"][0]["file_reputation"]["status"], "disabled")

    def test_enabled_ip_checks_keep_working(self):
        report = {"received_hops": [{"sender_ip": "8.8.8.8"}]}
        with patch.object(reputation, "check_hop_ip", return_value={"status": "ok"}) as ip, \
             patch.object(reputation, "geolocate", return_value={}):
            reputation.enrich(report, "", "key", disabled_providers={"virustotal"})
            ip.assert_called_once_with("key", "8.8.8.8")

    def test_disabled_otx_is_not_invoked(self):
        # Exercise the entry point's actual enrichment block with network mocks.
        from pathlib import Path
        source = (Path(__file__).parents[1] / "main.py").read_text(encoding="utf-8")
        start = source.index('    disabled_providers = set(')
        end = source.index('    return _json_safe(report)', start)
        import textwrap
        with patch.dict(os.environ, {"FISHSTOP_DISABLED_PROVIDERS": "otx", "OTX_API_KEY": "stored-key"}), \
             patch.object(reputation, "enrich") as enrich, \
             patch("fishstop_engine.otx_intelligence.apply_on_demand_otx_intelligence") as otx:
            scope = {"os": os, "report": {}, "enrich_reputation": enrich, "apply_on_demand_otx_intelligence": otx}
            exec(textwrap.dedent(source[start:end]), scope)
            otx.assert_not_called()
            self.assertEqual(scope["report"]["otx_intelligence"]["status"], "disabled")


if __name__ == "__main__":
    unittest.main()
