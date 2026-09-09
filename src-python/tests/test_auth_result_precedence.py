import unittest

from fishstop_engine.analyzer.received_parser import select_effective_auth_results


class AuthenticationResultPrecedenceTests(unittest.TestCase):
    def test_direct_receiver_pass_is_not_overridden_by_historical_arc_none(self):
        effective = select_effective_auth_results(
            [
                "mx.receiver; spf=pass smtp.mailfrom=brand.example; "
                "dkim=pass header.d=brand.example; "
                "dmarc=pass header.from=brand.example"
            ],
            [
                "i=2; mx.receiver; spf=pass smtp.mailfrom=brand.example; "
                "dkim=pass header.d=brand.example; dmarc=pass header.from=brand.example",
                "i=1; mx.previous; spf=none; dkim=none; dmarc=none",
            ],
            ["Pass client-ip=192.0.2.1"],
        )

        self.assertEqual("pass", effective["SPF"]["status"])
        self.assertEqual("pass", effective["DKIM"]["status"])
        self.assertEqual("pass", effective["DMARC"]["status"])
        self.assertEqual("Authentication-Results", effective["SPF"]["source"])

    def test_latest_arc_instance_fills_only_missing_direct_protocols(self):
        effective = select_effective_auth_results(
            ["mx.receiver; dmarc=pass header.from=brand.example"],
            [
                "i=1; mx.previous; spf=none; dkim=none",
                "i=2; mx.forwarder; spf=pass smtp.mailfrom=brand.example; "
                "dkim=pass header.d=brand.example",
            ],
            [],
        )

        self.assertEqual("pass", effective["DMARC"]["status"])
        self.assertEqual("Authentication-Results", effective["DMARC"]["source"])
        self.assertEqual("pass", effective["SPF"]["status"])
        self.assertEqual("ARC-Authentication-Results", effective["SPF"]["source"])

    def test_received_spf_is_used_only_when_no_authentication_result_exists(self):
        effective = select_effective_auth_results([], [], ["Pass client-ip=192.0.2.1"])

        self.assertEqual("pass", effective["SPF"]["status"])
        self.assertEqual("Received-SPF", effective["SPF"]["source"])


if __name__ == "__main__":
    unittest.main()
