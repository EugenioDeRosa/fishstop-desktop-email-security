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

    def test_arc_preserved_origin_softfail_becomes_primary(self):
        effective = select_effective_auth_results(
            [
                "mx.receiver; spf=pass smtp.mailfrom=brand.example; "
                "dkim=none; dmarc=pass header.from=brand.example"
            ],
            [
                "i=3; mx.receiver; spf=pass smtp.mailfrom=brand.example; arc=pass",
                "i=1; mx.forwarder; spf=softfail "
                "smtp.mailfrom=sender@brand.example; dmarc=fail header.from=brand.example",
            ],
            ["softfail client-ip=192.0.2.10"],
        )

        self.assertEqual("softfail", effective["SPF"]["status"])
        self.assertEqual("pass", effective["SPF"]["delivery_status"])
        self.assertEqual("softfail", effective["SPF"]["origin_status"])
        self.assertTrue(effective["SPF"]["sender_boundary_selected"])
        self.assertTrue(effective["SPF"]["path_conflict"])
        self.assertEqual(
            "ARC-Authentication-Results i=1 (sender boundary)",
            effective["SPF"]["source"],
        )
        self.assertEqual(
            "ARC-Authentication-Results i=1",
            effective["SPF"]["origin_source"],
        )

    def test_sender_boundary_remains_primary_when_forwarder_rewrites_envelope_domain(self):
        effective = select_effective_auth_results(
            ["mx.receiver; spf=pass smtp.mailfrom=forwarder.example"],
            [
                "i=2; mx.receiver; spf=pass smtp.mailfrom=forwarder.example; arc=pass",
                "i=1; mx.previous; spf=softfail smtp.mailfrom=sender@brand.example",
            ],
            [],
        )

        self.assertEqual("softfail", effective["SPF"]["status"])
        self.assertEqual("sender@brand.example", effective["SPF"]["origin_identity"])
        self.assertEqual("forwarder.example", effective["SPF"]["delivery_identity"])
        self.assertFalse(effective["SPF"]["same_envelope_domain"])
        self.assertTrue(effective["SPF"]["path_conflict"])

    def test_sender_boundary_pass_is_primary_over_final_receiver_failure(self):
        effective = select_effective_auth_results(
            ["mx.receiver; spf=temperror smtp.mailfrom=brand.example"],
            [
                "i=2; mx.receiver; spf=temperror smtp.mailfrom=brand.example; arc=pass",
                "i=1; mx.previous; spf=pass smtp.mailfrom=sender@brand.example",
            ],
            [],
        )

        self.assertEqual("pass", effective["SPF"]["status"])
        self.assertEqual("temperror", effective["SPF"]["delivery_status"])
        self.assertTrue(effective["SPF"]["path_conflict"])


if __name__ == "__main__":
    unittest.main()
