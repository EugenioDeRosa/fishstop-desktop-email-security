import unittest

from fishstop_engine.analyzer.received_parser import (
    build_authentication_checkpoints,
    select_effective_auth_results,
)


class AuthenticationResultPrecedenceTests(unittest.TestCase):
    def test_checkpoints_link_only_explicit_authentication_evidence(self):
        hops = [
            {
                "sender_ip": "198.51.100.20",
                "all_ips": ["198.51.100.20"],
                "from_host": "relay.example",
                "by_host": "mx.receiver",
                "received_at": "2026-09-10T10:02:00+00:00",
            },
            {
                "sender_ip": "203.0.113.10",
                "all_ips": ["203.0.113.10"],
                "from_host": "sender.example",
                "by_host": "relay.example",
                "received_at": "2026-09-10T10:01:00+00:00",
            },
        ]
        checkpoints = build_authentication_checkpoints(
            [
                "mx.receiver; spf=fail smtp.remote-ip=198.51.100.20 "
                "smtp.mailfrom=sender.example; dkim=pass header.d=sender.example; "
                "dmarc=fail header.from=sender.example"
            ],
            [],
            [],
            hops,
        )

        self.assertEqual(["SPF", "DKIM", "DMARC"], [item["protocol"] for item in checkpoints])
        self.assertTrue(all(item["association"] == "exact" for item in checkpoints))
        self.assertTrue(all(item["linked_hop_index"] == 1 for item in checkpoints))
        self.assertEqual("client-ip", checkpoints[0]["link_basis"])
        self.assertEqual("sender.example", checkpoints[0]["identity"])
        self.assertEqual("authserv-id", checkpoints[1]["link_basis"])

    def test_checkpoint_remains_unmapped_when_header_has_no_exact_hop(self):
        checkpoints = build_authentication_checkpoints(
            ["unknown.evaluator; dkim=fail header.d=sender.example"],
            [],
            [],
            [{"sender_ip": "203.0.113.10", "all_ips": ["203.0.113.10"], "by_host": "mx.receiver"}],
        )

        self.assertEqual("unmapped", checkpoints[0]["association"])
        self.assertIsNone(checkpoints[0]["linked_hop_index"])

    def test_received_spf_checkpoint_uses_explicit_client_ip(self):
        checkpoints = build_authentication_checkpoints(
            [],
            [],
            ["SoftFail client-ip=203.0.113.10; envelope-from=sender@example.com"],
            [{"sender_ip": "203.0.113.10", "all_ips": ["203.0.113.10"], "by_host": "mx.receiver"}],
        )

        self.assertEqual("SPF", checkpoints[0]["protocol"])
        self.assertEqual("softfail", checkpoints[0]["status"])
        self.assertEqual("exact", checkpoints[0]["association"])
        self.assertEqual("client-ip", checkpoints[0]["link_basis"])

    def test_reused_client_ip_is_not_forced_onto_an_ambiguous_hop(self):
        checkpoints = build_authentication_checkpoints(
            [],
            [],
            ["Pass client-ip=203.0.113.10; envelope-from=sender@example.com"],
            [
                {"sender_ip": "203.0.113.10", "all_ips": ["203.0.113.10"], "by_host": "mx.one"},
                {"sender_ip": "203.0.113.10", "all_ips": ["203.0.113.10"], "by_host": "mx.two"},
            ],
        )

        self.assertEqual("unmapped", checkpoints[0]["association"])
        self.assertIsNone(checkpoints[0]["linked_hop_index"])

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
