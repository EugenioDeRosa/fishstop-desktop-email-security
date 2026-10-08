import unittest
from unittest.mock import patch

from fishstop_engine.analyzer.llm_context_analyzer import (
    _strongly_authenticated_sender, _requested_links_match_verified_organisation,
    _identity_risk, _content_risk,
    _claimed_brand_domain_mismatch,
)


class IdentityPolicyTests(unittest.TestCase):
    def test_header_pass_is_not_described_as_incomplete_authentication(self):
        report = {"from_": "Person <sender@sielups.com>",
            "domain_authentication": {"status": "unverified", "verified_domains": []},
            "effective_auth_results": {name: {"status": "pass"} for name in ("SPF", "DKIM", "DMARC")}}
        status, reasons = _identity_risk(report)
        self.assertEqual("uncertain", status)
        self.assertIn("SPF, DKIM and DMARC are reported as PASS", reasons[0])
        self.assertIn("could not be independently verified", reasons[0])
        self.assertNotIn("incomplete", " ".join(reasons))

    def test_header_failure_remains_explicit(self):
        report = {"from_": "Person <sender@example.com>",
            "domain_authentication": {"status": "unverified"},
            "effective_auth_results": {"SPF": {"status": "fail"}, "DKIM": {"status": "pass"}, "DMARC": {"status": "fail"}}}
        self.assertIn("SPF did not pass (fail)", _identity_risk(report)[1])

    def test_relay_warning_explains_its_limited_scope(self):
        from fishstop_engine.analyzer.llm_context_analyzer import _technical_risk
        report = {"hop_reputation": {"2a01:111:f403:c200::3": {
            "status": "suspicious", "abuseConfidenceScore": 30, "totalReports": 19}}}
        _, reasons = _technical_risk(report)
        self.assertTrue(any("delivery infrastructure" in reason and "does not confirm a threat" in reason for reason in reasons))

    def report(self):
        return {"from_": "Acme <notice@acme.com>",
                "domain_authentication": {"status": "verified", "verified_domains": ["acme.com"]},
                "effective_auth_results": {"DMARC": {"status": "pass"}},
                "links": [{"url": "https://acme.com/account", "host": "acme.com"}],
                "identity_analysis": {"coherence": [{"brand": "Acme", "status": "aligned",
                    "sender_authentication": "verified", "authorized_action_relations": [
                        {"domain": "acme.com", "role": "official", "scopes": ["visit_link"]}]}]}}

    def test_header_pass_cannot_override_failed_independent_verification(self):
        report = self.report()
        report["domain_authentication"]["status"] = "unverified"
        self.assertFalse(_strongly_authenticated_sender(report))
        self.assertFalse(_requested_links_match_verified_organisation(report))

    def test_action_scope_and_exact_delegated_host_are_enforced_by_policy(self):
        report = self.report()
        self.assertTrue(_requested_links_match_verified_organisation(report, {"requested_action": "visit_link"}))
        self.assertFalse(_requested_links_match_verified_organisation(report, {"requested_action": "pay_or_transfer"}))
        report["identity_analysis"]["coherence"][0]["authorized_action_relations"] = [
            {"domain": "tenant.service.com", "role": "delegate", "scopes": ["visit_link"], "path_prefix": "/acme"}]
        report["links"] = [{"url": "https://other.service.com/acme/account", "host": "other.service.com"}]
        self.assertFalse(_requested_links_match_verified_organisation(report))
        report["links"] = [{"url": "https://tenant.service.com/acme/account", "host": "tenant.service.com"}]
        self.assertTrue(_requested_links_match_verified_organisation(report))

    def test_partial_public_domain_list_creates_review_not_impersonation_conviction(self):
        report = self.report()
        report["identity_analysis"]["coherence"] = [{"brand": "Acme", "status": "mismatch",
            "official_domain": "acme.com", "reference_status": "public_reference",
            "mismatches": [{"source": "From"}, {"source": "Link action"}]}]
        status, _ = _identity_risk(report, {"requested_action": "verify_account", "action_channel": "supplied_link"})
        self.assertEqual("uncertain", status)

    def test_authenticated_partner_still_detects_payment_diversion(self):
        semantic = {"action_channel": "supplied_link", "requested_action": "pay_or_transfer",
                    "asks_to_click_link": True, "asks_to_open_attachment": False,
                    "asks_for_credentials": False, "asks_for_sensitive_information": False,
                    "asks_for_payment": True, "asks_to_change_account_settings": False,
                    "asks_to_verify_account": False, "asks_to_claim_reward": False,
                    "payment_method": "bank_transfer", "payment_destination_change": True,
                    "payment_change_evidence": "Use our new bank account", "scam_type": "invoice_fraud"}
        risk, _ = _content_risk(self.report(), semantic)
        self.assertEqual("malicious", risk)

    def test_unresolved_company_does_not_revive_legacy_static_assertions(self):
        report = self.report()
        report["identity_analysis"]["coherence"] = []
        with patch("fishstop_engine.identity_store.resolve_partner", return_value=None):
            self.assertFalse(_claimed_brand_domain_mismatch(report,
                {"requested_action": "verify_account", "claimed_brand": "Microsoft"}))


if __name__ == "__main__":
    unittest.main()
