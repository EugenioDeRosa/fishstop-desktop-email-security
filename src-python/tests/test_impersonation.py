import copy
import unittest
from fishstop_engine.impersonation import assess_impersonation
from fishstop_engine.analyzer.llm_context_analyzer import _identity_risk


class ImpersonationTests(unittest.TestCase):
    def setUp(self):
        self.entity = [{"name": "Acme", "verified_claim": True, "occurrences": [{"source": "sender", "evidence": "Acme Support"}]}]
        self.report = {"from_": "Acme Support <notice@acme.com>",
                       "domain_authentication": {"status": "verified", "verified_domains": ["acme.com"]}}
        self.reference = [{"brand": "Acme", "official_domains": ["acme.com"], "resolution_source": "wikidata",
            "contacts": [{"source": "From", "matches_official": True}],
            "dns_observations": {"status": "observed"}, "registration_observations": {"status": "unavailable"}}]
        self.semantic = {"claimed_role": "representative", "requested_action": "informational"}

    def assess(self):
        return assess_impersonation(self.report, self.entity, self.semantic, self.reference)

    def test_documented_signature_verifies_identity_without_three_sources(self):
        result = self.assess()
        self.assertEqual("consistent", result["status"])
        self.assertEqual("high", result["confidence"])
        self.assertEqual(0, result["score"])
        self.assertIn("rdap_unavailable", result["missing"])

    def test_forged_pass_headers_do_not_authenticate(self):
        self.report.pop("domain_authentication")
        self.report["auth_results"] = {"DMARC": {"status": "pass", "identity": "acme.com"}}
        self.assertEqual("insufficient_data", self.assess()["status"])

    def test_unknown_company_offline_is_neutral(self):
        self.reference = []
        self.report["from_"] = "Acme <x@gmail.com>"
        result = self.assess()
        self.assertEqual(0, result["score"])
        self.assertEqual("none", result["decision"])

    def test_free_mail_claim_is_review_not_phishing(self):
        self.report["from_"] = "Acme Support <x@gmail.com>"
        self.reference[0]["contacts"][0]["matches_official"] = False
        result = self.assess()
        self.assertEqual("review", result["decision"])
        self.assertEqual(25, result["score"], "Correlated sender observations are capped")

    def test_customer_mention_does_not_accuse(self):
        self.report["from_"] = "Customer <x@gmail.com>"
        self.semantic["claimed_role"] = "mention"
        self.reference[0]["contacts"][0]["matches_official"] = False
        self.assertEqual([], self.assess()["signals"])

    def test_longer_unrelated_company_name_is_not_a_display_claim(self):
        self.report["from_"] = "Acme Valley Dental <x@gmail.com>"
        self.semantic["claimed_role"] = "unclear"
        self.assertEqual([], self.assess()["signals"])

    def test_esp_bounces_and_newsletter_links_are_not_suspicious(self):
        self.report.update(return_path="bounce@esp.test", links=[{"host": "tracker.esp.test", "url": "https://tracker.esp.test/open", "html_call_to_action": True}])
        self.semantic["requested_action"] = "visit_link"
        self.assertEqual("consistent", self.assess()["status"])
        self.assertEqual("none", self.assess()["decision"])

    def test_sender_lookalike_missing_authentication_does_not_escalate(self):
        self.report["from_"] = "Acme <x@acm3.com>"
        self.reference[0]["contacts"][0]["matches_official"] = False
        self.semantic.update(requested_action="provide_credentials", evidence_phrase="Enter your password")
        result = self.assess()
        self.assertEqual("inconsistent", result["status"])
        self.assertEqual("review", result["decision"])
        self.report["impersonation"] = result
        self.assertEqual("uncertain", _identity_risk(self.report, self.semantic)[0])

    def test_sensitive_action_lookalike_is_concrete_impersonation(self):
        self.semantic.update(requested_action="provide_credentials", evidence_phrase="Enter your password")
        self.report["links"] = [{"host": "acm3.com", "url": "https://acm3.com/login", "html_call_to_action": True}]
        result = self.assess()
        self.assertEqual("phishing", result["decision"])
        self.assertEqual("inconsistent", result["status"])
        self.assertGreater(result["score"], 0, "Sender authentication cannot cancel an action contradiction")
        self.report["impersonation"] = result
        self.assertEqual("spoofing_evidence", _identity_risk(self.report, self.semantic)[0])

    def test_unrelated_sensitive_destination_without_lookalike_is_review(self):
        self.semantic.update(requested_action="pay_or_transfer", evidence_phrase="Pay the invoice")
        self.report["links"] = [{"host": "billing.vendor.test", "url": "https://billing.vendor.test/pay", "html_call_to_action": True}]
        self.assertEqual("review", self.assess()["decision"])

    def test_old_domain_and_strict_policy_do_not_grant_identity(self):
        self.report["from_"] = "Acme <x@unrelated.test>"
        self.reference[0]["contacts"][0]["matches_official"] = False
        self.reference[0].update(registration_observations={"status": "observed", "events": [{"action": "registration", "date": "2000-01-01T00:00:00Z"}]}, dns_observations={"status": "observed", "dmarc": ["v=DMARC1; p=reject"]})
        self.assertNotEqual("consistent", self.assess()["status"])

    def test_function_does_not_mutate_report(self):
        before = copy.deepcopy(self.report)
        self.assess()
        self.assertEqual(before, self.report)

    def test_public_reference_mismatch_is_visible_as_possible_impersonation(self):
        self.report["from_"] = "Acme <notice@unrelated.test>"
        self.reference[0]["contacts"][0]["matches_official"] = False
        result = self.assess()
        self.assertEqual("inconsistent", result["status"])
        self.assertEqual("review", result["decision"], "A public list alone cannot convict phishing")

    def test_account_verification_to_personal_mailbox_is_strong_destination_evidence(self):
        self.reference[0]["resolution_source"] = "maintained_catalog"
        self.report["links"] = [{"url": "mailto:security@gmail.com", "host": "gmail.com",
                                 "scheme": "mailto", "html_call_to_action": True}]
        self.semantic.update(requested_action="verify_account", evidence_phrase="Verify your account")
        result = self.assess()
        self.assertEqual("phishing", result["decision"])
        self.assertTrue(any(s["id"] == "personal_mailbox_action" for s in result["signals"]))
        self.semantic["requested_action"] = "visit_link"
        self.assertFalse(any(s["id"] == "personal_mailbox_action" for s in self.assess()["signals"]))

    def test_incomplete_public_reference_and_personal_mailbox_require_review(self):
        self.report["links"] = [{"url": "mailto:owner@gmail.com", "host": "gmail.com",
                                 "scheme": "mailto", "html_call_to_action": True}]
        self.semantic.update(requested_action="verify_account", evidence_phrase="Verify your account")
        self.assertEqual("review", self.assess()["decision"])

    def test_platform_notification_does_not_claim_software_vendor_identity(self):
        self.semantic["claimed_role"] = "third_party"
        self.report["from_"] = "Acme <notice@customer.test>"
        self.reference[0]["contacts"][0]["matches_official"] = False
        result = self.assess()
        self.assertEqual([], result["signals"])
        self.assertFalse(result["coverage"]["claim"])

    def test_official_domain_does_not_bypass_documented_action_scope(self):
        self.reference[0]["resolution_source"] = "maintained_catalog"
        self.reference[0]["documented_action_relations"] = [{"domain": "acme.com", "role": "official", "scopes": ["visit_link"]}]
        self.report["links"] = [{"url": "https://acme.com/payment", "host": "acme.com", "html_call_to_action": True}]
        self.semantic.update(requested_action="pay_or_transfer", evidence_phrase="Pay the invoice")
        self.assertEqual("review", self.assess()["decision"])
        self.reference[0]["documented_action_relations"][0]["scopes"].append("pay_or_transfer")
        self.assertEqual("none", self.assess()["decision"])

    def test_pipeline_normalizes_the_action_before_assessing_identity(self):
        from unittest.mock import patch
        from fishstop_engine.analyzer.llm_context_analyzer import _identity_analysis_from_semantic
        self.report.update(body_for_ai="Enter your password to verify your Acme account.",
            links=[{"host": "acm3.com", "url": "https://acm3.com/login", "html_call_to_action": True}])
        raw = {"claimed_brand": "Acme", "claimed_role": "representative", "action": "provide_credentials",
               "channel": "link", "evidence": "Enter your password", "credential_type": "password"}
        with patch("fishstop_engine.brand_intelligence.assess_brand_coherence", return_value=self.reference):
            result = _identity_analysis_from_semantic(self.report, raw)
        self.assertEqual("phishing", result["impersonation"]["decision"])
        self.assertIs(self.report["impersonation"], result["impersonation"])

    def test_microsoft_account_heading_recovers_an_omitted_ai_identity(self):
        from unittest.mock import patch
        from fishstop_engine.analyzer.llm_context_analyzer import _identity_analysis_from_semantic
        body = "Microsoft account Unusual sign.in activity We detected something unusual about a recent sign-in to the Microsoft account phishing@pot. Sign-in details Country/region: Russia/Moscow IP address: 103.225.77.255 Date: Fri, 08 Sep 2023 05:46:57 +0000 Platform: Windows 10 Browser: Firefox A user from Russia/Moscow just logged into your account from a new device, If this wasn't you, please report the user. If this was you, we'll trust similar activity in the future. Report The User To opt out or change where you receive security notifications, click here."
        report = {"body_clean": body}
        semantic = {"claimed_brand": "", "action": "visit_link", "channel": "link", "evidence": "please report the user"}
        with patch("fishstop_engine.brand_intelligence.assess_brand_coherence", return_value=[{
            "brand": "Microsoft", "official_domains": ["microsoft.com"], "resolution_source": "maintained_catalog"}]):
            result = _identity_analysis_from_semantic(report, semantic)
        self.assertEqual("Microsoft", result["entities"][0]["name"])
        self.assertEqual("representative", result["impersonation"]["claimed_role"])
        self.assertEqual("none", result["impersonation"]["decision"], "Body identity alone cannot authenticate or accuse a sender")
        self.assertEqual("insufficient_data", result["impersonation"]["status"])

    def test_brand_mentions_and_longer_names_do_not_trigger_fallback(self):
        from fishstop_engine.analyzer.llm_context_analyzer import _visible_identity_fallback
        for report in [{"body_clean": "I use my Microsoft account. We detected an error."},
                       {"from_": "Apple Valley Dental <x@example.test>"},
                       {"body_clean": "Microsoft account is a service I use for work."}]:
            self.assertEqual(("", "unclear"), _visible_identity_fallback(report))

    def test_explicit_heading_recovers_omitted_representative_role(self):
        from unittest.mock import patch
        from fishstop_engine.analyzer.llm_context_analyzer import _identity_analysis_from_semantic
        report = {"body_clean": "Microsoft account Unusual sign-in activity. We detected a new sign-in to your account."}
        with patch("fishstop_engine.brand_intelligence.assess_brand_coherence", return_value=[]):
            result = _identity_analysis_from_semantic(report, {"claimed_brand": "Microsoft", "claimed_role": "unclear"})
        self.assertEqual("representative", result["impersonation"]["claimed_role"])

    def test_sensitive_lookalike_is_checked_even_when_sender_metadata_is_missing(self):
        self.report.pop("from_")
        self.report.pop("domain_authentication")
        self.semantic.update(requested_action="provide_credentials", evidence_phrase="Enter your password")
        self.reference[0]["contacts"] = []
        self.report["links"] = [{"host": "acm3.com", "url": "https://acm3.com/login", "html_call_to_action": True}]
        result = self.assess()
        self.assertTrue(any(item["id"] == "action_lookalike" for item in result["signals"]))
        self.assertFalse(any(item["id"] == "sender_domain_mismatch" for item in result["signals"]))


if __name__ == "__main__":
    unittest.main()
