import os
import tempfile
import unittest
from unittest.mock import patch

from fishstop_engine.brand_intelligence import assess_brand_coherence, _official_sites
from fishstop_engine.identity_store import registry_operation


def entity(name="Acme"):
    return {"name": name, "entity_types": ["ORG"], "verified_claim": True,
            "occurrences": [{"source": "sender", "evidence": name}]}


def message(domain="acme.com", verified=True):
    return {"from_": f"Acme <notice@{domain}>", "return_path": "<bounce@external-delivery.net>",
            "effective_auth_results": {"DMARC": {"status": "pass", "identity": domain}},
            "domain_authentication": {"status": "verified" if verified else "unverified", "verified_domains": [domain] if verified else []}}


class BrandIntelligenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.addCleanup(patch.stopall)
        patch.dict(os.environ, {"FISHSTOP_IDENTITY_DATA_DIR": self.directory.name}).start()
        patch("fishstop_engine.brand_intelligence.dns_observations", return_value={"provider": "Microsoft 365", "status": "observed"}).start()
        patch("fishstop_engine.brand_intelligence.rdap_observations", return_value={"identity_evidence": False}).start()
        self.lookup = patch("fishstop_engine.brand_intelligence._official_sites", return_value=(["https://acme.com/"], "Public reference.")).start()

    def partner(self, relations=None):
        return registry_operation({"operation": "add", "brand": "Acme", "identity_confirmed": True,
            "reference": "Confirmed with the known procurement contact", "relations": relations or [
                {"domain": "acme.com", "role": "official", "scopes": ["sender", "visit_link"]}]})

    def test_independent_authentication_is_distinct_from_company_reference(self):
        result = assess_brand_coherence(message(), [entity()])[0]
        self.assertEqual("aligned", result["status"])
        self.assertEqual("public_reference", result["reference_status"])
        self.assertEqual("verified", result["sender_authentication"])
        self.assertEqual([], result["mismatches"], "An ESP bounce domain is not a sender-brand mismatch")
        result = assess_brand_coherence(message(verified=False), [entity()])[0]
        self.assertEqual("unverified", result["status"])
        self.assertEqual("unverified", result["sender_authentication"])

    def test_forged_dmarc_header_cannot_authenticate_a_brand(self):
        source = message()
        del source["domain_authentication"]
        result = assess_brand_coherence(source, [entity()])[0]
        self.assertEqual("unverified", result["status"])

    def test_redirects_ct_and_shared_provider_cannot_promote_attacker(self):
        with patch("fishstop_engine.brand_intelligence._redirects_to_official_domain", return_value=True) as redirects:
            result = assess_brand_coherence(message("acme-login.com"), [entity()])[0]
        self.assertEqual("mismatch", result["status"])
        self.assertEqual([], result["associated_domains"])
        redirects.assert_not_called()
        self.assertEqual("Microsoft 365", result["dns_observations"]["provider"])
        self.assertEqual(["From"], [item["source"] for item in result["mismatches"]])

    def test_unknown_small_business_is_not_an_impersonation_detection(self):
        self.lookup.return_value = ([], "No independent record.")
        result = assess_brand_coherence(message("small-business.it"), [entity("Small Business")])[0]
        self.assertEqual("unverified", result["status"])
        self.assertEqual([], result["mismatches"])

    def test_small_business_registry_works_without_wikidata(self):
        self.partner()
        self.lookup.return_value = ([], "Unavailable.")
        result = assess_brand_coherence(message(), [entity()])[0]
        self.assertEqual("aligned", result["status"])
        self.assertEqual("administrator_confirmation", result["resolution_source"])
        self.lookup.assert_not_called()
        self.assertGreater(result["evidence"][0]["expires_at"], result["evidence"][0]["observed_at"])

    def test_delegated_sender_does_not_gain_payment_or_credential_authority(self):
        self.partner([{ "domain": "acme.com", "role": "official", "scopes": ["sender", "visit_link"]},
                      { "domain": "mail.service.com", "role": "delegate", "scopes": ["sender"]}])
        result = assess_brand_coherence(message("mail.service.com"), [entity()])[0]
        self.assertEqual("aligned", result["status"])
        self.assertEqual([], result["trusted_action_domains"])
        self.assertFalse(any("pay_or_transfer" in item["scopes"] for item in result["authorized_action_relations"]))
        result = assess_brand_coherence(message("other.service.com"), [entity()])[0]
        self.assertEqual("mismatch", result["status"], "Shared registrable domain does not authorize another tenant")

    def test_authenticated_official_site_link_does_not_authorize_external_service(self):
        with patch("fishstop_engine.brand_intelligence._linked_domains_from_official_site", return_value=frozenset({"external.com"})) as linked:
            result = assess_brand_coherence(message(), [entity()])[0]
        self.assertEqual([], result["trusted_action_domains"])
        linked.assert_not_called()

    def test_only_verified_registry_identity_updates_change_baseline(self):
        self.partner()
        assess_brand_coherence(message(), [entity()])
        with patch("fishstop_engine.brand_intelligence.dns_observations", return_value={"provider": "Other mail provider", "status": "observed"}):
            result = assess_brand_coherence(message(), [entity()])[0]
        self.assertEqual(1, len(result["anomalies"]))
        result = assess_brand_coherence(message(verified=False), [entity()])[0]
        self.assertEqual([], result["anomalies"])


class PublicLookupTests(unittest.TestCase):
    def claim(self, value):
        return {"mainsnak": {"datavalue": {"value": value}}}

    @patch("fishstop_engine.brand_intelligence.put")
    @patch("fishstop_engine.brand_intelligence.cached", return_value=None)
    @patch("fishstop_engine.brand_intelligence._wikidata_json")
    def test_company_and_artwork_homonyms_are_disambiguated(self, fetch, cached, put):
        fetch.side_effect = [{"search": [{"id": "Q194360", "label": "American Express"}, {"id": "Q77551558", "label": "American Express"}]},
          {"entities": {"Q194360": {"claims": {"P31": [self.claim({"id": "Q4830453"})], "P856": [self.claim("https://www.americanexpress.com/")]}},
                        "Q77551558": {"claims": {"P31": [self.claim({"id": "Q3305213"})], "P856": [self.claim("https://museum.example/")]}}}}]
        websites, _ = _official_sites("American Express")
        self.assertEqual(["https://www.americanexpress.com/"], websites)
        self.assertEqual("https://www.wikidata.org/wiki/Q194360", put.call_args.args[1]["reference"])

    @patch("fishstop_engine.brand_intelligence.put")
    @patch("fishstop_engine.brand_intelligence.cached", return_value=None)
    @patch("fishstop_engine.brand_intelligence._wikidata_json")
    def test_two_companies_remain_ambiguous(self, fetch, cached, put):
        claims = {"P31": [self.claim({"id": "Q4830453"})], "P856": [self.claim("https://acme.com/")]}
        fetch.side_effect = [{"search": [{"id": "Q1", "label": "Acme"}, {"id": "Q2", "label": "Acme"}]},
                             {"entities": {"Q1": {"claims": claims}, "Q2": {"claims": claims}}}]
        websites, message = _official_sites("Acme")
        self.assertEqual([], websites)
        self.assertIn("Ambiguous", message)

    @patch("fishstop_engine.brand_intelligence.put")
    @patch("fishstop_engine.brand_intelligence.cached", return_value=None)
    @patch("fishstop_engine.brand_intelligence._wikidata_json", return_value={"search": [{"id": "Q1", "label": "Other Acme"}]})
    def test_fuzzy_match_is_not_accepted(self, fetch, cached, put):
        self.assertEqual([], _official_sites("Acme")[0])
        self.assertEqual(1, fetch.call_count)

    def test_lookup_deadline_does_not_wait_for_all_workers(self):
        import threading
        import time
        release = threading.Event()
        def slow(*args):
            release.wait(.5)
            return {}
        try:
            with patch("fishstop_engine.brand_intelligence.IDENTITY_LOOKUP_BUDGET_SECONDS", .03), \
                 patch("fishstop_engine.brand_intelligence.resolve_partner", return_value=None), \
                 patch("fishstop_engine.brand_intelligence.dns_observations", side_effect=slow), \
                 patch("fishstop_engine.brand_intelligence.rdap_observations", side_effect=slow), \
                 patch("fishstop_engine.brand_intelligence._official_sites", side_effect=lambda *args: (release.wait(.5) and [], "Unavailable")):
                started = time.monotonic()
                result = assess_brand_coherence(message(), [entity()])
                self.assertLess(time.monotonic() - started, .2)
                self.assertEqual("unverified", result[0]["status"])
                self.assertEqual([], result[0]["evidence"])
        finally:
            release.set()


if __name__ == "__main__":
    unittest.main()
