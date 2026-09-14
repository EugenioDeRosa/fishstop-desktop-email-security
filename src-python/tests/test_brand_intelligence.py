import unittest
from unittest.mock import patch

from fishstop_engine.brand_intelligence import (
    _crt_sh_candidate_domains,
    assess_brand_coherence,
)


def google_entity() -> dict:
    return {
        "name": "Google",
        "entity_types": ["ORG"],
        "occurrences": [{"source": "sender", "evidence": "Google"}],
    }


def report(*, dmarc: str = "pass", identity: str = "google.com") -> dict:
    return {
        "from_": 'Google <drive-shares-noreply@google.com>',
        "reply_to": "Formazione Cefla <formazione@cefla.it>",
        "return_path": "<bounce@doclist.bounces.google.com>",
        "effective_auth_results": {
            "DMARC": {"status": dmarc, "identity": identity},
        },
    }


class BrandIntelligenceTests(unittest.TestCase):
    def tearDown(self):
        _crt_sh_candidate_domains.cache_clear()

    @patch("fishstop_engine.brand_intelligence.requests.get")
    def test_crt_sh_extracts_deduplicated_registrable_candidates(self, get):
        response = get.return_value
        response.raise_for_status.return_value = None
        response.json.return_value = [
            {"name_value": "*.paypal.it\nlogin.paypal.it"},
            {"name_value": "www.paypal.com\n"},
            {"name_value": ""},
        ]

        candidates = _crt_sh_candidate_domains("PayPal")

        self.assertEqual(frozenset({"paypal.it", "paypal.com"}), candidates)
        get.assert_called_once_with(
            "https://crt.sh/",
            params={"q": "%.paypal.%", "output": "json"},
            timeout=6,
            headers={"User-Agent": "FishStopDesktop/0.1 (local email-security analysis)"},
        )

    @patch(
        "fishstop_engine.brand_intelligence._linked_domains_from_official_site",
        return_value=frozenset({"google.com", "support.google.com"}),
    )
    @patch(
        "fishstop_engine.brand_intelligence._official_sites",
        return_value=(["https://about.google/"], "Resolved."),
    )
    def test_authenticated_operational_domain_linked_by_official_site_is_aligned(
        self, _official_sites, _linked_domains
    ):
        result = assess_brand_coherence(report(), [google_entity()])[0]

        self.assertEqual("about.google", result["official_domain"])
        self.assertEqual(["about.google"], result["official_domains"])
        self.assertEqual(["google.com"], result["associated_domains"])
        self.assertEqual([], result["mismatches"])
        self.assertEqual("aligned", result["status"])
        self.assertEqual(["cefla.it"], result["external_reply_domains"])

        contacts = {item["source"]: item for item in result["contacts"]}
        self.assertTrue(contacts["From"]["matches_official"])
        self.assertTrue(contacts["Return-Path"]["matches_official"])
        self.assertFalse(contacts["Reply-To"]["mismatch_eligible"])
        self.assertTrue(contacts["Reply-To"]["is_external"])

    @patch(
        "fishstop_engine.brand_intelligence._linked_domains_from_official_site",
        return_value=frozenset({"google.com"}),
    )
    @patch(
        "fishstop_engine.brand_intelligence._official_sites",
        return_value=(["https://about.google/"], "Resolved."),
    )
    def test_failed_dmarc_does_not_promote_operational_domain(
        self, _official_sites, _linked_domains
    ):
        result = assess_brand_coherence(report(dmarc="fail"), [google_entity()])[0]

        self.assertEqual([], result["associated_domains"])
        self.assertEqual("mismatch", result["status"])
        self.assertEqual({"From", "Return-Path"}, {
            item["source"] for item in result["mismatches"]
        })

    @patch(
        "fishstop_engine.brand_intelligence._linked_domains_from_official_site",
        return_value=frozenset({"google-login.com"}),
    )
    @patch(
        "fishstop_engine.brand_intelligence._official_sites",
        return_value=(["https://about.google/"], "Resolved."),
    )
    def test_lookalike_label_is_not_promoted(self, _official_sites, _linked_domains):
        suspicious = report(identity="google-login.com")
        suspicious["from_"] = "Google <notice@google-login.com>"
        suspicious["return_path"] = "<bounce@google-login.com>"

        result = assess_brand_coherence(suspicious, [google_entity()])[0]

        self.assertEqual([], result["associated_domains"])
        self.assertEqual("mismatch", result["status"])

    @patch(
        "fishstop_engine.brand_intelligence._official_sites",
        return_value=(
            ["https://brand.com/", "https://brand.org/"],
            "Resolved.",
        ),
    )
    def test_all_official_website_domains_are_accepted(self, _official_sites):
        entity = {
            "name": "Brand",
            "entity_types": ["ORG"],
            "occurrences": [{"source": "sender", "evidence": "Brand"}],
        }
        source = {
            "from_": "Brand <notice@brand.org>",
            "return_path": "<bounce@brand.org>",
        }

        result = assess_brand_coherence(source, [entity])[0]

        self.assertEqual(
            ["brand.com", "brand.org"],
            result["official_domains"],
        )
        self.assertEqual([], result["associated_domains"])
        self.assertEqual([], result["mismatches"])

    @patch(
        "fishstop_engine.brand_intelligence._linked_domains_from_official_site",
        return_value=frozenset({"brand.com", "brand-service.net"}),
    )
    @patch(
        "fishstop_engine.brand_intelligence._official_sites",
        return_value=(["https://brand.com/"], "Resolved."),
    )
    def test_authenticated_action_domain_linked_by_official_site_is_trusted(
        self, _official_sites, _linked_domains
    ):
        source = {
            "from_": "Brand <security@brand.com>",
            "return_path": "<security@brand.com>",
            "effective_auth_results": {
                "DMARC": {"status": "pass", "identity": "brand.com"},
            },
            "links": [{
                "url": "https://brand-service.net/security",
                "host": "brand-service.net",
                "scheme": "https",
                "role": "body_action",
                "actionable": True,
            }],
        }
        entity = {
            "name": "Brand",
            "entity_types": ["ORG"],
            "occurrences": [{"source": "sender", "evidence": "Brand"}],
        }

        result = assess_brand_coherence(source, [entity])[0]

        self.assertEqual(["brand-service.net"], result["trusted_action_domains"])

    @patch(
        "fishstop_engine.brand_intelligence._redirects_to_official_domain",
        return_value=True,
    )
    @patch(
        "fishstop_engine.brand_intelligence._crt_sh_candidate_domains",
        return_value=frozenset({"paypal.it"}),
    )
    @patch(
        "fishstop_engine.brand_intelligence._linked_domains_from_official_site",
        return_value=frozenset(),
    )
    @patch(
        "fishstop_engine.brand_intelligence._official_sites",
        return_value=(["https://paypal.com/"], "Resolved."),
    )
    def test_ct_candidate_requires_verified_redirect_before_association(
        self, _official_sites, _linked_domains, crt_candidates, redirects
    ):
        source = {
            "from_": "PayPal <service@paypal.it>",
            "return_path": "<bounce@paypal.it>",
            "effective_auth_results": {
                "DMARC": {"status": "pass", "identity": "paypal.it"},
            },
        }
        entity = {
            "name": "PayPal",
            "entity_types": ["ORG"],
            "occurrences": [{"source": "sender", "evidence": "PayPal"}],
        }

        result = assess_brand_coherence(source, [entity])[0]

        self.assertEqual(["paypal.it"], result["associated_domains"])
        self.assertEqual("aligned", result["status"])
        crt_candidates.assert_called_once_with("paypal")
        redirects.assert_any_call("paypal.it", "paypal.com")

    @patch(
        "fishstop_engine.brand_intelligence._redirects_to_official_domain",
        return_value=False,
    )
    @patch(
        "fishstop_engine.brand_intelligence._crt_sh_candidate_domains",
        return_value=frozenset({"paypal.it"}),
    )
    @patch(
        "fishstop_engine.brand_intelligence._linked_domains_from_official_site",
        return_value=frozenset(),
    )
    @patch(
        "fishstop_engine.brand_intelligence._official_sites",
        return_value=(["https://paypal.com/"], "Resolved."),
    )
    def test_ct_presence_alone_does_not_associate_domain(
        self, _official_sites, _linked_domains, _crt_candidates, _redirects
    ):
        source = {
            "from_": "PayPal <service@paypal.it>",
            "return_path": "<bounce@paypal.it>",
            "effective_auth_results": {
                "DMARC": {"status": "pass", "identity": "paypal.it"},
            },
        }
        entity = {
            "name": "PayPal",
            "entity_types": ["ORG"],
            "occurrences": [{"source": "sender", "evidence": "PayPal"}],
        }

        result = assess_brand_coherence(source, [entity])[0]

        self.assertEqual([], result["associated_domains"])
        self.assertEqual("mismatch", result["status"])


if __name__ == "__main__":
    unittest.main()
