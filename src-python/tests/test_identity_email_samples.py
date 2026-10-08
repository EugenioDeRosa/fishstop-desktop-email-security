"""Minimal, anonymised identity regressions derived from five Desktop/raw EMLs.

No original headers, recipient details, tracking tokens or private mail content
are stored. Network and signature availability are exercised independently.
"""
import unittest
from unittest.mock import patch

from fishstop_engine.analyzer.llm_context_analyzer import (
    _identity_analysis_from_semantic, apply_email_risk_policy,
    _corroborated_reward_impersonation, _grounded_reward_claim,
)
from fishstop_engine.domain_utils import identity_mailbox
from fishstop_engine.identity_store import resolve_partner


SAMPLES = [
    ("sample-10.eml", "Microsoft", {
        "from_": '"Microsoft account team", _ <no-reply@access-accsecurity.com>',
        "body_clean": "Microsoft account Unusual sign.in activity We detected something unusual about a recent sign-in to your account. Report The User",
    }, "inconsistent"),
    ("Congratulazioni! Avete vinto un set di utensili Dexter da 108 pezzi..eml", "Leroy Merlin", {
        "from_": "Dipartimento Leroy-Merlin <Noreply-jnwdkbsf@jnwdkbsf.it>",
        "body_clean": "Sondaggio su LEROY MERLIN Gentile cliente di Leroy Merlin, INIZIA IL SONDAGGIO",
    }, "inconsistent"),
    ("Creazione carta virtuale del 30_06_2026.eml", "Intesa Sanpaolo", {
        "from_": "comunicazioni@intesasanpaolo.com",
        "body_for_intent": "Gentile cliente, è stata creata una carta virtuale. Contatta la filiale digitale.",
        "body_clean": "Gentile cliente, è stata creata una carta virtuale. Contatta la filiale digitale. Grazie Intesa Sanpaolo Questo messaggio è stato inviato da un indirizzo email di sola notifica.",
    }, "insufficient_data"),
    ("Express yourself_ tune your artist profile to perfection.eml", "Spotify", {
        "from_": "Spotify for Artists <no-reply@artists.spotify.com>",
        "body_clean": "Express yourself: tune your artist profile to perfection. Inspire fans.",
    }, "insufficient_data"),
    ("Your music is live_ See how it's performing.eml", "Spotify", {
        "from_": "Spotify for Artists <no-reply@artists.spotify.com>",
        "body_clean": "Your new music is live. Go to Spotify for Artists to see how people are listening to your music.",
    }, "insufficient_data"),
]


class IdentityEmailSamplesTests(unittest.TestCase):
    def reward_report(self):
        report = {
            "from_": "Dipartimento Leroy-Merlin <notice@unrelated-example.it>",
            "body_clean": "Gentile cliente di Leroy Merlin. Per richiedere\nil suo premio, risponda ad alcune\nbrevi domande. Questa offerta è a tempo limitato.",
            "links": [{"url": "https://external-example.com/survey", "host": "external-example.com",
                       "role": "body_action", "html_call_to_action": True, "display_text": "INIZIA IL SONDAGGIO"}],
            "effective_auth_results": {"SPF": {"status": "pass"}},
        }
        report["identity_analysis"] = self.assess(report)
        report["impersonation"] = report["identity_analysis"]["impersonation"]
        return report

    def test_timed_reward_with_documented_identity_contradiction_is_phishing(self):
        report = self.reward_report()
        reward = _grounded_reward_claim(report)
        self.assertTrue(reward["urgency"])
        self.assertIn("richiedere il suo premio", reward["evidence"])
        # The deterministic combination also works when the model misses the CTA.
        result = apply_email_risk_policy(report, {"action": "informational", "channel": "none"})
        self.assertEqual("claim_reward", result["requested_action"])
        self.assertEqual("phishing", result["final_verdict"])
        self.assertTrue(any("time-limited reward" in reason for reason in result["evidence"]["content"]))

    def test_reward_combination_requires_each_piece_of_evidence(self):
        import copy
        baseline = self.reward_report()
        variants = []
        report = copy.deepcopy(baseline)
        report["body_clean"] = "Per richiedere il suo premio, risponda alle domande."
        variants.append(report)
        report = copy.deepcopy(baseline)
        report["impersonation"]["identity_confidence"] = "low"
        variants.append(report)
        report = copy.deepcopy(baseline)
        report["impersonation"]["claimed_role"] = "mention"
        variants.append(report)
        report = copy.deepcopy(baseline)
        report["impersonation"]["status"] = "consistent"
        variants.append(report)
        report = copy.deepcopy(baseline)
        report["identity_analysis"]["coherence"] = []
        variants.append(report)
        report = copy.deepcopy(baseline)
        report["links"] = [{"url": "https://leroymerlin.it/survey", "host": "leroymerlin.it", "role": "body_action"}]
        variants.append(report)
        report = copy.deepcopy(baseline)
        report["links"][0].update(role="tracking", html_call_to_action=False)
        variants.append(report)
        report = copy.deepcopy(baseline)
        report["identity_analysis"]["coherence"][0]["authorized_action_relations"] = [{
            "domain": "external-example.com", "role": "delegate", "scopes": ["claim_reward"], "path_prefix": "/survey"}]
        variants.append(report)
        for index, report in enumerate(variants):
            with self.subTest(index=index):
                self.assertFalse(_corroborated_reward_impersonation(report, {"requested_action": "claim_reward"}))

    def assess(self, report):
        with patch("fishstop_engine.brand_intelligence.dns_observations", return_value={}), \
             patch("fishstop_engine.brand_intelligence.rdap_observations", return_value={}), \
             patch("fishstop_engine.brand_intelligence._official_sites", side_effect=AssertionError("Catalogued brands need no Wikidata lookup")):
            return _identity_analysis_from_semantic(dict(report), {
                "claimed_brand": "", "claimed_role": "unclear", "action": "informational",
            })

    def test_five_samples_recover_identity_when_ai_omits_it(self):
        for filename, brand, report, status in SAMPLES:
            with self.subTest(filename=filename):
                result = self.assess(report)
                self.assertTrue(result["entities"])
                self.assertEqual(brand, resolve_partner(result["impersonation"]["claimed_identity"])["brand"])
                self.assertEqual(result["impersonation"]["claimed_identity"], result["coherence"][0]["brand"])
                self.assertEqual(status, result["impersonation"]["status"])
                self.assertEqual("review" if status == "inconsistent" else "none", result["impersonation"]["decision"])
                self.assertEqual("maintained_catalog", result["coherence"][0]["resolution_source"])

    def test_legitimate_domains_require_independently_verified_signature(self):
        for filename, _, report, _ in SAMPLES[2:]:
            with self.subTest(filename=filename):
                host = identity_mailbox(report["from_"])[1].split("@")[-1]
                result = self.assess({**report, "domain_authentication": {
                    "status": "verified", "verified_domains": [host]}})
                self.assertEqual("consistent", result["impersonation"]["status"])
                self.assertEqual(0, result["impersonation"]["score"])

    def test_signature_from_other_conversation_turn_is_not_appended(self):
        result = self.assess({"from_": "Person <person@example.test>",
            "body_for_intent": "A personal message.",
            "body_clean": "A personal message. Grazie Intesa Sanpaolo",
            "selected_target_authentication_scope": "embedded_unavailable"})
        self.assertEqual([], result["entities"])

    def test_longer_names_and_casual_mentions_are_not_claims(self):
        for report in [{"from_": "Spotify for Artists Fan Club <fan@example.test>"},
                       {"body_clean": "Thanks for your help with Spotify."},
                       {"body_clean": "I bought this at Leroy Merlin."}]:
            self.assertEqual([], self.assess(report)["entities"])

    def test_multiple_explicit_mailboxes_are_not_recovered(self):
        self.assertEqual(("", ""), identity_mailbox('Microsoft <a@example.test>, Other <b@example.test>'))


if __name__ == "__main__":
    unittest.main()
