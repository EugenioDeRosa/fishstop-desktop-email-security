import os
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

from fishstop_engine.brand_intelligence import _official_sender_evidence, assess_brand_coherence
from fishstop_engine.ai_input import compact_ai_body
from fishstop_engine.analyzer.link_extractor import extract_links
from fishstop_engine.impersonation import assess_impersonation


class SenderRelationshipTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        environment = patch.dict(os.environ, {"FISHSTOP_IDENTITY_DATA_DIR": directory.name})
        environment.start()
        self.addCleanup(environment.stop)

    def lookup(self, page, **kwargs):
        response = MagicMock(status_code=200, headers={"Content-Type": "text/html"})
        response.iter_content.return_value = [page.encode()]
        response.__enter__.return_value = response
        session = MagicMock()
        session.get.return_value = response
        with patch("fishstop_engine.brand_intelligence.requests.Session", return_value=session), patch(
                "fishstop_engine.brand_intelligence._resolves_only_to_public_addresses", return_value=kwargs.get("public", True)):
            result = _official_sender_evidence(["https://acme.com/"], "acme.it", time.monotonic() + 3)
        return result, session

    def test_explicit_email_contact_is_corroborated_and_cached_with_source(self):
        evidence, session = self.lookup('<a href="mailto:help@acme.it">Contact</a>')
        self.assertEqual("acme.it", evidence["domain"])
        self.assertEqual("https://acme.com/", evidence["reference"])
        again = _official_sender_evidence(["https://acme.com/"], "acme.it", time.monotonic() + 3)
        self.assertEqual(evidence, again)
        self.assertEqual(1, session.get.call_count)

    def test_generic_links_and_different_email_domain_do_not_confirm(self):
        evidence, _ = self.lookup('<a href="https://acme.it/">Site</a><a href="mailto:x@acme.it.attacker.com">Contact</a>')
        self.assertEqual({}, evidence)

    def test_private_official_host_is_not_requested(self):
        evidence, session = self.lookup('<a href="mailto:x@acme.it">Contact</a>', public=False)
        self.assertEqual({}, evidence)
        session.get.assert_not_called()

    def test_corroboration_does_not_authenticate_or_authorize_actions(self):
        report = {"from_": "Acme <x@acme.it>", "domain_authentication": {"status": "unverified"}}
        entities = [{"name": "Acme", "verified_claim": True, "entity_types": ["ORG"], "occurrences": [{"source": "sender", "evidence": "Acme"}]}]
        with patch("fishstop_engine.brand_intelligence.resolve_partner", return_value=None), patch(
                "fishstop_engine.brand_intelligence._official_sites", return_value=(["https://acme.com/"], "Public reference")), patch(
                "fishstop_engine.brand_intelligence._official_sender_evidence", return_value={"source": "official_site_mail_contact", "domain": "acme.it", "reference": "https://acme.com/", "observed_at": time.time()}), patch(
                "fishstop_engine.brand_intelligence.dns_observations", return_value={}), patch(
                "fishstop_engine.brand_intelligence.rdap_observations", return_value={}):
            reference = assess_brand_coherence(report, entities)
        self.assertTrue(reference[0]["contacts"][0]["matches_official"])
        self.assertEqual("unverified", reference[0]["sender_authentication"])
        self.assertEqual([], reference[0]["documented_action_relations"])
        result = assess_impersonation(report, entities, {"claimed_role": "representative"}, reference)
        self.assertEqual("insufficient_data", result["status"])

    def test_outlook_notice_is_not_an_action_but_other_aka_links_are(self):
        text = ("Non ricevi spesso messaggi di posta elettronica da user@acme.it. "
                "Scopri perché è importante<https://aka.ms/LearnAboutSenderIdentification> "
                "Ciao, inviami i certificati. https://aka.ms/other")
        links = extract_links(text, "")
        self.assertFalse(links[0]["actionable"])
        self.assertTrue(links[1]["actionable"])
        body = compact_ai_body(text)
        self.assertNotIn("Scopri perché", body)
        self.assertIn("Ciao, inviami i certificati.", body)
        self.assertIn("https://aka.ms/other", body)

    def test_notice_lookalike_and_query_are_still_actions(self):
        for url in ["https://aka.ms.attacker.com/LearnAboutSenderIdentification", "https://aka.ms/LearnAboutSenderIdentification?redirect=evil"]:
            self.assertTrue(extract_links(url, "")[0]["actionable"])

    def test_styled_html_notice_never_becomes_cta(self):
        link = extract_links("", '<a role="button" href="https://aka.ms/LearnAboutSenderIdentification">Learn why</a>')[0]
        self.assertFalse(link["actionable"])
        self.assertFalse(link["html_call_to_action"])
