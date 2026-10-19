import json
import os
import time
import unittest
from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver

from fishstop_engine.dns_lookup import resolve_records
from fishstop_engine.domain_identity import verify_message_domain
from fishstop_engine.analyzer.link_extractor import extract_links
from fishstop_engine.analyzer import llm_context_analyzer as llm
from fishstop_engine.identity_store import resolve_partner


class IdentityContextTests(unittest.TestCase):
    def test_absent_signature_is_not_a_failed_spf_check(self):
        raw = b'From: Person <person@example.com>\r\nReceived-SPF: pass\r\n\r\nHello'
        with patch('fishstop_engine.domain_identity.resolve_records') as lookup:
            result = verify_message_domain(raw, {'from_': 'Person <person@example.com>'})
        self.assertEqual('signature_absent', result['reason'])
        self.assertFalse(result['spf_recalculated'])
        self.assertEqual('unverified', result['status'])
        lookup.assert_not_called()

    def test_dns_fallback_accepts_only_the_answered_name(self):
        payload = {'Status': 0, 'Answer': [
            {'name': 'example.com.', 'type': 16, 'data': 'v=spf1 include:_spf.example.com -all'},
            {'name': 'example.com.', 'type': 16, 'data': 'v=DMARC1; p=none; rua=mailto:reports@example.com'},
            {'name': 'attacker.com.', 'type': 16, 'data': '"v=spf1 +all"'}]}
        session = MagicMock()
        session.__enter__.return_value = session
        response = session.get.return_value.__enter__.return_value
        response.raw.read.return_value = json.dumps(payload).encode()
        with patch('dns.resolver.resolve', side_effect=dns.exception.Timeout), \
                patch('fishstop_engine.dns_lookup.requests.Session', return_value=session), \
                patch.dict(os.environ, {'FISHSTOP_DISABLED_PROVIDERS': ''}):
            records = resolve_records('example.com', 'TXT')
        self.assertEqual([b'v=spf1 include:_spf.example.com -all', b'v=DMARC1; p=none; rua=mailto:reports@example.com'],
                         [b''.join(item.strings) for item in records])
        self.assertFalse(session.get.call_args.kwargs['allow_redirects'])

    def test_private_names_local_only_and_nxdomain_do_not_use_https(self):
        for name, disabled, error in [('mail.internal', '', dns.exception.Timeout),
                                      ('example.com', 'local_only', dns.exception.Timeout),
                                      ('example.com', '', dns.resolver.NXDOMAIN)]:
            with self.subTest(name=name, disabled=disabled), \
                    patch('dns.resolver.resolve', side_effect=error), \
                    patch('fishstop_engine.dns_lookup.requests.Session') as session, \
                    patch.dict(os.environ, {'FISHSTOP_DISABLED_PROVIDERS': disabled}):
                with self.assertRaises(dns.exception.DNSException):
                    resolve_records(name, 'TXT')
                session.assert_not_called()

    def test_inline_image_copy_is_not_promoted_to_an_action(self):
        url = 'https://images.example.com/logo.png'
        links = extract_links('[' + url + ']', '<div class="gmail_signature"><img src="' + url + '"></div>')
        self.assertEqual(1, len(links))
        self.assertFalse(links[0]['actionable'])
        # A real button using the very same image remains a request.
        links = extract_links(url, '<a href="' + url + '"><img src="' + url + '"></a>')
        self.assertTrue(links[0]['actionable'])

    def test_pdf_instructions_cannot_select_an_unrelated_body_contact(self):
        soc = {'body_for_ai': 'A guide is attached. The notification comes from notices@example.com.',
               'links': [{'url': 'mailto:notices@example.com', 'display_text': 'notices@example.com', 'scheme': 'mailto'}],
               'attachments': [{'filename': 'guide.pdf', 'pdf_security': {'text_excerpt': 'Download the application from its store.'}}]}
        self.assertEqual('', llm._explicit_link_action_evidence(soc))

    def test_signature_context_does_not_enter_action_input_or_quoted_history(self):
        selected = 'Your requested guide is attached. Thanks.'
        soc = {'body_for_ai': selected, 'body_clean': selected + '\n--\nPerson\nArbor Ltd.\nFrom: Other Company\nOld message'}
        identity = llm._identity_body_text(soc)
        self.assertIn('Arbor Ltd.', identity)
        self.assertNotIn('Other Company', identity)
        self.assertEqual(selected, llm._body_context_for_llm(soc))
        with patch('fishstop_engine.identity_store.known_identity_names', return_value=['Arbor']):
            self.assertEqual(('Arbor', 'representative'), llm._visible_identity_fallback(soc))

    def test_unavailable_authentication_alone_cannot_veto_grounded_benign_content(self):
        soc = {'body_for_ai': 'Read the guide online.', 'from_': 'Person <person@example.com>',
               'links': [{'url': 'https://documents.example.com/guide', 'host': 'documents.example.com'}],
               'domain_authentication': {'status': 'unverified', 'reason': 'signature_absent'},
               'identity_analysis': {'coherence': [{'contacts': [{'source': 'From', 'matches_official': True}],
                   'evidence': [{'source': 'maintained_catalog', 'expires_at': time.time() + 300}]}]}}
        raw = {'verdict': 'benign', 'explanation': 'The message shares an ordinary guide.',
               'action': 'visit_link', 'channel': 'link', 'evidence': 'Read the guide online.'}
        self.assertEqual('legitimate', llm.apply_email_risk_policy(soc, raw)['final_verdict'])
        reference = soc.pop('identity_analysis')
        self.assertEqual('review', llm.apply_email_risk_policy(soc, raw)['final_verdict'])
        soc['identity_analysis'] = reference
        soc['effective_auth_results'] = {'SPF': {'status': 'fail'}}
        self.assertEqual('review', llm.apply_email_risk_policy(soc, raw)['final_verdict'])

    def test_catalog_record_expiry_is_enforced_independently(self):
        bundle = {'verified_at': 1, 'expires_at': 1000, 'records': [
            {'brand': 'Arbor', 'verified_at': 2, 'expires_at': 30, 'relations': []}]}
        with patch('fishstop_engine.identity_store.local_records', return_value=[]), \
                patch('pathlib.Path.read_text', return_value=json.dumps(bundle)), \
                patch('fishstop_engine.identity_store.time.time', return_value=20):
            self.assertEqual(2, resolve_partner('Arbor')['verified_at'])
        with patch('fishstop_engine.identity_store.local_records', return_value=[]), \
                patch('pathlib.Path.read_text', return_value=json.dumps(bundle)), \
                patch('fishstop_engine.identity_store.time.time', return_value=31):
            self.assertIsNone(resolve_partner('Arbor'))

    def test_lookup_failure_does_not_promote_a_sender_relationship(self):
        from fishstop_engine.brand_intelligence import assess_brand_coherence
        report = {'from_': 'Arbor <notice@arbor.it>', 'domain_authentication': {'status': 'unverified'}}
        entities = [{'name': 'Arbor', 'verified_claim': True, 'entity_types': ['ORG'],
                     'occurrences': [{'source': 'sender', 'evidence': 'Arbor'}]}]
        with patch('fishstop_engine.brand_intelligence.resolve_partner', return_value=None), \
                patch('fishstop_engine.brand_intelligence._official_sites', return_value=(['https://arbor.com/'], 'Public reference')), \
                patch('fishstop_engine.brand_intelligence._official_sender_evidence', return_value={
                    'status': 'unavailable', 'reason': 'http_error', 'http_status': 403}), \
                patch('fishstop_engine.brand_intelligence.dns_observations', return_value={}), \
                patch('fishstop_engine.brand_intelligence.rdap_observations', return_value={}):
            reference = assess_brand_coherence(report, entities)[0]
        self.assertEqual([], reference['associated_domains'])
        self.assertFalse(reference['contacts'][0]['matches_official'])
        self.assertEqual(403, reference['lookup_diagnostics']['http_status'])

    def test_embedded_pdf_links_are_not_the_email_action_channel(self):
        from fishstop_engine.impersonation import assess_impersonation
        report = {'from_': 'Arbor <notice@arbor.com>', 'domain_authentication': {'status': 'unverified'},
                  'links': [{'url': 'https://external.example.net/app', 'host': 'external.example.net', 'actionable': True, 'role': 'body_action'}]}
        reference = [{'brand': 'Arbor', 'official_domains': ['arbor.com'], 'resolution_source': 'wikidata',
                      'contacts': [{'source': 'From', 'matches_official': True}]}]
        entities = [{'name': 'Arbor', 'verified_claim': True}]
        semantic = {'claimed_role': 'representative', 'requested_action': 'change_account_settings',
                    'action_channel': 'supplied_attachment', 'evidence_phrase': 'Enable camera permission in the guide.'}
        assessment = assess_impersonation(report, entities, semantic, reference)
        self.assertFalse(any(s['family'] == 'action_destination' for s in assessment['signals']))
        semantic['action_channel'] = 'supplied_link'
        assessment = assess_impersonation(report, entities, semantic, reference)
        self.assertTrue(any(s['family'] == 'action_destination' for s in assessment['signals']))


if __name__ == '__main__':
    unittest.main()
