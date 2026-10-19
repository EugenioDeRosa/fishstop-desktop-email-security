import tempfile
import unittest
from pathlib import Path

from fishstop_engine.analyzer.soc_analyzer import EmlSOCAnalyzer
from fishstop_engine.analyzer import llm_context_analyzer as llm


class ReplyRoutingTests(unittest.TestCase):
    def parse(self, sender, reply):
        raw = (f'From: {sender}\r\nReply-To: {reply}\r\n'
               'To: reader@example.net\r\nSubject: Shared document\r\n'
               'Content-Type: text/plain; charset=utf-8\r\n\r\n'
               'A document has been shared with you. Open the document here.').encode()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'share.eml'
            path.write_bytes(raw)
            return EmlSOCAnalyzer().analyze(str(path))

    def sharing_report(self):
        report = self.parse('"Person (via sharing service)" <notice@service.example>', 'Person <person@company.example>')
        report['links'] = [{'url': 'https://service.example/document', 'host': 'service.example',
                            'actionable': True, 'display_text': 'Open the document'}]
        report['domain_authentication'] = {'status': 'verified', 'verified_domains': ['service.example']}
        return report

    def test_cross_domain_reply_is_visible_without_a_high_severity_accusation(self):
        report = self.sharing_report()
        self.assertTrue(report['reply_to_mismatch'])
        flags = [f for f in report['flags'] if f['field'] == 'Reply-To']
        self.assertEqual(['MEDIUM'], [f['level'] for f in flags])
        self.assertIn('difference alone is not evidence of phishing', flags[0]['message'])
        self.assertFalse(llm._deterministic_identity_deception(report, {'requested_action': 'visit_link'}))
        result = llm.apply_email_risk_policy(report, {
            'action': 'visit_link', 'channel': 'link', 'evidence': 'Open the document here.',
            'risk_assessment': 'legitimate', 'risk_rationale': 'An ordinary document-sharing notification.'})
        self.assertEqual('uncertain', result['identity_risk'])
        self.assertEqual('review', result['final_verdict'])
        self.assertNotIn('spoofing_evidence', result['identity_risk'])

    def test_authenticated_service_does_not_authenticate_the_external_reply_person(self):
        report = self.sharing_report()
        report['impersonation'] = {'claimed_identity': 'Sharing Service', 'status': 'consistent', 'signals': []}
        status, reasons = llm._identity_risk(report)
        self.assertEqual('uncertain', status)
        self.assertIn('relationship could not be independently confirmed', ' '.join(reasons))

    def test_domain_or_display_name_cannot_create_a_service_allowlist(self):
        for sender in ['"Person (via Google Drive)" <notice@unrelated.example>',
                       '"Person (via Google Drive)" <drive-shares-dm-noreply@google.com>',
                       '"Person (via Google Drive)" <notice@google.com.attacker.example>']:
            with self.subTest(sender=sender):
                report = self.parse(sender, 'Person <person@company.example>')
                self.assertTrue(report['reply_to_mismatch'])
                self.assertFalse(report['reply_to_mismatch_legitimate'])
                self.assertEqual('uncertain', llm._identity_risk(report)[0])

    def test_malicious_shared_link_and_proven_identity_deception_still_prevail(self):
        report = self.sharing_report()
        report['link_reputation'] = {'https://service.example/document': {'status': 'malicious'}}
        result = llm.apply_email_risk_policy(report, {'action': 'visit_link', 'channel': 'link',
                 'evidence': 'Open the document here.', 'risk_assessment': 'legitimate'})
        self.assertEqual('phishing', result['final_verdict'])
        report['display_name_spoofing'] = 'another@example.net'
        self.assertTrue(llm._deterministic_identity_deception(report, {'requested_action': 'visit_link'}))
        self.assertEqual('spoofing_evidence', llm._identity_risk(report)[0])

    def test_service_authentication_cannot_clear_ai_deceptive_content(self):
        report = self.sharing_report()
        body = 'Your account will be closed unless you disclose your password in the shared document.'
        report['body_for_ai'] = body
        report['body_for_intent'] = body
        result = llm.apply_email_risk_policy(report, {
            'action': 'visit_link', 'channel': 'link', 'evidence': body,
            'risk_assessment': 'phishing', 'risk_evidence': body,
            'risk_rationale': 'The shared document is used to collect a password under an account-closure pretext.'})
        self.assertEqual('phishing', result['final_verdict'])
        self.assertEqual('malicious', result['content_risk'])

    def test_documented_sender_does_not_clear_unverified_external_reply(self):
        import time
        report = self.sharing_report()
        report['identity_analysis'] = {'coherence': [{
            'contacts': [{'source': 'From', 'matches_official': True}],
            'evidence': [{'source': 'maintained_catalog', 'expires_at': time.time() + 3600}]}]}
        result = llm.apply_email_risk_policy(report, {
            'action': 'visit_link', 'channel': 'link', 'evidence': 'Open the document here.',
            'risk_assessment': 'legitimate', 'risk_rationale': 'An ordinary document-sharing notification.'})
        self.assertEqual('review', result['final_verdict'])

    def test_same_domain_routing_keeps_existing_neutral_treatment(self):
        report = self.parse('Notice <notice@company.example>', 'Person <person@company.example>')
        self.assertTrue(report['reply_to_mismatch_legitimate'])
        self.assertFalse(report['reply_to_mismatch'])


if __name__ == '__main__':
    unittest.main()
