import tempfile
import unittest
from pathlib import Path

from fishstop_engine.analyzer.soc_analyzer import EmlSOCAnalyzer
from fishstop_engine.analyzer import llm_context_analyzer as llm
from fishstop_engine.analyzer.reply_routing import assess_reply_routing, refresh_reply_routing


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

    def test_unrecognized_cross_domain_reply_requires_review_with_benign_ai(self):
        # A different reply domain alone is a routing anomaly (helpdesk/CRM
        # services use one), not a phishing conviction.
        report = self.sharing_report()
        self.assertTrue(report['reply_to_mismatch'])
        flags = [f for f in report['flags'] if f['field'] == 'Reply-To']
        self.assertEqual(['MEDIUM'], [f['level'] for f in flags])
        self.assertIn('different domain than the sender', flags[0]['message'])
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
        report['from_'] = 'drive-shares-dm-noreply@google.com'
        report['links'] = [{'url': 'https://drive.google.com/file/d/123/view'}]
        report['domain_authentication'] = {'status': 'verified', 'verified_domains': ['google.com']}
        self.assertEqual('INFO', assess_reply_routing(report)['level'])
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

    def test_same_domain_different_mailbox_is_reported_without_affecting_the_verdict(self):
        report = self.parse('Notice <notice@company.example>', 'Person <person@company.example>')
        self.assertTrue(report['reply_to_mismatch_legitimate'])
        self.assertFalse(report['reply_to_mismatch'])
        self.assertEqual('LOW', assess_reply_routing(report)['level'])
        self.assertEqual('clean', llm._technical_risk(report)[0])

    def test_service_exception_requires_real_mailbox_and_official_destinations(self):
        report = self.parse('"Person (via Google Drive)" <drive-shares-dm-noreply@google.com>', 'person@company.example')
        report['links'] = [{'url': 'https://drive.google.com/file/d/123/view', 'actionable': True}]
        self.assertEqual('MEDIUM', refresh_reply_routing(report)['level'])
        report['domain_authentication'] = {'status': 'verified', 'verified_domains': ['google.com']}
        self.assertEqual('INFO', refresh_reply_routing(report)['level'])
        self.assertEqual('clean', llm._technical_risk(report)[0])
        report['link_reputation'] = {report['links'][0]['url']: {'status': 'malicious'}}
        self.assertEqual('malicious', llm._technical_risk(report)[0])
        report['links'][0]['url'] = 'https://drive.google.com.attacker.example/file'
        self.assertEqual('MEDIUM', refresh_reply_routing(report)['level'])

    def test_bulk_claim_alone_cannot_bypass_policy(self):
        report = self.sharing_report()
        report['is_bulk_sender'] = True
        # Authenticated bulk sender with a CRM/helpdesk reply domain.
        self.assertEqual('LOW', assess_reply_routing(report)['level'])
        report['domain_authentication'] = {'status': 'disabled'}
        # Bulk headers are sender-controlled: without authentication they
        # cannot lower the cross-domain reply below review.
        self.assertEqual('MEDIUM', assess_reply_routing(report)['level'])
        report['reply_to'] = 'support@service.example'
        self.assertEqual('LOW', assess_reply_routing(report)['level'])
        report['domain_authentication'] = {'status': 'verified', 'verified_domains': ['service.example']}
        self.assertEqual('INFO', assess_reply_routing(report)['level'])

    def test_corroborated_reply_hijack_patterns_remain_high(self):
        report = self.parse('Billing <billing@company.example>', 'Billing <company.billing.office@gmail.com>')
        self.assertEqual('HIGH', assess_reply_routing(report)['level'])
        self.assertEqual('malicious', llm._technical_risk(report)[0])
        report['domain_authentication'] = {'status': 'verified', 'verified_domains': ['company.example']}
        self.assertEqual('MEDIUM', assess_reply_routing(report)['level'])
        report = self.parse('Accounts <accounts@supplier-company.example>', 'Accounts <accounts@supplier-cornpany.example>')
        self.assertEqual('HIGH', assess_reply_routing(report)['level'])
        report = self.parse('PayPal <service@paypal.com>', 'Support <support@paypal-help-desk.example>')
        self.assertEqual('HIGH', assess_reply_routing(report)['level'])

    def test_sensitive_request_by_reply_to_external_domain_is_phishing(self):
        report = self.parse('Finance <finance@company.example>', 'Finance <finance@payments-office.example>')
        body = 'Please reply with the bank account details for the transfer of 12,000 EUR today.'
        report['body_for_ai'] = body
        report['body_for_intent'] = body
        result = llm.apply_email_risk_policy(report, {
            'action': 'pay', 'channel': 'reply', 'evidence': body, 'signals': ['payment'],
            'risk_assessment': 'suspicious', 'risk_evidence': body,
            'risk_rationale': 'Payment request answered through a different organisation.'})
        self.assertEqual('MEDIUM', report['reply_to_routing']['level'])
        self.assertEqual('phishing', result['final_verdict'])

    def test_additional_reply_recipient_cannot_hide_behind_matching_first_address(self):
        report = self.parse('alice@company.example', 'alice@company.example, thief@external.example')
        self.assertEqual('HIGH', assess_reply_routing(report)['level'])
        report['reply_to'] = 'Alice <alice@company.example>'
        self.assertEqual('NONE', assess_reply_routing(report)['level'])
        report['reply_to'] = None
        self.assertEqual('NONE', assess_reply_routing(report)['level'])

    def test_outer_routing_does_not_apply_to_selected_embedded_message(self):
        report = self.sharing_report()
        report['selected_target_authentication_scope'] = 'embedded_unavailable'
        self.assertEqual('NONE', refresh_reply_routing(report)['level'])
        self.assertFalse(any(flag['field'] == 'Reply-To' for flag in report['flags']))

    def test_sharepoint_notification_and_authentication_failure(self):
        report = self.parse('no-reply@sharepointonline.com', 'person@company.example')
        report['links'] = [{'url': 'https://company.sharepoint.com/sites/team/document'}]
        report['domain_authentication'] = {'status': 'verified', 'verified_domains': ['sharepointonline.com']}
        self.assertEqual('INFO', assess_reply_routing(report)['level'])
        report['domain_authentication'] = {'status': 'failed'}
        self.assertEqual('HIGH', assess_reply_routing(report)['level'])


if __name__ == '__main__':
    unittest.main()
