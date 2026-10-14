import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fishstop_engine.analyzer import llm_context_analyzer as llm


class CredentialReplyGroundingTests(unittest.TestCase):
    def assess(self, body, action='provide_credentials', evidence=''):
        soc = {'subject': 'Documento condiviso', 'body_for_ai': body,
               'links': [], 'attachments': []}
        raw = {'summary': 'The email discusses document access.', 'action': action,
               'channel': 'reply' if action == 'provide_credentials' else 'none',
               'evidence': evidence, 'signals': [], 'ambiguity': 'none',
               'risk_assessment': 'benign', 'risk_evidence': ''}
        return llm.apply_email_risk_policy(soc, llm.normalize_semantic_extraction(raw, soc=soc))

    def test_original_wrapped_eml_with_recorded_model_response(self):
        body = (
            'Abbiamo caricato la versione aggiornata dell’ordine su SharePoint.\n\n'
            'Quando ricevete il codice monouso di verifica, rispondete a questa email\n'
            'riportando il codice: il nostro ufficio lo utilizzerà per completare\n'
            'l’associazione del vostro account al documento.\n\n'
            'Non serve inviarci la password. Il codice scade dopo pochi minuti.'
        )
        result = self.assess(body, evidence='riportando il codice')
        self.assertEqual(result['final_verdict'], 'phishing')
        self.assertEqual(result['requested_action'], 'provide_credentials')
        self.assertEqual(result['action_channel'], 'email_reply')

    def test_indirect_plural_and_english_requests(self):
        bodies = [
            'Rispondete a questa email riportando il codice monouso di verifica.',
            'Per aprire il documento, inoltraci il codice di accesso ricevuto sul telefono.',
            'Please reply to this message with the one-time code from your authenticator.',
            'Send us the verification code. We do not need your password.',
            'Inviateci il codice monouso per abilitare i permessi Google Drive.',
            'Rispondi a questa email\nriportando il codice monouso ricevuto durante il login.',
        ]
        for body in bodies:
            with self.subTest(body=body):
                result = self.assess(body, evidence=body)
                self.assertEqual(result['final_verdict'], 'phishing')

    def test_does_not_promote_denied_quoted_or_nonsecret_requests(self):
        bodies = [
            'Il tuo codice di accesso è 461197. Non comunicarlo a nessuno.',
            'Non rispondete a questa email riportando il codice monouso.',
            'Never reply to this email with the verification code.',
            'Non inviare la password o il codice di verifica al nostro operatore.',
            'Esempio di truffa: "rispondete riportando il codice monouso". Non eseguire questa richiesta.',
            'La richiesta sotto è annullata.\n--- Messaggio originale ---\nRispondi con il codice monouso.',
            'Rispondete a questa email riportando il numero di ordine.',
            'Inserisci il codice nell’app che hai aperto autonomamente. Non inviarlo in risposta.',
        ]
        for body in bodies:
            with self.subTest(body=body):
                result = self.assess(body, evidence=body)
                self.assertEqual(result['final_verdict'], 'legitimate')
                self.assertFalse(result['semantic_extraction']['asks_for_credentials'])

    def test_request_is_recovered_even_when_model_calls_it_informational(self):
        result = self.assess('Rispondete a questa email riportando il codice monouso.', action='info')
        self.assertEqual(result['requested_action'], 'provide_credentials')
        self.assertEqual(result['final_verdict'], 'phishing')


if __name__ == '__main__':
    unittest.main()
