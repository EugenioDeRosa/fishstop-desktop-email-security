import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from fishstop_engine.analyzer import llm_context_analyzer as llm

class IntentGroundingRegressionTests(unittest.TestCase):
    def soc(self,body,links=None):return {'body_for_ai':body,'links':links or [],'attachments':[]}
    def test_payment_after_italian_obligation(self):
        for body in ['Per continuare devi pagare 12 EUR di commissione.', 'Per procedere devi prima pagare 14 EUR.', 'Ecco cosa devi fare - trasferire 90 EUR sul conto indicato.', 'Effettua il bonifico oggi.']:
            with self.subTest(body=body):self.assertTrue(llm._explicit_payment_request(self.soc(body)))
    def test_incoming_and_negated_payments_are_not_instructions(self):
        for body in ['Abbiamo ricevuto 12 EUR di pagamento.', 'Riceverai un rimborso di 90 EUR.', 'Non devi pagare 12 EUR.', 'Il cliente dichiara di pagare 12 EUR ogni mese.']:
            with self.subTest(body=body):self.assertFalse(llm._explicit_payment_request(self.soc(body)))
    def test_secrets_requested_in_reply(self):
        for body in ['Rispondi a questa email con il codice di sei cifre.', 'Rispondi con tutte le 12 parole della frase di recupero.', 'Comunicami ID e password della sessione di assistenza.', 'Per verificare devi inserire il codice monouso nel modulo.']:
            with self.subTest(body=body):
                soc=self.soc(body);self.assertTrue(llm._explicit_credential_submission(soc))
                result=llm.apply_email_risk_policy(soc,{'action':'reply','channel':'reply','evidence':body,'risk_assessment':'phishing','risk_evidence':body})
                self.assertEqual('provide_credentials',result['requested_action']);self.assertEqual('phishing',result['final_verdict'])
    def test_delivery_denial_and_order_references_do_not_disclose_secrets(self):
        for body in ['Il tuo codice di accesso è 527419. Inserisci il codice nella schermata aperta autonomamente.', 'Non rispondi con la password.', 'Rispondi con il codice ordine ORD-912.', 'Non eseguire questa richiesta. Rispondi con il codice di sei cifre.']:
            with self.subTest(body=body):self.assertFalse(llm._explicit_credential_submission(self.soc(body)))
    def test_link_caption_and_truncated_actual_url_are_grounded(self):
        url='https://documents.example.invalid/'+'abcdefgh'*15
        soc=self.soc('Verifica il tuo account.',[{'url':url,'display_text':'Verifica\r\n account','actionable':True}])
        self.assertEqual('Verifica account',llm._validated_evidence(soc,'Verifica account<'+url[:90]+'>','verify_account'))
        self.assertEqual('',llm._validated_evidence(soc,'Verifica account<https://other.example.invalid/abcdefgh>','verify_account'))
        self.assertEqual('',llm._validated_evidence(soc,'Invia la password<'+url+'>','provide_credentials'))
    def test_document_link_is_not_a_missing_attachment(self):
        body='Apri il documento qui'
        soc=self.soc(body,[{'url':'https://documents.example.invalid/view','display_text':body,'actionable':True}])
        result=llm.apply_email_risk_policy(soc,{'action':'open_attachment','channel':'reply','evidence':body})
        self.assertEqual('visit_link',result['requested_action'])
        self.assertEqual('supplied_link',result['action_channel'])
    def test_editorial_account_title_cannot_override_ai_with_generic_button(self):
        body = "Industry news: Alex joins as Strategic Account Director. Read more."
        soc = self.soc(body, [{'url': 'https://news.example/articles', 'display_text': 'View in browser', 'actionable': True}])
        for action in ('info', 'none', 'provide_information'):
            with self.subTest(action=action):
                result = llm.apply_email_risk_policy(soc, {
                    'action': action, 'channel': 'none',
                    'summary': 'The newsletter presents appointments and industry news.',
                    'risk_assessment': 'legitimate',
                    'risk_rationale': 'Editorial content without a deceptive request.'})
                self.assertNotEqual('verify_account', result['requested_action'])
                self.assertFalse(result['semantic_extraction']['asks_to_verify_account'])
                self.assertNotIn('claimed account or security issue', result['content_summary'])

    def test_grounded_ai_account_request_survives_without_automatic_promotion(self):
        body = 'Verify your account using the button below.'
        soc = self.soc(body, [{'url': 'https://service.example/check', 'display_text': 'Verify your account', 'actionable': True}])
        result = llm.apply_email_risk_policy(soc, {
            'action': 'verify_account', 'channel': 'link', 'evidence': body,
            'risk_assessment': 'phishing', 'risk_evidence': body,
            'risk_rationale': 'The message uses account verification as a deceptive lure.'})
        self.assertEqual('verify_account', result['requested_action'])
        self.assertTrue(result['semantic_extraction']['asks_to_verify_account'])

    def test_changed_account_requires_a_payment_request(self):
        self.assertTrue(llm._grounded_payment_diversion(self.soc('Usa il nuovo conto. Effettua il bonifico oggi.')))
        self.assertFalse(llm._grounded_payment_diversion(self.soc('Abbiamo registrato il nuovo conto. Nessun pagamento richiesto.')))

if __name__=='__main__':unittest.main()
