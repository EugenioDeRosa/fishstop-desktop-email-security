"""Deterministic reward and payment rules must not fire on ordinary wording.

5. Courier notices: "punto di ritiro" was read both as a benefit ("punto" ~
   Spanish "puntos") and as a redemption verb ("ritiro"), so a legitimate
   parcel notice became "a reward ... must be claimed" and went to review.
6. Security bulletins: a quoted scam text ("paga 500 euro in bitcoin") was
   taken as a payment request although the model judged the bulletin benign.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fishstop_engine.analyzer import llm_context_analyzer as llm

AUTH_PASS = {name: {"status": "pass"} for name in ("SPF", "DKIM", "DMARC")}


def _soc(body, label="Apri", subject="", sender="Mittente <info@example.com>", links=True):
    return {
        "from_": sender, "subject": subject, "body_for_ai": body,
        "links": [{"url": "https://www.example.com/a", "host": "www.example.com", "display_text": label,
                   "role": "body_action", "actionable": True}] if links else [],
        "attachments": [], "effective_auth_results": AUTH_PASS,
    }


BENIGN = {"verdict": "benign", "quote": "", "explanation": "An ordinary notice.",
          "action": "info", "channel": "none", "evidence": "", "signals": [], "ambiguity": "none"}


class CourierNoticeIsNotARewardTests(unittest.TestCase):
    NOTICES = [
        ("it", "Il tuo pacco è disponibile per il ritiro",
         "Gentile cliente, il tuo pacco è in deposito presso il punto di ritiro di Via Roma 12. "
         "Puoi ritirarlo entro 7 giorni presentando un documento. "
         "Per scegliere un altro punto di ritiro clicca sul link qui sotto.", "Gestisci la consegna"),
        ("it_label", "Pacco in giacenza",
         "Il pacco è in giacenza presso il punto di ritiro indicato.", "Ritira il pacco"),
        ("pt", "Encomenda disponível",
         "Sua encomenda está no ponto de retirada. Retire em até 5 dias úteis.", "Ver detalhes"),
        ("es", "Paquete disponible",
         "Tu paquete está en el punto de recogida. Recógelo y obtén tu comprobante en tienda.", "Ver envío"),
        ("en", "Your parcel is ready",
         "Your parcel is waiting at the pick-up point. Collect your parcel within 5 days.", "Track parcel"),
    ]

    def test_no_reward_claim_is_grounded(self):
        for name, subject, body, label in self.NOTICES:
            with self.subTest(name):
                self.assertEqual({}, llm._grounded_reward_claim(_soc(body, label, subject)))

    def test_courier_notice_is_not_sent_to_review_for_a_reward(self):
        for name, subject, body, label in self.NOTICES:
            with self.subTest(name):
                analysis = llm.apply_email_risk_policy(_soc(body, label, subject), dict(BENIGN))
                self.assertNotEqual("claim_reward", analysis["requested_action"])
                self.assertFalse(analysis["semantic_extraction"]["asks_to_claim_reward"])
                self.assertEqual("legitimate", analysis["final_verdict"], analysis.get("explanation"))


class RewardLuresStillDetectedTests(unittest.TestCase):
    LURES = [
        ("pt_points", "Você possui 92.990 pontos disponíveis para resgate que expiram HOJE.", "Resgatar Agora"),
        ("en_points", "Redeem your points before they expire.", "Open"),
        ("it_prize", "Hai vinto un buono da 50 euro. Ritira il tuo premio entro oggi.", "Vai"),
        ("en_miles", "Your 5,000 miles are waiting. Claim now.", "Go"),
        ("it_loyalty", "Hai accumulato 1200 punti fedeltà.", "Riscatta ora"),
        ("es_points", "Tienes 3.000 puntos acumulados. Canjea tus puntos hoy.", "Canjear"),
    ]

    def test_reward_claims_remain_grounded(self):
        for name, body, label in self.LURES:
            with self.subTest(name):
                self.assertTrue(llm._grounded_reward_claim(_soc(body, label)).get("evidence"))


BULLETIN = (
    "Ciao a tutti,\n"
    "in questi giorni circolano email che dicono \"ho registrato la tua webcam, paga 500 euro in bitcoin "
    "entro 48 ore o pubblico il video\".\n"
    "Non pagate e non rispondete: si tratta di una truffa. Se ne ricevete una, inoltratela a sicurezza@azienda.it.\n"
    "Il team Sicurezza IT"
)


class ReportedScamTextIsNotAPaymentRequestTests(unittest.TestCase):
    BULLETINS = [
        ("it_quoted", BULLETIN),
        ("it_curly", BULLETIN.replace('"ho', "“ho").replace('video"', "video”")),
        ("it_guillemets", BULLETIN.replace('"ho', "«ho").replace('video"', "video»")),
        ("it_reported", "Attenzione: circolano email che chiedono di pagare 500 euro in bitcoin per non pubblicare un video. "
                        "Non pagate e segnalatele all'IT."),
        ("en_reported", "Beware of emails claiming you must pay $800 in bitcoin to stop a video being published. "
                        "Do not reply; report them to IT."),
        ("en_quoted_multisentence", "Staff have received messages like: \"I recorded you. Pay 0.05 bitcoin to this wallet "
                                    "within 48 hours.\" Delete them and report to the security team."),
        ("es_reported", "Circulan correos que piden transferir 500 euros en bitcoin para no publicar un vídeo. "
                        "No paguéis y avisad a seguridad."),
    ]

    def test_bulletins_contain_no_payment_instruction(self):
        for name, body in self.BULLETINS:
            with self.subTest(name):
                soc = _soc(body, links=False, subject="Avviso truffa", sender="Sicurezza IT <sicurezza@azienda.it>")
                self.assertEqual("", llm._explicit_payment_evidence(soc))
                analysis = llm.apply_email_risk_policy(soc, dict(BENIGN))
                self.assertNotEqual("pay_or_transfer", analysis["requested_action"])
                self.assertEqual("legitimate", analysis["final_verdict"], analysis.get("explanation"))


class RealPaymentDemandsStillDetectedTests(unittest.TestCase):
    DEMANDS = [
        ("sextortion", "I recorded you through your webcam. Pay 500 euro in bitcoin within 48 hours or I publish the video."),
        ("sextortion_it", "Ho registrato la tua webcam. Paga 500 euro in bitcoin entro 48 ore o pubblico il video."),
        ("invoice", "Please pay the attached invoice of 1.250 EUR by bank transfer to IBAN IT60X0542811101000000123456."),
        ("partly_quoted", "As agreed, please transfer 2.000 EUR to the \"new account\" before Friday."),
        ("sender_says", "Il fornitore ha confermato. Per favore effettua il bonifico di 900 euro oggi."),
    ]

    def test_direct_payment_instructions_remain(self):
        for name, body in self.DEMANDS:
            with self.subTest(name):
                evidence = llm._explicit_payment_evidence(_soc(body, links=False))
                self.assertTrue(evidence)
                self.assertIn(evidence.split()[0], body)


if __name__ == "__main__":
    unittest.main()
