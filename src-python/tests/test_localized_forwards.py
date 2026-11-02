"""Forwarded messages written by localized mail clients must reach the AI.

Regression: a Gmail forward in Italian (``---------- Messaggio inoltrato
---------``) was read as an Outlook reply, so ``body_ai`` kept only the
forwarder's note and the forwarded phishing message was discarded.
"""

import unittest
from email.message import EmailMessage

from fishstop_engine.analyzer.body_context import extract_forwarded_identity, select_body_for_ai
from fishstop_engine.analyzer.conversation import inspect_conversation_bytes

PAYLOAD = (
    "Gentile cliente, il suo conto è stato bloccato.\n"
    "Acceda subito per sbloccarlo: https://banca-sicura-verifica.com/login\n"
)
SENDER = "Banca Sicura <alert@banca-sicura-verifica.com>"

# (case name, forwarder note, separator, header lines as (label, value))
CASES = [
    ("gmail_it", "Ti inoltro questa email, puoi dare un'occhiata?",
     "---------- Messaggio inoltrato ---------",
     [("Da", SENDER), ("Date", "lun 2 nov 2026 alle ore 10:12"),
      ("Subject", "Account bloccato"), ("To", "<mario@example.com>")]),
    ("gmail_it_labels", "Ti inoltro questa email.",
     "---------- Messaggio inoltrato ---------",
     [("Da", SENDER), ("Data", "lun 2 nov 2026"), ("Oggetto", "Account bloccato"), ("A", "mario@example.com")]),
    ("apple_it", "Guarda questa.",
     "Inizio messaggio inoltrato:",
     [("Da", SENDER), ("Oggetto", "Account bloccato"), ("Data", "2 novembre 2026"), ("A", "mario@example.com")]),
    ("gmail_es", "Te reenvío este correo, ¿puedes revisarlo?",
     "---------- Mensaje reenviado ---------",
     [("De", SENDER), ("Date", "lun, 2 nov 2026"), ("Subject", "Cuenta bloqueada"), ("To", "<ana@example.com>")]),
    ("outlook_es", "Te reenvío este correo.",
     "-------- Mensaje reenviado --------",
     [("De", SENDER), ("Fecha", "2 nov 2026"), ("Asunto", "Cuenta bloqueada"), ("Para", "ana@example.com")]),
    ("apple_es", "Mira esto.",
     "Inicio del mensaje reenviado:",
     [("De", SENDER), ("Asunto", "Cuenta bloqueada"), ("Fecha", "2 de noviembre de 2026"), ("Para", "ana@example.com")]),
    ("gmail_pt", "Encaminho este e-mail, pode verificar?",
     "---------- Mensagem encaminhada ---------",
     [("De", SENDER), ("Date", "seg., 2 de nov. de 2026"), ("Subject", "Conta bloqueada"), ("To", "<joao@example.com>")]),
    ("pt_pt_labels", "Reencaminho este e-mail.",
     "---------- Mensagem reencaminhada ---------",
     [("De", SENDER), ("Data", "2 nov 2026"), ("Assunto", "Conta bloqueada"), ("Para", "joao@example.com")]),
    ("apple_pt", "Veja isto.",
     "Início da mensagem encaminhada:",
     [("De", SENDER), ("Assunto", "Conta bloqueada"), ("Data", "2 de novembro de 2026"), ("Para", "joao@example.com")]),
    ("gmail_fr", "Je te transfère ce mail, tu peux regarder ?",
     "---------- Message transféré ---------",
     [("De", SENDER), ("Date", "lun. 2 nov. 2026"), ("Subject", "Compte bloqué"), ("To", "<luc@example.com>")]),
    ("fr_labels", "Je te transfère ce mail.",
     "-------- Message transféré --------",
     [("De", SENDER), ("Date", "2 nov 2026"), ("Objet", "Compte bloqué"), ("À", "luc@example.com")]),
    ("apple_fr", "Regarde ça.",
     "Début du message réexpédié :",
     [("De", SENDER), ("Objet", "Compte bloqué"), ("Date", "2 novembre 2026"), ("À", "luc@example.com")]),
    ("gmail_de", "Ich leite dir diese E-Mail weiter, kannst du sie prüfen?",
     "---------- Weitergeleitete Nachricht ---------",
     [("Von", SENDER), ("Date", "Mo., 2. Nov. 2026"), ("Subject", "Konto gesperrt"), ("To", "<jan@example.com>")]),
    ("thunderbird_de", "Bitte prüfen.",
     "-------- Weitergeleitete Nachricht --------",
     [("Betreff", "Konto gesperrt"), ("Datum", "Mon, 2 Nov 2026"), ("Von", SENDER), ("An", "jan@example.com")]),
    ("apple_de", "Schau mal.",
     "Anfang der weitergeleiteten Nachricht:",
     [("Von", SENDER), ("Betreff", "Konto gesperrt"), ("Datum", "2. November 2026"), ("An", "jan@example.com")]),
    ("gmail_nl", "Ik stuur je deze e-mail door, kun je kijken?",
     "---------- Doorgestuurd bericht ---------",
     [("Van", SENDER), ("Date", "ma 2 nov. 2026"), ("Subject", "Account geblokkeerd"), ("To", "<piet@example.com>")]),
    ("nl_labels", "Ik stuur je deze e-mail door.",
     "-------- Doorgestuurd bericht --------",
     [("Van", SENDER), ("Datum", "2 nov 2026"), ("Onderwerp", "Account geblokkeerd"), ("Aan", "piet@example.com")]),
    ("apple_nl", "Kijk hier eens naar.",
     "Begin doorgestuurd bericht:",
     [("Van", SENDER), ("Onderwerp", "Account geblokkeerd"), ("Datum", "2 november 2026"), ("Aan", "piet@example.com")]),
    ("gmail_en", "Forwarding this, can you take a look?",
     "---------- Forwarded message ---------",
     [("From", SENDER), ("Date", "Mon, Nov 2, 2026"), ("Subject", "Account locked"), ("To", "<bob@example.com>")]),
]


def _body(note: str, separator: str, headers) -> str:
    header_block = "\n".join(f"{label}: {value}" for label, value in headers)
    return f"{note}\n\n{separator}\n{header_block}\n\n{PAYLOAD}"


class LocalizedForwardSelectionTests(unittest.TestCase):
    def test_forwarded_payload_reaches_the_ai(self):
        for name, note, separator, headers in CASES:
            with self.subTest(name):
                result = select_body_for_ai(_body(note, separator, headers))
                self.assertEqual("forwarded", result["body_context"])
                self.assertIn("il suo conto è stato bloccato", result["body_ai"])
                self.assertIn("https://banca-sicura-verifica.com/login", result["body_ai"])
                # Neither the forwarder's note nor the embedded header block is
                # sent to the model as message content.
                self.assertNotIn(note, result["body_ai"])
                self.assertNotIn("banca-sicura-verifica.com>", result["body_ai"])
                self.assertEqual(0, result["body_ai"].count(separator.strip(" -:")))

    def test_embedded_sender_is_extracted(self):
        for name, note, separator, headers in CASES:
            with self.subTest(name):
                identity = extract_forwarded_identity(_body(note, separator, headers))
                self.assertEqual("alert@banca-sicura-verifica.com", identity.get("address"))
                self.assertEqual("banca-sicura-verifica.com", identity.get("domain"))
                self.assertEqual("embedded_forward", identity.get("authentication_scope"))

    def test_conversation_scanner_finds_the_forwarded_segment(self):
        for name, note, separator, headers in CASES:
            with self.subTest(name):
                message = EmailMessage()
                message["From"] = "Collega <collega@example.com>"
                message["To"] = "it@example.com"
                message["Subject"] = "Fwd: controllo"
                message.set_content(_body(note, separator, headers))
                report = inspect_conversation_bytes(bytes(message))
                forwarded = [s for s in report["segments"] if s.get("kind") == "forwarded"]
                self.assertEqual(1, len(forwarded), report["segments"])
                self.assertEqual("banca-sicura-verifica.com", forwarded[0]["domain"])
                self.assertIn("conto è stato bloccato", forwarded[0]["text"])


class ReplySelectionIsUnchangedTests(unittest.TestCase):
    def test_original_message_separator_still_keeps_the_new_reply(self):
        body = (
            "Please change the IBAN for the next payment to IT60X0542811101000000123456.\n\n"
            "-----Original Message-----\n"
            "From: Supplier <billing@supplier.example>\n"
            "Sent: Monday, November 2, 2026 10:00\n"
            "To: Accounts <ap@example.com>\n"
            "Subject: Invoice 42\n\n"
            "Old invoice text.\n"
        )
        result = select_body_for_ai(body)
        self.assertEqual("reply", result["body_context"])
        self.assertIn("change the IBAN", result["body_ai"])
        self.assertNotIn("Old invoice text", result["body_ai"])

    def test_localized_outlook_reply_header_keeps_the_new_reply(self):
        body = (
            "Bitte die neue Bankverbindung verwenden.\n\n"
            "Von: Lieferant <billing@supplier.example>\n"
            "Gesendet: Montag, 2. November 2026 10:00\n"
            "An: Buchhaltung <ap@example.com>\n"
            "Betreff: Rechnung 42\n\n"
            "Alter Rechnungstext.\n"
        )
        result = select_body_for_ai(body)
        self.assertEqual("reply", result["body_context"])
        self.assertIn("neue Bankverbindung", result["body_ai"])
        self.assertNotIn("Alter Rechnungstext", result["body_ai"])

    def test_plain_message_mentioning_a_forward_is_not_split(self):
        body = "Il messaggio inoltrato ieri conteneva un errore, ecco la versione corretta.\nGrazie"
        self.assertEqual("normal", select_body_for_ai(body)["body_context"])
        self.assertEqual({}, extract_forwarded_identity(body))


if __name__ == "__main__":
    unittest.main()
