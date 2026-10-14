import io
import unittest
from unittest.mock import patch

from PIL import Image
import zxingcpp

from fishstop_engine.analyzer.qr_analysis import _inspect, inspect_requested_qr, qr_request, MAX_BYTES
from fishstop_engine.analyzer.llm_context_analyzer import normalize_semantic_extraction, apply_email_risk_policy


def assess(report):
    semantic = normalize_semantic_extraction({"action": "informational", "channel": "none",
        "summary": "The message provides information.", "evidence": "", "confidence": .9}, soc=report)
    return apply_email_risk_policy(report, semantic)


class QrPaymentTests(unittest.TestCase):
    def qr_image(self, value):
        barcode = zxingcpp.create_barcode(value, zxingcpp.BarcodeFormat.QRCode)
        bitmap = zxingcpp.write_barcode_to_image(barcode, scale=5)
        height, width = memoryview(bitmap).shape
        return Image.frombytes("L", (width, height), bytes(bitmap))

    def test_local_image_and_pdf_qr_decode_without_network(self):
        image = self.qr_image("https://example.com/invite")
        for format_, mime in [("PNG", "image/png"), ("PDF", "application/pdf")]:
            with self.subTest(format=format_):
                stream = io.BytesIO()
                image.convert("RGB").save(stream, format=format_)
                result = _inspect(stream.getvalue(), mime)
                self.assertEqual(["https://example.com/invite"], result["urls"])
                self.assertTrue(result["analysis_complete"])

    def test_non_web_qr_is_never_an_action_destination(self):
        stream = io.BytesIO(); self.qr_image("powershell evil-command").save(stream, format="PNG")
        self.assertEqual([], _inspect(stream.getvalue(), "image/png")["urls"])

    def test_oversized_input_is_unavailable(self):
        result = inspect_requested_qr([(0, b"x" * (MAX_BYTES + 1), "image/png")])
        self.assertFalse(result[0]["analysis_complete"])

    def test_qr_invitation_with_work_email_is_review_even_when_model_misses_action(self):
        report = {"body_clean": "Ti prego di scansionare il codice di invito allegato e usare l'email lavorativa per confermare le tue informazioni.",
                  "attachments": [{"filename": "invite.pdf", "actionable": True}], "links": []}
        result = assess(report)
        self.assertEqual("provide_information", result["requested_action"])
        self.assertEqual("review", result["final_verdict"])
        self.assertIn("QR", result["content_summary"])

    def test_decoded_qr_is_kept_as_supplied_action(self):
        report = {"from_": "Company <person@company.test>", "body_clean": "Please scan the QR code and confirm your information using your work email.",
                  "links": [{"url": "https://example.com/invite", "host": "example.com", "source": "attachment_qr", "role": "body_action"}]}
        result = assess(report)
        self.assertEqual("supplied_link", result["action_channel"])
        self.assertEqual("review", result["final_verdict"])

    def test_malicious_qr_reputation_escalates(self):
        report = {"body_clean": "Please scan the QR code.", "links": [{"url": "https://example.com/invite", "host": "example.com", "source": "attachment_qr"}],
                  "link_reputation": {"https://example.com/invite": {"status": "malicious"}}}
        self.assertEqual("phishing", assess(report)["final_verdict"])

    def test_isolated_worker_decodes_a_qr(self):
        stream = io.BytesIO(); self.qr_image("https://example.com/invite").save(stream, format="PNG")
        result = inspect_requested_qr([(0, stream.getvalue(), "image/png")])
        self.assertEqual(["https://example.com/invite"], result[0]["urls"])

    def test_iban_and_pending_payment_proof_are_an_implicit_payment_request(self):
        body = "Aquí está la cuenta bancaria: IBAN PT50 0035 0701 0000 8660 9300 8. Enviaré la información solicitada tan pronto como recibamos el comprobante de pago."
        result = assess({"body_clean": body, "body_context": "conversation_selection", "selected_target_body": body})
        self.assertEqual("pay_or_transfer", result["requested_action"])
        self.assertEqual("phishing", result["final_verdict"])
        self.assertNotIn("changed", result["content_summary"])

    def test_iban_alone_and_received_receipt_are_not_payment_requests(self):
        for body in ["Our IBAN is IT60X0542811101000000123456.",
                     "Aquí está la cuenta bancaria IBAN PT50 0035 0701 0000 8660 9300 8. Hemos recibido el comprobante de pago."]:
            with self.subTest(body=body):
                self.assertEqual("legitimate", assess({"body_clean": body})["final_verdict"])

    def test_selected_target_does_not_inherit_qr_or_implicit_payment_from_context(self):
        report = {"body_context": "conversation_selection", "selected_target_body": "Thank you for the update.",
                  "body_clean": "Thank you for the update.",
                  "body_for_intent": "Thank you for the update. Please scan the QR code and use a work email. IBAN PT50 0035 0701 0000 8660 9300 8. Send proof of payment."}
        self.assertEqual("informational", assess(report)["requested_action"])

    def test_selected_acknowledgement_does_not_inherit_explicit_transfer_from_context(self):
        report = {"body_context": "conversation_selection", "selected_target_body": "Thank you for the update.",
                  "body_for_intent": "Thank you for the update. Please transfer EUR 500 to our new IBAN IT60X0542811101000000123456."}
        self.assertEqual("informational", assess(report)["requested_action"])


if __name__ == "__main__":
    unittest.main()
