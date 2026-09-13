import unittest

from fishstop_engine.analyzer.conversation import (
    apply_conversation_selection,
    inspect_conversation_bytes,
    public_conversation_manifest,
)


CONVERSATION_EML = (
    "From: Forwarder <forwarder@example.com>\r\n"
    "To: analyst@example.net\r\n"
    "Subject: Fwd: payment details\r\n"
    "Date: Tue, 12 May 2026 12:59:39 +0200\r\n"
    "Content-Type: text/plain; charset=utf-8\r\n"
    "\r\n"
    "Please inspect this.\r\n"
    "\r\n"
    "---------- Forwarded message ---------\r\n"
    "From: accounts@customer.example\r\n"
    "Date: Tue, 12 May 2026 12:56:00 +0200\r\n"
    "Subject: RE: payment details\r\n"
    "To: forwarder@example.com\r\n"
    "\r\n"
    "This is the message we received.\r\n"
    "\r\n"
    "De: Finance <finance@example.com>\r\n"
    "Enviado el: Tue, 12 May 2026 12:32:00 +0200\r\n"
    "Para: accounts@customer.example\r\n"
    "Asunto: RE: payment details\r\n"
    "\r\n"
    "Use this bank account. IBAN PT50 0000 0000. Send proof of payment.\r\n"
    "\r\n"
    "On Tue, 12 May 2026, accounts@customer.example wrote:\r\n"
    "Please send the account for the transfer.\r\n"
).encode("utf-8")


class ConversationSelectionTests(unittest.TestCase):
    def test_discovers_forwarded_payment_turn_and_recommends_context(self):
        manifest = inspect_conversation_bytes(CONVERSATION_EML)

        self.assertTrue(manifest["requires_selection"])
        self.assertEqual(4, manifest["message_count"])
        self.assertEqual("context", manifest["segments"][0]["recommended_role"])
        self.assertEqual("target", manifest["segments"][2]["recommended_role"])
        self.assertEqual("finance@example.com", manifest["segments"][2]["address"])
        self.assertEqual("context", manifest["segments"][3]["recommended_role"])
        self.assertEqual("unavailable", manifest["segments"][2]["authentication_status"])

    def test_public_manifest_does_not_expose_full_bodies(self):
        manifest = public_conversation_manifest(inspect_conversation_bytes(CONVERSATION_EML))

        self.assertTrue(all("text" not in segment for segment in manifest["segments"]))
        self.assertTrue(all(segment.get("preview") for segment in manifest["segments"]))

    def test_selection_scopes_ai_body_and_links_but_keeps_outer_auth_boundary(self):
        manifest = inspect_conversation_bytes(CONVERSATION_EML)
        report = {
            "body_for_ai": "full conversation",
            "from_": "Forwarder <forwarder@example.com>",
            "to": "analyst@example.net",
            "subject": "Fwd: payment details",
            "auth_results": {"SPF": {"status": "pass", "identity": "example.com"}},
            "effective_auth_results": {"SPF": {"status": "pass", "identity": "example.com"}},
            "received_hops": [{"sender_ip": "203.0.113.8"}],
            "injection_sender_ip": "203.0.113.8",
            "links": [
                {"url": "https://example.com/pay", "host": "example.com", "display_text": ""},
                {"url": "https://old.example/archive", "host": "old.example", "display_text": ""},
            ],
        }
        manifest["segments"][2]["text"] += " https://example.com/pay"

        apply_conversation_selection(report, manifest, {
            "target_ids": ["message-2"],
            "context_ids": ["message-1", "message-3"],
            "prior_context_ids": ["message-3"],
            "later_context_ids": ["message-1"],
        })

        self.assertIn("[TARGET MESSAGE: Finance <finance@example.com>]", report["body_for_ai"])
        self.assertIn("[PRIOR CONTEXT MESSAGE: accounts@customer.example]", report["body_for_ai"])
        self.assertIn("[LATER FOLLOW-UP CONTEXT MESSAGE: accounts@customer.example]", report["body_for_ai"])
        self.assertEqual(["https://example.com/pay"], [link["url"] for link in report["links"]])
        self.assertEqual(1, report["conversation_excluded_link_count"])
        self.assertEqual("embedded_unavailable", report["authentication_scope"])
        self.assertEqual("embedded_unavailable", report["selected_target_authentication_scope"])
        self.assertEqual("Finance <finance@example.com>", report["from_"])
        self.assertEqual({}, report["auth_results"])
        self.assertEqual([], report["received_hops"])
        self.assertIsNone(report["injection_sender_ip"])
        self.assertEqual("pass", report["outer_delivery_evidence"]["auth_results"]["SPF"]["status"])
        self.assertEqual("complete_delivered_file", report["container_analysis_scope"])
        self.assertEqual(["message-3"], report["conversation_analysis"]["selection"]["prior_context_ids"])
        self.assertEqual(["message-1"], report["conversation_analysis"]["selection"]["later_context_ids"])
        self.assertIn("Attachments belong to the complete email", report["conversation_analysis"]["technical_scope_message"])

    def test_single_message_does_not_require_selection(self):
        manifest = inspect_conversation_bytes(
            b"From: sender@example.com\r\nSubject: Hello\r\n\r\nA normal message.\r\n"
        )

        self.assertEqual("single", manifest["status"])
        self.assertFalse(manifest["requires_selection"])
        self.assertEqual("target", manifest["segments"][0]["recommended_role"])

    def test_outer_target_keeps_its_delivery_authentication(self):
        manifest = inspect_conversation_bytes(CONVERSATION_EML)
        report = {
            "from_": "Forwarder <forwarder@example.com>",
            "auth_results": {"SPF": {"status": "pass"}},
            "links": [],
        }

        apply_conversation_selection(report, manifest, {
            "target_ids": ["outer"],
            "context_ids": [],
        })

        self.assertEqual("outer_delivery", report["selected_target_authentication_scope"])
        self.assertEqual("pass", report["auth_results"]["SPF"]["status"])
        self.assertNotIn("outer_delivery_evidence", report)

    def test_mixed_targets_keep_auth_only_for_the_outer_target(self):
        manifest = inspect_conversation_bytes(CONVERSATION_EML)
        report = {
            "from_": "Forwarder <forwarder@example.com>",
            "auth_results": {"SPF": {"status": "pass"}},
            "links": [],
        }

        apply_conversation_selection(report, manifest, {
            "target_ids": ["outer", "message-2"],
            "context_ids": [],
        })

        self.assertEqual("mixed_outer_and_embedded", report["selected_target_authentication_scope"])
        self.assertEqual("pass", report["auth_results"]["SPF"]["status"])


if __name__ == "__main__":
    unittest.main()
