import unittest

from fishstop_engine.analyzer.body_context import extract_forwarded_identity


class ForwardedIdentityTests(unittest.TestCase):
    def test_localized_forward_headers_are_kept_as_a_separate_identity(self):
        identity = extract_forwarded_identity(
            """p.c.

---------- Forwarded message ---------
Da: Massimo Masotti <m.masotti@lslex.com>
Date: mer 3 giu 2026 alle ore 08:59
Subject: Nuova dichiarazione approvata
To: Davide <davide@example.com>

Apri il documento qui.
"""
        )

        self.assertEqual("Massimo Masotti", identity["display_name"])
        self.assertEqual("m.masotti@lslex.com", identity["address"])
        self.assertEqual("lslex.com", identity["domain"])
        self.assertEqual("unavailable", identity["authentication_status"])
        self.assertEqual("embedded_forward", identity["authentication_scope"])

    def test_normal_message_has_no_embedded_identity(self):
        self.assertEqual({}, extract_forwarded_identity("Hello from sender@example.com"))


if __name__ == "__main__":
    unittest.main()
