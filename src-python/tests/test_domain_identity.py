import base64
import unittest
from unittest.mock import patch

import dkim
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from fishstop_engine.domain_identity import verify_message_domain, dns_observations


class DomainIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
        cls.public = b"v=DKIM1; k=rsa; p=" + base64.b64encode(key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1))
        cls.raw = b"From: Acme <notice@acme.com>\r\nTo: user@example.net\r\nSubject: Receipt\r\n\r\nView your receipt.\r\n"
        cls.signature = dkim.sign(cls.raw, b"test", b"acme.com", cls.private, include_headers=[b"from", b"to", b"subject"])

    def test_real_signature_authenticates_domain_but_modified_body_does_not(self):
        answer = type("TXT", (), {"strings": [self.public]})()
        report = {"from_": "Acme <notice@acme.com>"}
        with patch("dns.resolver.resolve", return_value=[answer]):
            verified = verify_message_domain(self.signature + self.raw, report)
            tampered = verify_message_domain(self.signature + self.raw.replace(b"View your receipt.", b"Send your password."), report)
        self.assertEqual("verified", verified["status"])
        self.assertEqual(["acme.com"], verified["verified_domains"])
        self.assertEqual("unverified", tampered["status"])

    def test_fake_authentication_headers_and_unsigned_embedded_messages_are_unverified(self):
        report = {"from_": "Acme <notice@acme.com>"}
        forged = b"Authentication-Results: mx.google.com; dmarc=pass header.from=acme.com\r\n" + self.raw
        self.assertEqual("unverified", verify_message_domain(forged, report)["status"])
        report["selected_target_authentication_scope"] = "embedded_unavailable"
        self.assertEqual("unverified", verify_message_domain(self.signature + self.raw, report)["status"])

    def test_duplicate_from_and_partial_body_signatures_are_unverified(self):
        report = {"from_": "Acme <notice@acme.com>"}
        duplicate = self.signature + b"From: Attacker <evil@example.com>\r\n" + self.raw
        self.assertEqual("unverified", verify_message_domain(duplicate, report)["status"])
        partial = dkim.sign(self.raw, b"test", b"acme.com", self.private, length=True)
        self.assertEqual("unverified", verify_message_domain(partial + self.raw, report)["status"])

    def test_mx_provider_never_becomes_identity_evidence(self):
        answer = type("MX", (), {"exchange": "tenant.mail.protection.outlook.com."})()
        with patch("fishstop_engine.domain_identity.cached", return_value=None), patch("fishstop_engine.domain_identity.put"), patch("dns.resolver.resolve", return_value=[answer]):
            # TXT records are absent; their lookup errors are handled conservatively.
            with patch("dns.resolver.resolve", side_effect=lambda name, kind, **kw: [answer] if kind == "MX" else []):
                result = dns_observations("acme.com")
        self.assertEqual("Microsoft 365", result["provider"])
        self.assertFalse(result["identity_evidence"])


if __name__ == "__main__":
    unittest.main()
