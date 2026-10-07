import base64
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from fishstop_engine.identity_store import (registry_operation, resolve_partner, cached, put,
                                           import_directory, action_authorized, local_records)


class IdentityStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.env = patch.dict(os.environ, {"FISHSTOP_IDENTITY_DATA_DIR": self.temp.name})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.record = {"brand": "Small Company", "aliases": ["Small Co"], "reference": "Confirmed through a previously known procurement contact",
                       "relations": [{"domain": "small-company.it", "role": "official", "scopes": ["sender", "visit_link"]}]}

    def add(self, **extra):
        return registry_operation({**self.record, "operation": "add", "identity_confirmed": True, **extra})

    def signed(self, sequence=1):
        private = Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        key_file = Path(self.temp.name) / "keys.json"
        key_file.write_text(json.dumps({"admin-1": base64.b64encode(public).decode()}), encoding="utf-8")
        os.environ["FISHSTOP_IDENTITY_TRUSTED_KEYS"] = str(key_file)
        now = time.time()
        payload = {"key_id": "admin-1", "sequence": sequence, "issued_at": now, "expires_at": now + 3600, "records": [self.record]}
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        return {"payload": payload, "signature": base64.b64encode(private.sign(encoded)).decode()}, private

    def test_manual_confirmation_alias_and_revocation(self):
        with self.assertRaises(ValueError):
            self.add(identity_confirmed=False)
        result = self.add()
        self.assertEqual("Small Company", resolve_partner("SMALL CO")["brand"])
        registry_operation({"operation": "remove", "id": result["records"][0]["id"]})
        self.assertIsNone(resolve_partner("Small Company"))

    def test_expired_evidence_is_not_reused(self):
        put("sample", {"test": True}, -1)
        self.assertIsNone(cached("sample"))
        self.add(valid_days=1)
        with patch("fishstop_engine.identity_store.time.time", return_value=time.time() + 86401):
            self.assertIsNone(resolve_partner("Small Company"))

    def test_signed_directory_rejects_tampering_rollback_and_revoked_key(self):
        bundle, _ = self.signed()
        import_directory(bundle)
        self.assertEqual("signed_directory", resolve_partner("Small Company")["source"])
        with self.assertRaises(ValueError):
            import_directory(bundle)
        bundle["payload"]["records"][0]["brand"] = "Attacker"
        with self.assertRaises(InvalidSignature):
            import_directory(bundle)
        Path(os.environ["FISHSTOP_IDENTITY_TRUSTED_KEYS"]).write_text("{}", encoding="utf-8")
        self.assertEqual([], local_records())

    def test_signed_snapshot_removal_revokes_previous_relationship(self):
        bundle, private = self.signed()
        import_directory(bundle)
        bundle["payload"]["sequence"] = 2
        bundle["payload"]["records"] = []
        encoded = json.dumps(bundle["payload"], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        bundle["signature"] = base64.b64encode(private.sign(encoded)).decode()
        import_directory(bundle)
        self.assertIsNone(resolve_partner("Small Company"))

    def test_delegation_is_exact_host_action_and_path_scoped(self):
        relation = {"domain": "forms.service.com", "role": "delegate", "scopes": ["provide_information"], "path_prefix": "/customer/form"}
        good = {"url": "https://forms.service.com/customer/form/start"}
        self.assertTrue(action_authorized(good, relation, "provide_information"))
        for url in ["https://forms.service.com/other/form", "https://forms.service.com/customer/form-evil",
                    "https://other.service.com/customer/form", "https://forms.service.com/customer/form/../evil",
                    "http://forms.service.com/customer/form", "https://attacker@forms.service.com/customer/form"]:
            self.assertFalse(action_authorized({"url": url}, relation, "provide_information"))
        self.assertFalse(action_authorized(good, relation, "pay_or_transfer"))

    def test_whole_external_service_cannot_be_authorized_for_actions(self):
        with self.assertRaises(ValueError):
            self.add(relations=[*self.record["relations"], {"domain": "service.com", "role": "delegate", "scopes": ["pay_or_transfer"]}])

    def test_domain_control_does_not_assign_a_company_identity(self):
        challenge = registry_operation({"operation": "challenge", "domain": "small-company.it"})
        value = challenge["record_value"].encode()
        answer = type("TXT", (), {"strings": [value]})()
        with patch("dns.resolver.resolve", return_value=[answer]):
            result = registry_operation({"operation": "verify-control", "domain": "small-company.it"})
        self.assertTrue(result["control_verified"])
        self.assertIsNone(resolve_partner("Small Company"))


if __name__ == "__main__":
    unittest.main()
