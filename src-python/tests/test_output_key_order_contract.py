"""Point 9: the JSON key order FAST was trained on must match what the app gets.

Offline checks (always run):
* every schema still produces the trained top-level order;
* the bundled Ollama runtime is the version the order was observed on.

Live check (opt-in, on a machine running the bundled Ollama):
    FISHSTOP_OLLAMA_CONTRACT_MODEL=fishstop-fast-lite \\
    [OLLAMA_HOST=http://127.0.0.1:11434] python -m pytest tests/test_output_key_order_contract.py
It sends each schema to Ollama and reads the key order of the raw output.
"""

import json
import os
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fishstop_engine.analyzer.output_contract import (
    OLLAMA_CONTRACT_VERSION,
    TRAINED_KEY_ORDER,
    expected_generation_order,
    schemas_by_stage,
)

REPO = Path(__file__).resolve().parents[2]


class OfflineKeyOrderContractTests(unittest.TestCase):
    def test_every_pipeline_schema_is_covered(self):
        self.assertEqual(set(TRAINED_KEY_ORDER), set(schemas_by_stage()))

    def test_schemas_still_generate_the_trained_order(self):
        for stage, schema in schemas_by_stage().items():
            with self.subTest(stage):
                self.assertEqual(
                    TRAINED_KEY_ORDER[stage], expected_generation_order(schema),
                    "The required keys changed: the model would receive a different order than it was "
                    "trained on. Re-verify with the live check and realign the dataset (see output_contract.py).",
                )

    def test_audit_sub_objects_follow_the_verifier_orders(self):
        audit = schemas_by_stage()["audit"]
        for check, schema in audit["properties"].items():
            with self.subTest(check):
                self.assertEqual(TRAINED_KEY_ORDER[f"verifier:{check}"], expected_generation_order(schema))

    def test_primary_pass_writes_the_explanation_before_the_verdict(self):
        order = TRAINED_KEY_ORDER["primary"]
        self.assertLess(order.index("explanation"), order.index("verdict"))

    def test_bundled_ollama_is_the_contract_version(self):
        rust = (REPO / "src-tauri/src/ollama_runtime.rs").read_text(encoding="utf-8")
        script = (REPO / "scripts/download_ollama_runtime.py").read_text(encoding="utf-8")
        bundled = {
            "src-tauri/src/ollama_runtime.rs": re.search(r'OLLAMA_RUNTIME_VERSION:\s*&str\s*=\s*"([^"]+)"', rust).group(1),
            "scripts/download_ollama_runtime.py": re.search(r'OLLAMA_VERSION",\s*"([^"]+)"', script).group(1),
        }
        for source, version in bundled.items():
            with self.subTest(source):
                self.assertEqual(
                    OLLAMA_CONTRACT_VERSION, version,
                    "The bundled Ollama changed. Run the live key-order check against it before releasing, "
                    "then update OLLAMA_CONTRACT_VERSION (and the dataset if the order changed).",
                )


def _object_key_order(text: str) -> list[str]:
    """Top-level keys in the order they appear in the generated JSON text."""
    pairs = json.loads(text, object_pairs_hook=lambda items: items)
    return [key for key, _ in pairs]


@unittest.skipUnless(os.getenv("FISHSTOP_OLLAMA_CONTRACT_MODEL"), "live Ollama contract check is opt-in")
class LiveOllamaKeyOrderContractTests(unittest.TestCase):
    def setUp(self):
        import requests
        self.requests = requests
        self.host = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
        self.model = os.environ["FISHSTOP_OLLAMA_CONTRACT_MODEL"]

    def test_running_ollama_is_the_contract_version(self):
        version = self.requests.get(f"{self.host}/api/version", timeout=10).json().get("version", "")
        self.assertEqual(OLLAMA_CONTRACT_VERSION.lstrip("v"), version.lstrip("v"))

    def test_generated_key_order_matches_training(self):
        for stage, schema in schemas_by_stage().items():
            with self.subTest(stage):
                response = self.requests.post(f"{self.host}/api/chat", json={
                    "model": self.model,
                    "stream": False,
                    "format": schema,
                    "options": {"temperature": 0, "num_predict": 512},
                    "messages": [{"role": "user", "content": (
                        "Return the JSON object for this email.\n<UNTRUSTED_EMAIL>\nSUBJECT: Hello\n"
                        "BODY:\nThe meeting is moved to Friday.\n</UNTRUSTED_EMAIL>")}],
                }, timeout=180)
                response.raise_for_status()
                text = response.json()["message"]["content"]
                self.assertEqual(TRAINED_KEY_ORDER[stage], _object_key_order(text), text)


if __name__ == "__main__":
    unittest.main()
