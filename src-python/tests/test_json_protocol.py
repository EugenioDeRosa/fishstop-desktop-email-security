"""Regression tests for the UTF-8 protocol used by the desktop sidecar."""

from __future__ import annotations

import io
import json
import sys
import unittest
from unittest.mock import patch

import main


class _BinaryOutput:
    def __init__(self) -> None:
        self.buffer = io.BytesIO()

    def write(self, _value: str) -> None:
        raise AssertionError("JSON protocol output must use the binary stream")


class _BinaryInput:
    def __init__(self, value: bytes) -> None:
        self.buffer = io.BytesIO(value)


class JsonProtocolTests(unittest.TestCase):
    def test_output_is_utf8_independent_of_text_stream_encoding(self) -> None:
        output = _BinaryOutput()
        payload = {
            "subject": "Pagamento già effettuato – conferma",
            "sender": "José",
            "currency": "€",
        }

        with patch.object(sys, "stdout", output):
            main._write_json(payload, flush=True)

        encoded = output.buffer.getvalue()
        self.assertIn("già".encode("utf-8"), encoded)
        self.assertEqual(payload, json.loads(encoded.decode("utf-8")))

    def test_unpaired_surrogate_cannot_corrupt_utf8_output(self) -> None:
        encoded = main._json_bytes({"subject": "Valore non valido: \udce9"})

        decoded = json.loads(encoded.decode("utf-8"))
        self.assertEqual("Valore non valido: ?", decoded["subject"])

    def test_worker_input_is_always_decoded_as_utf8(self) -> None:
        input_stream = _BinaryInput('{"subject":"Caffè €"}\n'.encode("utf-8"))

        with patch.object(sys, "stdin", input_stream):
            lines = list(main._stdin_lines())

        self.assertEqual(['{"subject":"Caffè €"}\n'], lines)


if __name__ == "__main__":
    unittest.main()
