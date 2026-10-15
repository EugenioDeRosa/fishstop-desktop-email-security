import json
import unittest
from unittest.mock import patch

import prepare_release_legal


class CargoMetadataTests(unittest.TestCase):
    def test_non_ascii_metadata_is_parsed_without_windows_locale_decoding(self):
        expected = {"packages": [{"name": "example", "description": "License: Łódź 日本語"}]}
        payload = json.dumps(expected, ensure_ascii=False).encode("utf-8")
        with patch.object(prepare_release_legal.subprocess, "check_output", return_value=payload) as run:
            self.assertEqual(prepare_release_legal.cargo_metadata(), expected)
            self.assertFalse(run.call_args.kwargs.get("text", False))
            self.assertIn("--locked", run.call_args.args[0])

    def test_invalid_metadata_is_not_silently_ignored(self):
        with patch.object(prepare_release_legal.subprocess, "check_output", return_value=b"not json"):
            with self.assertRaises(json.JSONDecodeError):
                prepare_release_legal.cargo_metadata()


if __name__ == "__main__":
    unittest.main()
