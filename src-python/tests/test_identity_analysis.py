import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fishstop_engine.identity_analysis import _is_low_quality_entity


class IdentityEntityQualityTests(unittest.TestCase):
    def test_entity_at_start_of_text_is_not_rejected_by_empty_boundary(self):
        text = "Microsoft detected a sign-in"
        self.assertFalse(
            _is_low_quality_entity(
                "Microsoft",
                "Microsoft",
                text,
                0,
                len("Microsoft"),
            )
        )

    def test_entity_embedded_in_an_email_address_is_rejected(self):
        text = "alerts@microsoft.com"
        start = text.index("microsoft")
        self.assertTrue(
            _is_low_quality_entity(
                "microsoft",
                "microsoft",
                text,
                start,
                start + len("microsoft"),
            )
        )


if __name__ == "__main__":
    unittest.main()
