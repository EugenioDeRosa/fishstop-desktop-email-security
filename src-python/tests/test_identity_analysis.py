import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fishstop_engine.identity_analysis import _is_low_quality_entity, extract_organisations


class FakeGliner:
    def __init__(self):
        self.calls = []

    def inference(self, texts, labels, **kwargs):
        self.calls.append((texts, labels, kwargs))
        return [
            ([{
                "text": "PayPal",
                "label": "financial institution",
                "score": 0.91,
                "start": text.index("PayPal"),
                "end": text.index("PayPal") + len("PayPal"),
            }] if "PayPal" in text else [])
            for text in texts
        ]


class IdentityEntityQualityTests(unittest.TestCase):
    def test_gliner_extracts_brand_from_subject_in_one_batch(self):
        model = FakeGliner()
        result = extract_organisations(
            {
                "from_": "Security Team <alerts@example.invalid>",
                "subject": "Urgent: Your PayPal Account Has Been Limited",
                "body_clean": "Verify your PayPal account.",
            },
            model,
        )

        paypal = next(item for item in result["entities"] if item["name"] == "PayPal")
        self.assertEqual("ORG", paypal["entity_type"])
        self.assertIn("subject", {item["source"] for item in paypal["occurrences"]})
        self.assertEqual(1, len(model.calls))
        self.assertIn("financial institution", model.calls[0][1])
        self.assertEqual(0.35, model.calls[0][2]["threshold"])

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
