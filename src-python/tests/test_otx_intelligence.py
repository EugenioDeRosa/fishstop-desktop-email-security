import sys
import unittest
from pathlib import Path
from urllib.parse import unquote


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fishstop_engine.otx_intelligence import (
    _indicator_candidates,
    _lookup_exact_indicator,
    apply_on_demand_otx_intelligence,
)


PHISHING_PULSE = {
    "id": "0123456789abcdef01234567",
    "name": "Exact phishing campaign",
    "author_name": "researcher",
    "modified": "2026-09-12T10:00:00Z",
    "tags": ["phishing"],
    "TLP": "white",
}


class Response:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self.payload


class Session:
    def __init__(self, responder):
        self.headers = {}
        self._responder = responder

    def get(self, url, timeout):
        return self._responder(url, timeout)

    def close(self):
        pass


def report_with_url(url="https://evil.example/login?id=42"):
    return {
        "from_": "Security <notice@example.org>",
        "return_path": "bounce@example.org",
        "reply_to": "",
        "links": [{
            "url": url,
            "scheme": "https",
            "host": "evil.example",
            "role": "body_action",
            "actionable": True,
            "html_call_to_action": True,
            "display_text": "Open document",
        }],
        "attachments": [],
        "received_hops": [],
        "flags": [],
    }


class OnDemandOtxTests(unittest.TestCase):
    def test_candidates_do_not_derive_host_or_parent_domain_from_url(self):
        candidates = _indicator_candidates(report_with_url())

        self.assertIn(("url", "https://evil.example/login?id=42", "link"), candidates)
        self.assertNotIn(("hostname", "evil.example", "link"), candidates)
        self.assertNotIn(("domain", "evil.example", "link"), candidates)

    def test_sender_subdomain_is_not_replaced_with_parent_domain(self):
        report = report_with_url()
        report["from_"] = "Security <notice@mail.example.org>"
        report["return_path"] = ""

        candidates = _indicator_candidates(report)

        self.assertIn(("domain", "mail.example.org", "sender identity"), candidates)
        self.assertNotIn(("domain", "example.org", "sender identity"), candidates)

    def test_exact_url_and_phishing_tag_create_a_high_risk_match(self):
        requested = []

        def responder(url, _timeout):
            indicator = unquote(url.split("/url/", 1)[1].rsplit("/general", 1)[0])
            requested.append(indicator)
            return Response({
                "indicator": indicator,
                "type": "URL",
                "pulse_info": {"pulses": [PHISHING_PULSE]},
            })

        report = report_with_url()
        apply_on_demand_otx_intelligence(
            report,
            "test-key",
            session_factory=lambda: Session(responder),
        )

        self.assertIn("https://evil.example/login?id=42", requested)
        self.assertEqual("match", report["otx_intelligence"]["status"])
        self.assertEqual("exact", report["otx_intelligence"]["matches"][0]["match_type"])
        self.assertEqual(
            report["otx_intelligence"]["matches"][0]["indicator"],
            report["otx_intelligence"]["matches"][0]["matched_indicator"],
        )
        self.assertTrue(any(flag["level"] == "HIGH" for flag in report["flags"]))

    def test_different_returned_url_is_not_a_match(self):
        def responder(_url, _timeout):
            return Response({
                "indicator": "https://evil.example/login",
                "type": "URL",
                "pulse_info": {"pulses": [PHISHING_PULSE]},
            })

        result = _lookup_exact_indicator(
            Session(responder),
            "url",
            "https://evil.example/login?id=42",
        )

        self.assertFalse(result["matched"])

    def test_same_domain_different_url_is_not_a_match(self):
        def responder(_url, _timeout):
            return Response({
                "indicator": "https://evil.example/other",
                "type": "URL",
                "pulse_info": {"pulses": [PHISHING_PULSE]},
            })

        report = report_with_url()
        apply_on_demand_otx_intelligence(
            report,
            "test-key",
            session_factory=lambda: Session(responder),
        )

        self.assertEqual("no_match", report["otx_intelligence"]["status"])
        self.assertEqual([], report["otx_intelligence"]["matches"])
        self.assertFalse(any(flag["field"] == "OTX Threat Intelligence" for flag in report["flags"]))

    def test_unrecognized_pulse_tag_is_neutral_context(self):
        def responder(url, _timeout):
            indicator = unquote(url.split("/url/", 1)[1].rsplit("/general", 1)[0])
            return Response({
                "indicator": indicator,
                "type": "URL",
                "pulse_info": {"pulses": [{**PHISHING_PULSE, "tags": ["phishing-kit"]}]},
            })

        report = report_with_url()
        apply_on_demand_otx_intelligence(
            report,
            "test-key",
            session_factory=lambda: Session(responder),
        )

        self.assertEqual("context_only", report["otx_intelligence"]["status"])
        self.assertEqual("informational", report["otx_intelligence"]["matches"][0]["confidence"])
        self.assertFalse(any(flag["field"] == "OTX Threat Intelligence" for flag in report["flags"]))

    def test_exact_url_in_malware_pulse_is_high_confidence(self):
        def responder(url, _timeout):
            indicator = unquote(url.split("/url/", 1)[1].rsplit("/general", 1)[0])
            return Response({
                "indicator": indicator,
                "type": "URL",
                "pulse_info": {"pulses": [{**PHISHING_PULSE, "tags": ["malware"]}]},
            })

        report = report_with_url()
        report["from_"] = ""
        report["return_path"] = ""
        apply_on_demand_otx_intelligence(report, "test-key", session_factory=lambda: Session(responder))

        self.assertEqual("match", report["otx_intelligence"]["status"])
        self.assertEqual("strong", report["otx_intelligence"]["matches"][0]["confidence"])

    def test_exact_domain_in_malware_pulse_is_neutral_context(self):
        def responder(url, _timeout):
            indicator = unquote(url.split("/domain/", 1)[1].rsplit("/general", 1)[0])
            return Response({
                "indicator": indicator,
                "type": "domain",
                "pulse_info": {"pulses": [{**PHISHING_PULSE, "tags": ["malware"]}]},
            })

        report = report_with_url()
        report["links"] = []
        apply_on_demand_otx_intelligence(report, "test-key", session_factory=lambda: Session(responder))

        self.assertEqual("context_only", report["otx_intelligence"]["status"])
        self.assertEqual("informational", report["otx_intelligence"]["matches"][0]["confidence"])

    def test_exact_phishing_ip_requires_independent_corroboration(self):
        ip = "8.8.8.8"

        def responder(url, _timeout):
            indicator = unquote(url.split("/IPv4/", 1)[1].rsplit("/general", 1)[0])
            return Response({
                "indicator": indicator,
                "type": "IPv4",
                "pulse_info": {"pulses": [PHISHING_PULSE]},
            })

        report = report_with_url()
        report["links"] = []
        report["from_"] = ""
        report["return_path"] = ""
        report["received_hops"] = [{"all_ips": [ip]}]
        apply_on_demand_otx_intelligence(report, "test-key", session_factory=lambda: Session(responder))
        self.assertEqual("supporting", report["otx_intelligence"]["matches"][0]["confidence"])
        self.assertEqual("context_only", report["otx_intelligence"]["status"])

        report = {**report_with_url(), "links": [], "from_": "", "return_path": "", "received_hops": [{"all_ips": [ip]}], "hop_reputation": {ip: {"abuseConfidenceScore": 80}}}
        apply_on_demand_otx_intelligence(report, "test-key", session_factory=lambda: Session(responder))
        self.assertEqual("strong", report["otx_intelligence"]["matches"][0]["confidence"])
        self.assertEqual("match", report["otx_intelligence"]["status"])

    def test_missing_key_is_unavailable_and_does_not_contact_otx(self):
        report = report_with_url()
        apply_on_demand_otx_intelligence(report, "")

        self.assertEqual("unavailable", report["otx_intelligence"]["status"])
        self.assertEqual(0, report["otx_intelligence"]["checked_indicator_count"])

    def test_footer_and_unsubscribe_links_are_not_queried(self):
        report = report_with_url()
        report["links"].extend([
            {
                "url": "https://example.org/unsubscribe",
                "scheme": "https",
                "role": "unsubscribe",
                "actionable": True,
            },
            {
                "url": "https://example.org/signature",
                "scheme": "https",
                "role": "signature",
                "actionable": True,
            },
        ])

        urls = [value for kind, value, _source in _indicator_candidates(report) if kind == "url"]
        self.assertEqual(["https://evil.example/login?id=42"], urls)

    def test_labelled_call_to_action_excludes_unlabelled_tracking_anchor(self):
        report = report_with_url()
        report["links"].append({
            "url": "https://tracking.example/pixel?id=7",
            "scheme": "https",
            "role": "body_action",
            "actionable": True,
            "html_call_to_action": True,
            "display_text": "",
        })

        urls = [value for kind, value, _source in _indicator_candidates(report) if kind == "url"]
        self.assertEqual(["https://evil.example/login?id=42"], urls)

    def test_inline_image_hash_is_not_queried(self):
        report = report_with_url()
        inline_hash = "a" * 64
        document_hash = "b" * 64
        report["attachments"] = [
            {
                "filename": "logo.png",
                "hash_sha256": inline_hash,
                "mime_role": "inline_resource",
                "actionable": False,
            },
            {
                "filename": "invoice.pdf",
                "hash_sha256": document_hash,
                "mime_role": "attachment",
                "actionable": True,
            },
        ]

        hashes = [value for kind, value, _source in _indicator_candidates(report) if kind == "sha256"]
        self.assertEqual([document_hash], hashes)


if __name__ == "__main__":
    unittest.main()
