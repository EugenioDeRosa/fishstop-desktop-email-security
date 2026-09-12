from datetime import datetime, timezone
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import requests

from fishstop_engine.analyzer.llm_context_analyzer import (
    _technical_context_lines,
    _technical_risk,
)
from fishstop_engine.otx_intelligence import (
    OtxSearchDepthError,
    _active_indicator,
    _database_connection,
    _enqueue_public_pulse,
    _initialize_database,
    _process_public_pulse_queue,
    _request_json,
    _set_metadata,
    _store_pulse,
    apply_local_otx_intelligence,
    otx_cache_status,
    sync_subscribed_pulses,
)


PULSE = {
    "id": "0123456789abcdef01234567",
    "name": "Credential phishing infrastructure",
    "author": "researcher",
    "modified": "2026-09-08T10:00:00Z",
    "tags": ["phishing"],
    "tlp": "white",
}


class LocalOtxIntelligenceTests(unittest.TestCase):
    def test_previous_schema_requires_a_safe_rebuild(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "otx.sqlite3"
            with _database_connection(path) as connection:
                _initialize_database(connection)
                _set_metadata(connection, "schema_version", 4)
                connection.commit()

            status = otx_cache_status(str(path))
            report = {"links": [], "flags": []}
            apply_local_otx_intelligence(report, str(path))

        self.assertEqual("not_synced", status["status"])
        self.assertEqual("schema", status["limit_reason"])
        self.assertGreater(status["database_bytes"], 0)
        self.assertEqual("unavailable", report["otx_intelligence"]["status"])

    def test_public_indicator_queue_resumes_from_saved_page(self):
        pulse_id = "0123456789abcdef01234567"
        now = datetime.now(timezone.utc)
        pages = {
            f"https://otx.alienvault.com/api/v1/pulses/{pulse_id}/indicators": {
                "count": 2,
                "next": f"https://otx.alienvault.com/api/v1/pulses/{pulse_id}/indicators?page=2",
                "results": [{"type": "domain", "indicator": "first.example"}],
            },
            f"https://otx.alienvault.com/api/v1/pulses/{pulse_id}/indicators?page=2": {
                "count": 2,
                "next": None,
                "results": [{"type": "domain", "indicator": "second.example"}],
            },
        }

        def request(_session, url, **_kwargs):
            return pages[url]

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "otx.sqlite3"
            with _database_connection(path) as connection:
                _initialize_database(connection)
                with connection:
                    _enqueue_public_pulse(connection, PULSE, now)
                with (
                    patch("fishstop_engine.otx_intelligence._request_json", request),
                    patch(
                        "fishstop_engine.otx_intelligence._public_budget_reason",
                        side_effect=["", "", "time"],
                    ),
                ):
                    _, reason = _process_public_pulse_queue(
                        object(), connection, now, 0, lambda _event: None
                    )
                checkpoint = connection.execute(
                    "SELECT processed, next_url FROM public_pulse_queue WHERE pulse_id = ?",
                    (pulse_id,),
                ).fetchone()
                self.assertEqual("time", reason)
                self.assertEqual(1, checkpoint["processed"])
                self.assertTrue(checkpoint["next_url"].endswith("page=2"))

                with (
                    patch("fishstop_engine.otx_intelligence._request_json", request),
                    patch("fishstop_engine.otx_intelligence._public_budget_reason", return_value=""),
                ):
                    _process_public_pulse_queue(
                        object(), connection, now, 0, lambda _event: None
                    )
                self.assertEqual(
                    0,
                    connection.execute(
                        "SELECT COUNT(*) FROM public_pulse_queue"
                    ).fetchone()[0],
                )
                self.assertEqual(
                    2,
                    connection.execute("SELECT COUNT(*) FROM indicators").fetchone()[0],
                )

    def test_public_indicator_queue_downloads_different_pulses_concurrently(self):
        pulse_ids = (
            "0123456789abcdef01234567",
            "89abcdef0123456701234567",
        )
        now = datetime.now(timezone.utc)
        barrier = threading.Barrier(2)
        lock = threading.Lock()
        active = 0
        maximum_active = 0
        session_ids = set()

        def request(session, url, **_kwargs):
            nonlocal active, maximum_active
            pulse_id = next(item for item in pulse_ids if item in url)
            with lock:
                session_ids.add(id(session))
                active += 1
                maximum_active = max(maximum_active, active)
            try:
                barrier.wait(timeout=2)
                return {
                    "count": 1,
                    "next": None,
                    "results": [{
                        "type": "domain",
                        "indicator": f"{pulse_id}.example",
                    }],
                }
            finally:
                with lock:
                    active -= 1

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "otx.sqlite3"
            with _database_connection(path) as connection:
                _initialize_database(connection)
                with connection:
                    for pulse_id in pulse_ids:
                        _enqueue_public_pulse(
                            connection,
                            {**PULSE, "id": pulse_id, "name": f"Pulse {pulse_id}"},
                            now,
                        )
                with (
                    patch("fishstop_engine.otx_intelligence._request_json", request),
                    patch(
                        "fishstop_engine.otx_intelligence._indicator_worker_count",
                        return_value=2,
                    ),
                    patch(
                        "fishstop_engine.otx_intelligence._public_budget_reason",
                        return_value="",
                    ),
                ):
                    _process_public_pulse_queue(
                        object(), connection, now, 0, lambda _event: None
                    )

                self.assertEqual(2, maximum_active)
                self.assertEqual(2, len(session_ids))
                self.assertEqual(
                    0,
                    connection.execute(
                        "SELECT COUNT(*) FROM public_pulse_queue"
                    ).fetchone()[0],
                )
                self.assertEqual(
                    2,
                    connection.execute("SELECT COUNT(*) FROM indicators").fetchone()[0],
                )

    def test_analysis_pause_checkpoints_and_resumes_subscribed_pagination(self):
        second_id = "89abcdef0123456701234567"
        calls = []

        class Response:
            status_code = 200
            headers = {}

            def __init__(self, payload):
                self.payload = payload

            @staticmethod
            def raise_for_status():
                return None

            def json(self):
                return self.payload

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "otx.sqlite3"
            pause_file = Path(directory) / "analysis.pause"

            class Session:
                def __init__(self):
                    self.headers = {}

                def get(self, url, **_kwargs):
                    calls.append(url)
                    if "/pulses/subscribed" in url:
                        if "page=2" in url:
                            return Response({
                                "next": None,
                                "results": [{
                                    **PULSE,
                                    "id": second_id,
                                    "name": "Second subscribed Pulse",
                                    "indicators": [{
                                        "type": "domain",
                                        "indicator": "second.example",
                                    }],
                                }],
                            })
                        pause_file.write_text("analysis", encoding="utf-8")
                        return Response({
                            "next": (
                                "https://otx.alienvault.com/api/v1/"
                                "pulses/subscribed?page=2"
                            ),
                            "results": [{
                                **PULSE,
                                "name": "First subscribed Pulse",
                                "indicators": [{
                                    "type": "domain",
                                    "indicator": "first.example",
                                }],
                            }],
                        })
                    if "/search/pulses" in url:
                        return Response({"next": None, "results": []})
                    raise AssertionError(f"Unexpected OTX URL: {url}")

            with (
                patch("fishstop_engine.otx_intelligence.requests.Session", Session),
                patch.dict(
                    "os.environ",
                    {"FISHSTOP_OTX_PAUSE_FILE": str(pause_file)},
                ),
                patch(
                    "fishstop_engine.otx_intelligence.PUBLIC_SEARCH_WINDOW_DAYS",
                    365,
                ),
            ):
                paused = sync_subscribed_pulses(str(path), "test-key")
                self.assertTrue(paused["truncated"])
                self.assertEqual("analysis", paused["limit_reason"])
                self.assertEqual(1, paused["indicator_count"])

                pause_file.unlink()
                calls.clear()
                resumed = sync_subscribed_pulses(str(path), "test-key")

            self.assertFalse(resumed["truncated"])
            self.assertEqual(2, resumed["indicator_count"])
            self.assertTrue(any("subscribed?page=2" in url for url in calls))
            self.assertFalse(any(url.endswith("/pulses/subscribed") for url in calls))

    def test_page_51_bad_request_is_recognized_as_search_depth_limit(self):
        class Response:
            status_code = 400
            headers = {}

            @staticmethod
            def raise_for_status():
                raise AssertionError("The generic HTTP error path should not run")

        class Session:
            @staticmethod
            def get(_url, **_kwargs):
                return Response()

        with self.assertRaises(OtxSearchDepthError):
            _request_json(
                Session(),
                "https://otx.alienvault.com/api/v1/search/pulses?page=51&limit=50",
            )

    def test_search_depth_limit_restarts_with_narrower_time_windows(self):
        queries = []

        def request(_session, url, *, params=None, **_kwargs):
            if url.endswith("/pulses/subscribed"):
                return {"next": None, "results": []}
            if "page=51" in url:
                raise OtxSearchDepthError("search depth")
            query = (params or {}).get("q", "")
            queries.append(query)
            if query.endswith("modified:<4d") and "modified:>" not in query:
                return {
                    "count": 2_501,
                    "next": (
                        "https://otx.alienvault.com/api/v1/search/pulses"
                        "?page=51&limit=50"
                    ),
                    "results": [],
                }
            return {"count": 0, "next": None, "results": []}

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "otx.sqlite3"
            with (
                patch("fishstop_engine.otx_intelligence.requests.Session"),
                patch("fishstop_engine.otx_intelligence._request_json", request),
                patch("fishstop_engine.otx_intelligence.INITIAL_LOOKBACK_DAYS", 4),
                patch("fishstop_engine.otx_intelligence.PUBLIC_SEARCH_WINDOW_DAYS", 4),
            ):
                result = sync_subscribed_pulses(str(path), "test-key")

        self.assertFalse(result["truncated"])
        self.assertIn('tag:"phishing" AND modified:<2d', queries)
        self.assertIn(
            'tag:"phishing" AND modified:>2d AND modified:<4d',
            queries,
        )

    def _cache(self, entries: dict) -> tuple[tempfile.TemporaryDirectory, str]:
        directory = tempfile.TemporaryDirectory()
        path = Path(directory.name) / "otx.sqlite3"
        indicators = []
        for key in entries:
            kind, value = key.split(":", 1)
            indicators.append({
                "type": "FileHash-SHA256" if kind == "sha256" else kind,
                "indicator": value,
            })
        with _database_connection(path) as connection:
            _initialize_database(connection)
            _store_pulse(
                connection,
                {**PULSE, "indicators": indicators},
                "public_phishing",
                datetime(2026, 9, 8, 10, tzinfo=timezone.utc),
            )
            _set_metadata(connection, "synced_at", "2026-09-08T10:00:00Z")
            _set_metadata(connection, "lookback_days", 365)
            connection.commit()
        return directory, str(path)

    def test_indicator_expiration_accepts_naive_and_aware_otx_timestamps(self):
        self.assertTrue(_active_indicator({"expiration": "2999-01-01T00:00:00"}))
        self.assertTrue(_active_indicator({"expiration": "2999-01-01T00:00:00Z"}))
        self.assertTrue(_active_indicator({"expiration": "2999-01-01T01:00:00+01:00"}))
        self.assertFalse(_active_indicator({"expiration": "2000-01-01T00:00:00"}))

    def test_invalid_indicator_expiration_does_not_break_synchronization(self):
        self.assertTrue(_active_indicator({"expiration": "not-a-timestamp"}))

    def test_exact_url_match_is_high_risk_evidence(self):
        directory, path = self._cache({
            "url:https://malicious.example/login": [PULSE],
        })
        self.addCleanup(directory.cleanup)
        report = {
            "links": [{
                "url": "https://malicious.example/login#ignored",
                "host": "malicious.example",
                "scheme": "https",
            }],
            "flags": [],
        }

        apply_local_otx_intelligence(report, path)

        self.assertEqual("match", report["otx_intelligence"]["status"])
        self.assertEqual("strong", report["otx_intelligence"]["matches"][0]["confidence"])
        self.assertEqual(
            "https://otx.alienvault.com/pulse/0123456789abcdef01234567",
            report["otx_intelligence"]["matches"][0]["pulses"][0]["url"],
        )
        self.assertEqual("HIGH", report["flags"][-1]["level"])
        self.assertEqual("malicious", _technical_risk(report)[0])

    def test_link_does_not_inherit_a_domain_level_otx_match(self):
        directory, path = self._cache({
            "domain:malicious.com": [PULSE],
        })
        self.addCleanup(directory.cleanup)
        report = {
            "links": [{
                "url": "https://sub.malicious.com/path",
                "host": "sub.malicious.com",
                "scheme": "https",
            }],
            "flags": [],
        }

        apply_local_otx_intelligence(report, path)

        self.assertEqual("no_match", report["otx_intelligence"]["status"])
        self.assertEqual([], report["flags"])
        self.assertNotEqual("malicious", _technical_risk(report)[0])

    def test_specific_parent_url_scope_is_high_risk_evidence(self):
        directory, path = self._cache({
            "url:https://sites.google.com/view/known-phishing-site": [PULSE],
        })
        self.addCleanup(directory.cleanup)
        report = {
            "links": [{
                "url": "https://sites.google.com/view/known-phishing-site/home",
                "host": "sites.google.com",
                "scheme": "https",
            }],
            "flags": [],
        }

        apply_local_otx_intelligence(report, path)

        match = report["otx_intelligence"]["matches"][0]
        self.assertEqual("url_scope", match["match_type"])
        self.assertEqual(
            "https://sites.google.com/view/known-phishing-site",
            match["matched_indicator"],
        )
        self.assertEqual("HIGH", report["flags"][-1]["level"])

    def test_google_sites_link_does_not_inherit_other_tenants_pulses(self):
        directory, path = self._cache({
            "url:https://sites.google.com/view/facturacion2026mx": [PULSE],
        })
        self.addCleanup(directory.cleanup)
        report = {
            "links": [{
                "url": "https://sites.google.com/view/1099812345/home",
                "host": "sites.google.com",
                "scheme": "https",
            }],
            "flags": [],
        }

        apply_local_otx_intelligence(report, path)

        self.assertEqual("no_match", report["otx_intelligence"]["status"])
        self.assertEqual([], report["flags"])

    def test_public_mailbox_domain_match_is_context_only(self):
        directory, path = self._cache({
            "domain:gmail.com": [PULSE],
        })
        self.addCleanup(directory.cleanup)
        report = {
            "from_": "Unknown sender <someone@gmail.com>",
            "flags": [],
        }

        apply_local_otx_intelligence(report, path)

        intelligence = report["otx_intelligence"]
        self.assertEqual("match", intelligence["status"])
        self.assertEqual(0, intelligence["strong_match_count"])
        self.assertEqual(1, intelligence["supporting_match_count"])
        self.assertEqual("supporting", intelligence["matches"][0]["confidence"])
        self.assertTrue(intelligence["matches"][0]["shared_infrastructure"])
        self.assertEqual([], report["flags"])
        self.assertNotEqual("malicious", _technical_risk(report)[0])
        self.assertTrue(any(
            "shared infrastructure is not a malicious-domain verdict" in line
            for line in _technical_context_lines(report)
        ))

    def test_exact_public_mailbox_address_remains_high_risk(self):
        directory, path = self._cache({
            "email:known-attacker@gmail.com": [PULSE],
            "domain:gmail.com": [PULSE],
        })
        self.addCleanup(directory.cleanup)
        report = {
            "reply_to": "known-attacker@gmail.com",
            "flags": [],
        }

        apply_local_otx_intelligence(report, path)

        intelligence = report["otx_intelligence"]
        self.assertEqual(1, intelligence["strong_match_count"])
        self.assertEqual(1, intelligence["supporting_match_count"])
        self.assertEqual("email", intelligence["matches"][0]["indicator_type"])
        self.assertEqual("strong", intelligence["matches"][0]["confidence"])
        self.assertEqual("HIGH", report["flags"][-1]["level"])
        self.assertEqual("malicious", _technical_risk(report)[0])

    def test_no_match_is_neutral_and_does_not_add_a_flag(self):
        directory, path = self._cache({
            "domain:unrelated.example": [PULSE],
        })
        self.addCleanup(directory.cleanup)
        report = {
            "links": [{
                "url": "https://ordinary.example/",
                "host": "ordinary.example",
                "scheme": "https",
            }],
            "flags": [],
        }

        apply_local_otx_intelligence(report, path)

        self.assertEqual("no_match", report["otx_intelligence"]["status"])
        self.assertEqual([], report["flags"])
        context = _technical_context_lines(report)
        self.assertTrue(any("neutral evidence" in line for line in context))

    def test_missing_cache_is_non_blocking(self):
        report = {"links": [], "flags": []}
        apply_local_otx_intelligence(report, "/path/that/does/not/exist.json")
        self.assertEqual("unavailable", report["otx_intelligence"]["status"])
        self.assertEqual([], report["flags"])

    def test_sync_writes_an_indexed_local_database(self):
        class Response:
            status_code = 200

            @staticmethod
            def raise_for_status():
                return None

            @staticmethod
            def json():
                return {
                    "next": None,
                    "results": [{
                        **PULSE,
                        "indicators": [{
                            "type": "URL",
                            "indicator": "https://malicious.example/login#fragment",
                            "is_active": True,
                            "expiration": "2999-01-01T00:00:00",
                        }],
                    }],
                }

        class Session:
            def __init__(self):
                self.headers = {}

            @staticmethod
            def get(*_args, **_kwargs):
                return Response()

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "otx.sqlite3"
            progress = []
            with patch("fishstop_engine.otx_intelligence.requests.Session", Session):
                result = sync_subscribed_pulses(str(path), "test-key", progress.append)
            with _database_connection(path, readonly=True) as connection:
                origins = connection.execute(
                    """SELECT i.kind, io.origin_kind, io.is_derived
                       FROM indicator_origins io
                       JOIN indicators i ON i.id = io.indicator_id
                       ORDER BY i.kind"""
                ).fetchall()

        self.assertEqual("ready", result["status"])
        # The URL plus its derived hostname and registrable domain are indexed.
        self.assertEqual(3, result["indicator_count"])
        self.assertEqual(
            [("domain", "url", 1), ("hostname", "url", 1), ("url", "url", 0)],
            [(row["kind"], row["origin_kind"], row["is_derived"]) for row in origins],
        )
        self.assertFalse(result["truncated"])
        self.assertEqual("preparing", progress[0]["phase"])
        self.assertEqual(100, progress[-1]["percentage"])

    def test_sync_adds_exactly_tagged_public_phishing_pulses(self):
        public_id = "0123456789abcdef01234567"

        class Response:
            status_code = 200

            def __init__(self, payload):
                self.payload = payload

            @staticmethod
            def raise_for_status():
                return None

            def json(self):
                return self.payload

        class Session:
            def __init__(self):
                self.headers = {}

            @staticmethod
            def get(url, **_kwargs):
                if url.endswith("/pulses/subscribed"):
                    return Response({"next": None, "results": []})
                if url.endswith("/search/pulses"):
                    return Response({
                        "next": None,
                        "results": [{
                            "id": public_id,
                            "name": "Public phishing campaign",
                            "author_name": "community",
                            "modified": "2999-01-01T00:00:00",
                            "tags": ["Phishing", "fraud"],
                        }],
                    })
                if url.endswith(f"/pulses/{public_id}/indicators"):
                    return Response({
                        "next": None,
                        "results": [{
                            "type": "url",
                            "indicator": "https://guncel.mariobet-resmiadresi.vip/",
                        }],
                    })
                raise AssertionError(f"Unexpected OTX URL: {url}")

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "otx.sqlite3"
            with patch("fishstop_engine.otx_intelligence.requests.Session", Session):
                result = sync_subscribed_pulses(str(path), "test-key")
            report = {"links": [{"url": "https://guncel.mariobet-resmiadresi.vip/", "host": "guncel.mariobet-resmiadresi.vip", "scheme": "https"}], "flags": []}
            apply_local_otx_intelligence(report, str(path))

        self.assertEqual(1, result["public_phishing_pulse_count"])
        self.assertEqual(0, result["subscribed_pulse_count"])
        self.assertEqual("match", report["otx_intelligence"]["status"])

    def test_public_summary_with_omitted_tags_downloads_paginated_indicators(self):
        public_id = "0123456789abcdef01234567"
        indicator_calls = []

        class Response:
            status_code = 200
            headers = {}

            def __init__(self, payload):
                self.payload = payload

            @staticmethod
            def raise_for_status():
                return None

            def json(self):
                return self.payload

        class Session:
            def __init__(self):
                self.headers = {}

            @staticmethod
            def get(url, **kwargs):
                if url.endswith("/pulses/subscribed"):
                    return Response({"next": None, "results": []})
                if url.endswith("/search/pulses"):
                    return Response({
                        "next": None,
                        "results": [{
                            "id": public_id,
                            "name": "Phish feed",
                            "author_name": "community",
                            "modified": "2999-01-01T00:00:00Z",
                            "tags": [],
                        }],
                    })
                if url.endswith(f"/pulses/{public_id}/indicators"):
                    indicator_calls.append(kwargs.get("params"))
                    return Response({
                        "next": (
                            f"https://otx.alienvault.com/api/v1/pulses/{public_id}"
                            "/indicators?page=2"
                        ),
                        "count": 2,
                        "results": [{"type": "domain", "indicator": "first.example"}],
                    })
                if url.endswith("/indicators?page=2"):
                    indicator_calls.append(kwargs.get("params"))
                    return Response({
                        "next": None,
                        "count": 2,
                        "results": [{"type": "domain", "indicator": "second.example"}],
                    })
                raise AssertionError(f"Unexpected OTX URL: {url}")

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "otx.sqlite3"
            with patch("fishstop_engine.otx_intelligence.requests.Session", Session):
                result = sync_subscribed_pulses(str(path), "test-key")

        self.assertEqual(1, result["public_phishing_pulse_count"])
        self.assertEqual(2, result["indicator_count"])
        self.assertEqual(2_000, indicator_calls[0]["limit"])
        self.assertIsNone(indicator_calls[1])

    def test_time_budget_publishes_progress_and_checkpoints_search_page(self):
        class Response:
            status_code = 200
            headers = {}

            @staticmethod
            def raise_for_status():
                return None

            @staticmethod
            def json():
                return {
                    "next": None,
                    "results": [{
                        "id": "0123456789abcdef01234567",
                        "name": "Deferred phishing Pulse",
                        "modified": "2999-01-01T00:00:00Z",
                        "tags": [],
                    }],
                }

        class Session:
            def __init__(self):
                self.headers = {}

            @staticmethod
            def get(*_args, **_kwargs):
                return Response()

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "otx.sqlite3"
            with (
                patch("fishstop_engine.otx_intelligence.requests.Session", Session),
                patch("fishstop_engine.otx_intelligence.PUBLIC_SYNC_SOFT_SECONDS", 0),
            ):
                result = sync_subscribed_pulses(str(path), "test-key")
            with _database_connection(path, readonly=True) as connection:
                resume_url = connection.execute(
                    "SELECT value FROM metadata WHERE key = 'public_search_resume_url'"
                ).fetchone()[0]

        self.assertTrue(result["truncated"])
        self.assertEqual("time", result["limit_reason"])
        self.assertIn("tag%3A%22phishing%22", resume_url)

    def test_public_search_ignores_text_matches_without_exact_phishing_tag(self):
        class Response:
            status_code = 200

            def __init__(self, payload):
                self.payload = payload

            @staticmethod
            def raise_for_status():
                return None

            def json(self):
                return self.payload

        class Session:
            def __init__(self):
                self.headers = {}

            @staticmethod
            def get(url, **_kwargs):
                if url.endswith("/pulses/subscribed"):
                    return Response({"next": None, "results": []})
                if url.endswith("/search/pulses"):
                    return Response({
                        "next": None,
                        "results": [{
                            "id": "0123456789abcdef01234567",
                            "name": "Article mentioning phishing",
                            "modified": "2999-01-01T00:00:00",
                            "tags": ["malware"],
                            "indicators": [{"type": "domain", "indicator": "benign.example"}],
                        }],
                    })
                raise AssertionError(f"Unexpected OTX URL: {url}")

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "otx.sqlite3"
            with patch("fishstop_engine.otx_intelligence.requests.Session", Session):
                result = sync_subscribed_pulses(str(path), "test-key")

        self.assertEqual(0, result["public_phishing_pulse_count"])
        self.assertEqual(0, result["indicator_count"])

    def test_failed_sync_keeps_the_previous_cache(self):
        class Response:
            status_code = 429

        class Session:
            def __init__(self):
                self.headers = {}

            @staticmethod
            def get(*_args, **_kwargs):
                return Response()

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "otx.sqlite3"
            previous_directory, previous_path = self._cache({"domain:kept.example": [PULSE]})
            self.addCleanup(previous_directory.cleanup)
            path.write_bytes(Path(previous_path).read_bytes())
            previous = path.read_bytes()
            with (
                patch("fishstop_engine.otx_intelligence.requests.Session", Session),
                patch("fishstop_engine.otx_intelligence.time.sleep"),
            ):
                with self.assertRaisesRegex(RuntimeError, "rate limit"):
                    sync_subscribed_pulses(str(path), "test-key")
            self.assertEqual(previous, path.read_bytes())

    def test_slow_pulse_details_are_skipped_without_losing_successful_results(self):
        slow_id = "0123456789abcdef01234567"
        ready_id = "89abcdef0123456701234567"

        class Response:
            status_code = 200
            headers = {}

            def __init__(self, payload):
                self.payload = payload

            @staticmethod
            def raise_for_status():
                return None

            def json(self):
                return self.payload

        class Session:
            def __init__(self):
                self.headers = {}

            @staticmethod
            def get(url, **_kwargs):
                if url.endswith("/pulses/subscribed"):
                    return Response({"next": None, "results": []})
                if url.endswith("/search/pulses"):
                    common = {
                        "author_name": "community",
                        "modified": "2999-01-01T00:00:00Z",
                        "tags": ["phishing"],
                    }
                    return Response({
                        "next": None,
                        "results": [
                            {**common, "id": slow_id, "name": "Slow Pulse"},
                            {**common, "id": ready_id, "name": "Ready Pulse"},
                        ],
                    })
                if url.endswith(f"/pulses/{slow_id}/indicators"):
                    raise requests.ReadTimeout("slow details endpoint")
                if url.endswith(f"/pulses/{ready_id}/indicators"):
                    return Response({
                        "next": None,
                        "results": [{
                            "type": "url",
                            "indicator": "https://detected.example/",
                        }],
                    })
                raise AssertionError(f"Unexpected OTX URL: {url}")

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "otx.sqlite3"
            progress = []
            with (
                patch("fishstop_engine.otx_intelligence.requests.Session", Session),
                patch("fishstop_engine.otx_intelligence.time.sleep"),
            ):
                result = sync_subscribed_pulses(str(path), "test-key", progress.append)
            status = otx_cache_status(str(path))
            report = {"links": [{"url": "https://detected.example/", "host": "detected.example", "scheme": "https"}], "flags": []}
            apply_local_otx_intelligence(report, str(path))

        self.assertEqual("ready", result["status"])
        self.assertEqual(1, result["skipped_pulse_count"])
        self.assertEqual(1, status["skipped_pulse_count"])
        self.assertEqual("match", report["otx_intelligence"]["status"])
        indicator_progress = next(
            item for item in progress if item["phase"] == "public_indicators"
        )
        self.assertEqual("current_pulse_indicators", indicator_progress["metric"])
        self.assertEqual(2, indicator_progress["pulse_index"])
        self.assertEqual(2, indicator_progress["pulse_total"])
        self.assertEqual("Ready Pulse", indicator_progress["pulse_name"])

    def test_public_phishing_sync_follows_pagination_within_budget(self):
        class Response:
            status_code = 200
            headers = {}

            def __init__(self, payload):
                self.payload = payload

            @staticmethod
            def raise_for_status():
                return None

            def json(self):
                return self.payload

        class Session:
            def __init__(self):
                self.headers = {}
                self.public_page = 0

            def get(self, url, **_kwargs):
                if url.endswith("/pulses/subscribed"):
                    return Response({"next": None, "results": []})
                if "/search/pulses" in url:
                    self.public_page += 1
                    page = self.public_page
                    return Response({
                        "next": (
                            f"https://otx.alienvault.com/api/v1/search/pulses?page={page + 1}"
                            if page < 2 else None
                        ),
                        "results": [{
                            "id": f"pulse-{page}",
                            "name": f"Phishing page {page}",
                            "author_name": "community",
                            "modified": "2999-01-01T00:00:00Z",
                            "tags": ["phishing"],
                            "indicators": [{"type": "hostname", "indicator": f"page-{page}.example"}],
                        }],
                    })
                raise AssertionError(f"Unexpected OTX URL: {url}")

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "otx.sqlite3"
            with patch("fishstop_engine.otx_intelligence.requests.Session", Session):
                with patch(
                    "fishstop_engine.otx_intelligence.PUBLIC_SEARCH_WINDOW_DAYS",
                    365,
                ):
                    result = sync_subscribed_pulses(str(path), "test-key")

        self.assertEqual(2, result["public_phishing_pulse_count"])
        self.assertEqual(2, result["indicator_count"])
        self.assertFalse(result["truncated"])

    def test_public_search_has_no_fixed_page_budget(self):
        class Response:
            status_code = 200
            headers = {}

            def __init__(self, payload):
                self.payload = payload

            @staticmethod
            def raise_for_status():
                return None

            def json(self):
                return self.payload

        class Session:
            def __init__(self):
                self.headers = {}
                self.public_page = 0

            def get(self, url, **_kwargs):
                if url.endswith("/pulses/subscribed"):
                    return Response({"next": None, "results": []})
                if "/search/pulses" in url:
                    self.public_page += 1
                    page = self.public_page
                    return Response({
                        "count": 3,
                        "next": (
                            "https://otx.alienvault.com/api/v1/search/pulses"
                            f"?page={page + 1}&limit=50"
                            if page < 3 else None
                        ),
                        "results": [{
                            "id": f"pulse-{page}",
                            "name": f"Phishing page {page}",
                            "author_name": "community",
                            "modified": "2999-01-01T00:00:00Z",
                            "tags": ["phishing"],
                            "indicators": [{
                                "type": "hostname",
                                "indicator": f"page-{page}.example",
                            }],
                        }],
                    })
                raise AssertionError(f"Unexpected OTX URL: {url}")

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "otx.sqlite3"
            with patch("fishstop_engine.otx_intelligence.requests.Session", Session):
                with patch(
                    "fishstop_engine.otx_intelligence.PUBLIC_SEARCH_WINDOW_DAYS",
                    365,
                ):
                    result = sync_subscribed_pulses(str(path), "test-key")
            status = otx_cache_status(str(path))

        self.assertEqual(3, result["public_phishing_pulse_count"])
        self.assertFalse(result["truncated"])
        self.assertFalse(status["truncated"])

    def test_public_search_uses_otx_query_syntax_for_the_time_window(self):
        captured_params = []

        class Response:
            status_code = 200
            headers = {}

            @staticmethod
            def raise_for_status():
                return None

            @staticmethod
            def json():
                return {"next": None, "count": 0, "results": []}

        class Session:
            def __init__(self):
                self.headers = {}

            @staticmethod
            def get(url, **kwargs):
                if url.endswith("/search/pulses"):
                    captured_params.append(kwargs.get("params") or {})
                return Response()

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "otx.sqlite3"
            with patch("fishstop_engine.otx_intelligence.requests.Session", Session):
                sync_subscribed_pulses(str(path), "test-key")

        self.assertEqual(53, len(captured_params))
        self.assertEqual(
            'tag:"phishing" AND modified:<7d',
            captured_params[0]["q"],
        )
        self.assertEqual(
            'tag:"phishing" AND modified:>7d AND modified:<14d',
            captured_params[1]["q"],
        )
        self.assertEqual(
            'tag:"phishing" AND modified:>364d AND modified:<365d',
            captured_params[-1]["q"],
        )
        self.assertEqual("-modified", captured_params[0]["sort"])
        self.assertNotIn("modified_since", captured_params[0])

    def test_public_summary_without_supported_iocs_skips_detail_download(self):
        public_id = "0123456789abcdef01234567"

        class Response:
            status_code = 200
            headers = {}

            def __init__(self, payload):
                self.payload = payload

            @staticmethod
            def raise_for_status():
                return None

            def json(self):
                return self.payload

        class Session:
            def __init__(self):
                self.headers = {}

            @staticmethod
            def get(url, **_kwargs):
                if url.endswith("/pulses/subscribed"):
                    return Response({"next": None, "results": []})
                if url.endswith("/search/pulses"):
                    return Response({
                        "next": None,
                        "results": [{
                            "id": public_id,
                            "modified": "2999-01-01T00:00:00Z",
                            "tags": ["phishing"],
                            "indicator_type_counts": {
                                "FileHash-MD5": 20,
                                "FileHash-SHA1": 10,
                            },
                        }],
                    })
                if url.endswith(f"/pulses/{public_id}"):
                    raise AssertionError("Irrelevant Pulse details were downloaded")
                raise AssertionError(f"Unexpected OTX URL: {url}")

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "otx.sqlite3"
            with patch("fishstop_engine.otx_intelligence.requests.Session", Session):
                result = sync_subscribed_pulses(str(path), "test-key")

        self.assertEqual(0, result["public_phishing_pulse_count"])
        self.assertEqual(0, result["indicator_count"])

    def test_unchanged_public_pulse_reuses_local_indicators(self):
        public_id = "0123456789abcdef01234567"

        class Response:
            status_code = 200
            headers = {}

            def __init__(self, payload):
                self.payload = payload

            @staticmethod
            def raise_for_status():
                return None

            def json(self):
                return self.payload

        class Session:
            def __init__(self):
                self.headers = {}

            @staticmethod
            def get(url, **_kwargs):
                if url.endswith("/pulses/subscribed"):
                    return Response({"next": None, "results": []})
                if url.endswith("/search/pulses"):
                    return Response({
                        "next": None,
                        "results": [{
                            "id": public_id,
                            "name": "Cached phishing campaign",
                            "modified": "2026-09-08T10:00:00Z",
                            "tags": ["phishing"],
                        }],
                    })
                if url.endswith(f"/pulses/{public_id}"):
                    raise AssertionError("Unchanged Pulse details were downloaded again")
                raise AssertionError(f"Unexpected OTX URL: {url}")

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "otx.sqlite3"
            with _database_connection(path) as connection:
                _initialize_database(connection)
                _store_pulse(
                    connection,
                    {
                        "id": public_id,
                        "name": "Cached phishing campaign",
                        "modified": "2026-09-08T10:00:00Z",
                        "tags": ["phishing"],
                        "indicators": [{
                            "type": "hostname",
                            "indicator": "cached.example",
                        }],
                    },
                    "public_phishing",
                    datetime(2026, 9, 8, 10, tzinfo=timezone.utc),
                )
                _set_metadata(connection, "synced_at", "2026-09-08T10:00:00Z")
                connection.commit()
            with patch("fishstop_engine.otx_intelligence.requests.Session", Session):
                result = sync_subscribed_pulses(str(path), "test-key")

        self.assertEqual(1, result["public_phishing_pulse_count"])
        self.assertEqual(1, result["indicator_count"])

    def test_sync_prunes_pulses_outside_the_365_day_window(self):
        class Response:
            status_code = 200
            headers = {}

            @staticmethod
            def raise_for_status():
                return None

            @staticmethod
            def json():
                return {"next": None, "results": []}

        class Session:
            def __init__(self):
                self.headers = {}

            @staticmethod
            def get(*_args, **_kwargs):
                return Response()

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "otx.sqlite3"
            with _database_connection(path) as connection:
                _initialize_database(connection)
                _store_pulse(
                    connection,
                    {**PULSE, "modified": "2000-01-01T00:00:00Z", "indicators": [{"type": "domain", "indicator": "expired.example"}]},
                    "public_phishing",
                    datetime(2000, 1, 1, tzinfo=timezone.utc),
                )
                _set_metadata(connection, "synced_at", "2026-09-08T10:00:00Z")
                connection.commit()
            with patch("fishstop_engine.otx_intelligence.requests.Session", Session):
                result = sync_subscribed_pulses(str(path), "test-key")

        self.assertEqual(0, result["pulse_count"])
        self.assertEqual(0, result["indicator_count"])


if __name__ == "__main__":
    unittest.main()
