import json
import unittest
from unittest.mock import Mock, patch

from fishstop_engine.analyzer import llm_context_analyzer as llm
from fishstop_engine.analyzer.llm_context_analyzer import _stream_ollama


class _StreamingResponse:
    def __init__(self, events: list[dict]):
        self.events = events
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def raise_for_status(self):
        return None

    def iter_lines(self, decode_unicode=False):
        self.decode_unicode = decode_unicode
        for event in self.events:
            yield json.dumps(event)

    def close(self):
        self.closed = True


class OllamaTimeoutTests(unittest.TestCase):
    @patch("fishstop_engine.analyzer.llm_context_analyzer.requests.post")
    @patch("fishstop_engine.analyzer.llm_context_analyzer.monotonic")
    def test_stream_has_a_total_deadline_even_while_tokens_arrive(
        self,
        mocked_monotonic: Mock,
        mocked_post: Mock,
    ):
        mocked_monotonic.side_effect = [100.0, 101.0, 111.0]
        response = _StreamingResponse(
            [
                {"message": {"content": "first"}, "done": False},
                {"message": {"content": "late"}, "done": False},
            ]
        )
        mocked_post.return_value = response

        events = list(_stream_ollama([], "test-model", timeout=10))

        self.assertEqual("stream", events[0]["status"])
        self.assertEqual("error", events[-1]["status"])
        self.assertIn("total time budget", events[-1]["message"])
        self.assertEqual("first", events[-1]["text"])
        self.assertTrue(response.closed)
        self.assertEqual((5.0, 10.0), mocked_post.call_args.kwargs["timeout"])

    @patch("fishstop_engine.analyzer.llm_context_analyzer.requests.post")
    @patch("fishstop_engine.analyzer.llm_context_analyzer.monotonic")
    def test_idle_timeout_reports_the_real_phase_and_elapsed_time(
        self,
        mocked_monotonic: Mock,
        mocked_post: Mock,
    ):
        mocked_monotonic.side_effect = [100.0, 190.0]
        mocked_post.side_effect = llm.requests.exceptions.ReadTimeout("no first byte")

        events = list(_stream_ollama([], "test-model", timeout=180))

        self.assertEqual("error", events[-1]["status"])
        self.assertIn("first response", events[-1]["message"])
        self.assertIn("90 seconds", events[-1]["message"])
        self.assertIn("elapsed 90.0s", events[-1]["message"])
        self.assertIn("total request budget 180s", events[-1]["message"])
        self.assertEqual((5.0, 90.0), mocked_post.call_args.kwargs["timeout"])

    @patch("fishstop_engine.analyzer.llm_context_analyzer.requests.post")
    @patch("fishstop_engine.analyzer.llm_context_analyzer.monotonic")
    def test_connection_timeout_is_not_reported_as_the_full_request_budget(
        self,
        mocked_monotonic: Mock,
        mocked_post: Mock,
    ):
        mocked_monotonic.side_effect = [100.0, 105.0]
        mocked_post.side_effect = llm.requests.exceptions.ConnectTimeout("offline")

        events = list(_stream_ollama([], "test-model", timeout=180))

        self.assertEqual("error", events[-1]["status"])
        self.assertIn("5 second connection budget", events[-1]["message"])
        self.assertNotIn("180 seconds", events[-1]["message"])

    @patch("fishstop_engine.analyzer.llm_context_analyzer.requests.post")
    def test_cpu_thread_count_is_forwarded_as_a_request_option(self, mocked_post: Mock):
        mocked_post.return_value = _StreamingResponse([
            {"message": {"content": "{}"}, "done": True},
        ])

        with patch.object(llm, "OLLAMA_NUM_THREAD", 6):
            events = list(_stream_ollama([], "test-model", timeout=10))

        self.assertEqual("ok", events[-1]["status"])
        self.assertEqual(6, mocked_post.call_args.kwargs["json"]["options"]["num_thread"])

    @patch("fishstop_engine.analyzer.llm_context_analyzer.requests.post")
    def test_http_error_includes_ollama_response_detail(self, mocked_post: Mock):
        response = Mock(status_code=400, text='{"error":"invalid keep_alive"}')
        response.json.return_value = {"error": "invalid keep_alive"}
        mocked_post.side_effect = llm.requests.exceptions.HTTPError(response=response)

        events = list(_stream_ollama([], "test-model", timeout=10))

        self.assertEqual("error", events[-1]["status"])
        self.assertEqual("Ollama HTTP 400: invalid keep_alive", events[-1]["message"])


if __name__ == "__main__":
    unittest.main()
