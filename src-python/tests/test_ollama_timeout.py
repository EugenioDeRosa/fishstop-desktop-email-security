import json
import unittest
from unittest.mock import Mock, patch

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


if __name__ == "__main__":
    unittest.main()
