import json
import unittest
from unittest.mock import patch

from fishstop_engine.analyzer import llm_context_analyzer as llm


class _StreamingResponse:
    status_code = 200

    def __init__(self, events):
        self.events = events

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def raise_for_status(self):
        return None

    def close(self):
        return None

    def iter_lines(self, decode_unicode=False):
        del decode_unicode
        for event in self.events:
            if event == "[DONE]":
                yield "data: [DONE]"
            else:
                yield "data: " + json.dumps(event)


class MlxBackendTests(unittest.TestCase):
    def test_mlx_stream_is_adapted_to_the_existing_pipeline_protocol(self):
        response = _StreamingResponse([
            {
                "choices": [{"delta": {"content": '{"action":'}}],
            },
            {
                "choices": [{"delta": {"content": '"none"}'}}],
                "usage": {"prompt_tokens": 41, "completion_tokens": 5},
            },
            "[DONE]",
        ])
        telemetry = []
        with (
            patch.object(llm, "LLM_PROVIDER", "mlx"),
            patch.object(llm.requests, "post", return_value=response) as post,
        ):
            events = list(llm._stream_ollama(
                [{"role": "user", "content": "test"}],
                llm.OLLAMA_MODEL,
                10,
                request_stage="primary:1",
                telemetry=telemetry,
                num_predict=32,
            ))

        self.assertEqual(events[-1]["status"], "ok")
        self.assertEqual(events[-1]["backend"], "mlx")
        self.assertEqual(events[-1]["text"], '{"action":"none"}')
        self.assertEqual(telemetry[0]["prompt_eval_count"], 41)
        self.assertEqual(telemetry[0]["eval_count"], 5)
        payload = post.call_args.kwargs["json"]
        self.assertEqual(payload["model"], llm.MLX_MODEL)
        self.assertEqual(payload["max_tokens"], 32)


if __name__ == "__main__":
    unittest.main()
