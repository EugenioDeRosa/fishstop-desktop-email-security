"""Frozen entry point for FishSTOP's Apple Silicon MLX runtime."""

from __future__ import annotations

import os
import sys

from mlx_lm.server import main as mlx_server_main


def main() -> None:
    model = os.getenv(
        "MLX_MODEL",
        "mlx-community/Qwen3-4B-Instruct-2507-4bit",
    )
    sys.argv = [
        "fishstop-mlx",
        "--model",
        model,
        "--host",
        "127.0.0.1",
        "--port",
        "11436",
        "--allowed-origins",
        "http://127.0.0.1",
        "--max-tokens",
        "320",
        "--prefill-step-size",
        "2048",
        "--prompt-cache-size",
        "8",
        "--decode-concurrency",
        "1",
        "--prompt-concurrency",
        "1",
        "--log-level",
        "WARNING",
    ]
    mlx_server_main()


if __name__ == "__main__":
    main()
