"""Run FishSTOP's experimental MLX backend on Apple Silicon."""

from __future__ import annotations

import os
import platform
import sys


MODEL = os.getenv(
    "MLX_MODEL",
    "mlx-community/Qwen3-4B-Instruct-2507-4bit",
)
HOST = "127.0.0.1"
PORT = "11436"


def main() -> None:
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise SystemExit("The experimental MLX backend requires Apple Silicon.")
    try:
        import mlx_lm  # noqa: F401
    except ImportError as error:
        raise SystemExit(
            "MLX-LM is not installed in this interpreter. Create .venv-mlx and "
            "install src-python/requirements-mlx.txt first."
        ) from error

    command = [
        sys.executable,
        "-m",
        "mlx_lm",
        "server",
        "--model",
        MODEL,
        "--host",
        HOST,
        "--port",
        PORT,
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
        "INFO",
    ]
    # Replace this lightweight launcher with MLX itself. This keeps a single
    # process for the desktop app to own and guarantees that stopping it also
    # releases the model's unified memory.
    os.execv(sys.executable, command)


if __name__ == "__main__":
    main()
