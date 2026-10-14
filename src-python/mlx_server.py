"""Frozen entry point for FishSTOP's Apple Silicon MLX runtime."""

from __future__ import annotations

import os
import json
import sys
import threading
from pathlib import Path

from huggingface_hub import hf_hub_download, snapshot_download
from mlx_lm.server import main as mlx_server_main
from tqdm.auto import tqdm


class _DownloadProgress(tqdm):
    """Report byte progress as JSON lines for the desktop application."""

    _lock = threading.Lock()
    _base = 0
    _total_bytes = 0

    @classmethod
    def configure(cls, base: int, total: int) -> None:
        with cls._lock:
            cls._base = base
            cls._total_bytes = total

    def update(self, amount: int = 1) -> bool | None:
        result = super().update(amount)
        if self.format_dict.get("unit") == "B" and amount > 0:
            with self._lock:
                completed = min(self._total_bytes, self._base + int(self.n))
                print(
                    json.dumps(
                        {
                            "status": "Downloading Qwen optimized for MLX…",
                            "total": self._total_bytes,
                            "completed": completed,
                        }
                    ),
                    flush=True,
                )
        return result


def main() -> None:
    model = os.getenv(
        "MLX_MODEL",
        "mlx-community/Qwen3-4B-Instruct-2507-4bit",
    )
    if len(sys.argv) == 3 and sys.argv[1] == "--download":
        destination = Path(sys.argv[2]).resolve()
        destination.mkdir(parents=True, exist_ok=True)
        patterns = [
            "*.json",
            "*.model",
            "*.safetensors",
            "*.txt",
            "*.tiktoken",
        ]
        files = snapshot_download(
            repo_id=model,
            allow_patterns=patterns,
            dry_run=True,
        )
        total = sum(file.file_size for file in files)
        completed = 0
        print(
            json.dumps(
                {
                    "status": "Downloading Qwen optimized for MLX…",
                    "total": total,
                    "completed": completed,
                }
            ),
            flush=True,
        )
        for file in files:
            _DownloadProgress.configure(completed, total)
            hf_hub_download(
                repo_id=model,
                filename=file.filename,
                revision=file.commit_hash,
                local_dir=destination,
                tqdm_class=_DownloadProgress,
            )
            completed += file.file_size
            print(
                json.dumps(
                    {
                        "status": "Downloading Qwen optimized for MLX…",
                        "total": total,
                        "completed": completed,
                    }
                ),
                flush=True,
            )
        if not (destination / "config.json").is_file() or not any(
            destination.glob("model*.safetensors")
        ):
            raise SystemExit("The downloaded MLX model is incomplete.")
        return

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
