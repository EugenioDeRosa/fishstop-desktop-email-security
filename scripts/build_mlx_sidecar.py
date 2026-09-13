"""Package the native Apple Silicon MLX server for the Tauri application."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / "src-python" / "mlx_server.py"
BUILD_DIRECTORY = ROOT / "build" / "mlx-sidecar"
TARGET = "aarch64-apple-darwin"
DESTINATION = ROOT / "src-tauri" / "resources" / "mlx" / TARGET / "fishstop-mlx"


def main() -> None:
    target = os.environ.get("FISHSTOP_TARGET_TRIPLE", TARGET)
    if target != TARGET or sys.platform != "darwin":
        print("Skipping MLX sidecar: it is only bundled for Apple Silicon.")
        return

    subprocess.run(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            "--onefile",
            "--name",
            "fishstop-mlx",
            "--collect-all",
            "mlx",
            "--collect-all",
            "mlx_lm",
            "--collect-submodules",
            "transformers",
            "--collect-submodules",
            "tokenizers",
            "--collect-submodules",
            "huggingface_hub",
            "--workpath",
            str(BUILD_DIRECTORY / "work"),
            "--distpath",
            str(BUILD_DIRECTORY / "dist"),
            "--specpath",
            str(BUILD_DIRECTORY / "spec"),
            str(ENTRYPOINT),
        ],
        check=True,
    )
    DESTINATION.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(BUILD_DIRECTORY / "dist" / "fishstop-mlx", DESTINATION)
    DESTINATION.chmod(DESTINATION.stat().st_mode | 0o111)
    print(f"Built MLX sidecar: {DESTINATION.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
