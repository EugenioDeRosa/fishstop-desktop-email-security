"""Package the FishSTOP Python engine as a platform-specific Tauri sidecar."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENGINE_ENTRYPOINT = ROOT / "src-python" / "main.py"
BINARIES_DIRECTORY = ROOT / "src-tauri" / "binaries"
BUILD_DIRECTORY = ROOT / "build" / "sidecar"


def main() -> None:
    target = os.environ.get("FISHSTOP_TARGET_TRIPLE")
    if not target:
        raise SystemExit("Set FISHSTOP_TARGET_TRIPLE before building the sidecar.")

    is_windows = "windows" in target
    executable_name = "fishstop-engine.exe" if is_windows else "fishstop-engine"
    destination = BINARIES_DIRECTORY / f"fishstop-engine-{target}{'.exe' if is_windows else ''}"

    subprocess.run(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            "--onefile",
            "--name",
            "fishstop-engine",
            "--paths",
            str(ROOT / "src-python"),
            "--collect-submodules",
            "fishstop_engine",
            "--workpath",
            str(BUILD_DIRECTORY / "work"),
            "--distpath",
            str(BUILD_DIRECTORY / "dist"),
            "--specpath",
            str(BUILD_DIRECTORY / "spec"),
            str(ENGINE_ENTRYPOINT),
        ],
        check=True,
    )

    BINARIES_DIRECTORY.mkdir(parents=True, exist_ok=True)
    built_binary = BUILD_DIRECTORY / "dist" / executable_name
    shutil.copy2(built_binary, destination)
    if not is_windows:
        destination.chmod(destination.stat().st_mode | 0o111)
    print(f"Built Tauri sidecar: {destination.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
