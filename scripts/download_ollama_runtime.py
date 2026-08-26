"""Fetch the official Ollama CLI runtime used internally by FishSTOP."""
from __future__ import annotations

import os
import shutil
import tarfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = os.getenv("OLLAMA_VERSION", "v0.32.15")
BASE_URL = f"https://github.com/ollama/ollama/releases/download/{VERSION}/"

# The standard Windows archive contains multiple CUDA distributions and is
# several gigabytes after extraction. Bundling all of them makes NSIS/WiX hit
# their installer-size limits. FishSTOP keeps Ollama's CPU runtime (which works
# everywhere) and any compact non-CUDA runtime shipped alongside it.
WINDOWS_OPTIONAL_RUNTIME_PREFIXES = ("cuda_", "mlx_")


def asset_for(target: str) -> str:
    if "windows" in target:
        return "ollama-windows-amd64.zip"
    if "apple-darwin" in target:
        return "ollama-darwin.tgz"
    raise SystemExit(f"Unsupported Ollama target: {target}")


def remove_optional_windows_runtimes(destination: Path) -> list[str]:
    runtime_directory = destination / "lib" / "ollama"
    removed: list[str] = []
    if not runtime_directory.is_dir():
        return removed

    for entry in runtime_directory.iterdir():
        if entry.name.lower().startswith(WINDOWS_OPTIONAL_RUNTIME_PREFIXES):
            if entry.is_dir():
                shutil.rmtree(entry)
            else:
                entry.unlink()
            removed.append(entry.name)
    return sorted(removed)


def directory_size(directory: Path) -> int:
    return sum(path.stat().st_size for path in directory.rglob("*") if path.is_file())


def main() -> None:
    target = os.environ["FISHSTOP_TARGET_TRIPLE"]
    asset = asset_for(target)
    destination = ROOT / "src-tauri" / "resources" / "ollama" / target
    archive = ROOT / "build" / asset

    # Avoid stale accelerator files when this script is rerun locally or from a
    # restored CI workspace.
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    archive.parent.mkdir(parents=True, exist_ok=True)

    urllib.request.urlretrieve(BASE_URL + asset, archive)
    if asset.endswith(".zip"):
        with zipfile.ZipFile(archive) as bundle:
            bundle.extractall(destination)
    else:
        with tarfile.open(archive) as bundle:
            bundle.extractall(destination, filter="data")
    archive.unlink()

    executable = destination / ("ollama.exe" if "windows" in target else "ollama")
    if not executable.is_file():
        raise SystemExit(f"Ollama archive does not contain the expected executable: {executable}")

    removed: list[str] = []
    if "windows" in target:
        removed = remove_optional_windows_runtimes(destination)
    else:
        executable.chmod(0o755)

    size_mib = directory_size(destination) / (1024 * 1024)
    if "windows" in target and size_mib > 900:
        raise SystemExit(
            f"Pruned Windows Ollama runtime is still too large to bundle ({size_mib:.1f} MiB)."
        )
    removed_note = f"; removed optional runtimes: {', '.join(removed)}" if removed else ""
    print(f"Bundled Ollama {VERSION} for {target} ({size_mib:.1f} MiB{removed_note})")


if __name__ == "__main__":
    main()
