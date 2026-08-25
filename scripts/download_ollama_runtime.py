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
TARGET = os.environ["FISHSTOP_TARGET_TRIPLE"]
BASE_URL = f"https://github.com/ollama/ollama/releases/download/{VERSION}/"

if "windows" in TARGET:
    ASSET = "ollama-windows-amd64.zip"
elif "apple-darwin" in TARGET:
    ASSET = "ollama-darwin.tgz"
else:
    raise SystemExit(f"Unsupported Ollama target: {TARGET}")

destination = ROOT / "src-tauri" / "resources" / "ollama" / TARGET
archive = ROOT / "build" / f"{ASSET}"
destination.mkdir(parents=True, exist_ok=True)
archive.parent.mkdir(parents=True, exist_ok=True)
urllib.request.urlretrieve(BASE_URL + ASSET, archive)
if ASSET.endswith(".zip"):
    with zipfile.ZipFile(archive) as bundle:
        bundle.extractall(destination)
else:
    with tarfile.open(archive) as bundle:
        bundle.extractall(destination, filter="data")
if "windows" not in TARGET:
    (destination / "ollama").chmod(0o755)
print(f"Bundled Ollama {VERSION} for {TARGET}")
