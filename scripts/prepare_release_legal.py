"""Collect installed Python notices and archive tracked release sources only."""
from __future__ import annotations

import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def cargo_metadata() -> dict:
    # Cargo emits UTF-8 JSON. Parse bytes directly instead of using the Windows
    # locale (which may be cp1252 and cannot decode some dependency notices).
    return json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--format-version=1"],
        cwd=ROOT / "src-tauri",
    ))


def main() -> None:
    target = os.environ["FISHSTOP_TARGET_TRIPLE"]
    legal = ROOT / "src-tauri" / "resources" / "legal"
    legal.mkdir(parents=True, exist_ok=True)
    for name in ("LICENSE", "COPYRIGHT", "THIRD_PARTY_NOTICES.md"):
        shutil.copyfile(ROOT / name, legal / name)
    inventory = []
    for distribution in sorted(importlib.metadata.distributions(), key=lambda d: d.metadata["Name"].lower()):
        name = distribution.metadata["Name"]
        notices = []
        for entry in distribution.files or []:
            if any(part.lower().startswith(("license", "copying", "notice")) for part in Path(str(entry)).parts):
                source = Path(distribution.locate_file(entry))
                if not source.is_file():
                    continue
                destination = legal / "python" / name / str(entry)
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
                notices.append(destination.relative_to(legal).as_posix())
        inventory.append({"name": name, "version": distribution.version,
                          "license": distribution.metadata.get("License-Expression") or distribution.metadata.get("License"),
                          "notices": notices})
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    (legal / f"python-inventory-{target}.json").write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
    frontend_inventory = []
    lock = json.loads((ROOT / "package-lock.json").read_text(encoding="utf-8"))
    for relative, package in lock["packages"].items():
        if not relative:
            continue
        directory = ROOT / relative
        if not directory.is_dir():
            continue  # Platform-specific optional packages may not be installed.
        frontend_inventory.append({"package": relative, "version": package.get("version"),
                                   "license": package.get("license")})
        for source in directory.iterdir():
            if source.is_file() and source.name.lower().startswith(("license", "copying", "notice")):
                destination = legal / "frontend" / relative / source.name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
    (legal / f"frontend-inventory-{target}.json").write_text(json.dumps(frontend_inventory, indent=2) + "\n", encoding="utf-8")
    if os.environ.get("FISHSTOP_COLLECT_RUST_NOTICES") == "1":
        metadata = cargo_metadata()
        rust_inventory = []
        for package in metadata["packages"]:
            if not package.get("source"):
                continue
            rust_inventory.append({"name": package["name"], "version": package["version"],
                                   "license": package.get("license"), "source": package["source"]})
            directory = Path(package["manifest_path"]).parent
            for source in directory.iterdir():
                if source.is_file() and source.name.lower().startswith(("license", "copying", "notice")):
                    destination = legal / "rust" / f"{package['name']}-{package['version']}" / source.name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, destination)
        (legal / f"rust-inventory-{target}.json").write_text(json.dumps(rust_inventory, indent=2) + "\n", encoding="utf-8")
    (legal / "SOURCE.txt").write_text(
        f"FishStop source revision: {revision}\n"
        f"https://github.com/EugenioDeRosa/fishstop-desktop-email-security/tree/{revision}\n"
        "Release source archive and dependency inventories are provided beside the installers.\n"
        "See docs/distribution-licensing.md for build instructions and third-party source obligations.\n",
        encoding="utf-8",
    )
    build = ROOT / "build"
    build.mkdir(exist_ok=True)
    subprocess.run(["git", "archive", "--format=zip", f"--prefix=fishstop-{revision[:12]}/",
                    f"--output={build / 'fishstop-source.zip'}", revision], cwd=ROOT, check=True)
    shutil.make_archive(str(build / f"fishstop-notices-{target}"), "zip", legal)
    print(f"Prepared legal notices and tracked source archive for {target}.")


if __name__ == "__main__":
    main()
