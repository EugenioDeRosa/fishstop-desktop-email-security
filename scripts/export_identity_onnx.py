"""Export FishStop's pinned multilingual GLiNER model to an ONNX artifact."""

from __future__ import annotations

import argparse
import inspect
import shutil
from pathlib import Path

import torch
from gliner import GLiNER


ROOT = Path(__file__).resolve().parents[1]
MODEL_ID = "urchade/gliner_multi-v2.1"
MODEL_REVISION = "443d26d654e0324125a96bebd8e796c14ff2efe6"
DEFAULT_OUTPUT = ROOT / "build" / "identity-model"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    output = args.output.expanduser().resolve()
    onnx_directory = output / "onnx"
    if args.force and output.exists():
        shutil.rmtree(output)
    onnx_models = list(onnx_directory.glob("*.onnx")) if onnx_directory.exists() else []
    if onnx_models:
        print(f"Identity ONNX model already exists at {onnx_directory}")
        return

    onnx_directory.mkdir(parents=True, exist_ok=True)
    model = GLiNER.from_pretrained(
        MODEL_ID,
        revision=MODEL_REVISION,
        map_location="cpu",
        low_cpu_mem_usage=True,
    )
    # GLiNER 0.2.29 explicitly selects the legacy exporter with ``dynamo``.
    # Torch 2.2.2 (required by macOS Intel) already uses that exporter but does
    # not expose the keyword yet, so discard only that unsupported selector.
    original_export = torch.onnx.export
    if "dynamo" not in inspect.signature(original_export).parameters:
        def compatible_export(*export_args, **export_kwargs):
            export_kwargs.pop("dynamo", None)
            return original_export(*export_args, **export_kwargs)

        torch.onnx.export = compatible_export
    try:
        artifacts = model.export_to_onnx(
            save_dir=onnx_directory,
            onnx_filename="model.onnx",
            quantize=False,
            opset=17,
        )
    finally:
        torch.onnx.export = original_export
    onnx_path = Path(str(artifacts.get("onnx_path") or ""))
    if not onnx_path.is_file():
        raise RuntimeError("GLiNER did not produce the expected ONNX model.")
    print(f"Exported identity model to {onnx_directory}")


if __name__ == "__main__":
    main()
