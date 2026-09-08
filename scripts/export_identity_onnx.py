"""Export FishStop's pinned multilingual NER model to optimized ONNX artifacts."""

from __future__ import annotations

import argparse
import platform
import shutil
from pathlib import Path

from optimum.onnxruntime import ORTModelForTokenClassification, ORTQuantizer
from optimum.onnxruntime.configuration import AutoQuantizationConfig
from transformers import AutoTokenizer


ROOT = Path(__file__).resolve().parents[1]
MODEL_ID = "Davlan/distilbert-base-multilingual-cased-ner-hrl"
MODEL_REVISION = "d421f57d5b1d36b375408588669e9340f9b11a89"
DEFAULT_OUTPUT = ROOT / "build" / "identity-model"


def quantization_config():
    machine = platform.machine().lower()
    if machine in {"arm64", "aarch64"}:
        return AutoQuantizationConfig.arm64(is_static=False, per_channel=True)
    return AutoQuantizationConfig.avx2(is_static=False, per_channel=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    output = args.output.expanduser().resolve()
    fp32_directory = output / "fp32"
    int8_directory = output / "int8"
    if args.force and output.exists():
        shutil.rmtree(output)
    int8_models = list(int8_directory.glob("*.onnx")) if int8_directory.exists() else []
    if int8_models:
        print(f"Identity ONNX model already exists at {int8_directory}")
        return

    output.mkdir(parents=True, exist_ok=True)
    tokenizer = AutoTokenizer.from_pretrained(
        MODEL_ID,
        revision=MODEL_REVISION,
        use_fast=True,
    )
    model = ORTModelForTokenClassification.from_pretrained(
        MODEL_ID,
        revision=MODEL_REVISION,
        export=True,
        provider="CPUExecutionProvider",
    )
    model.save_pretrained(fp32_directory)
    tokenizer.save_pretrained(fp32_directory)

    quantizer = ORTQuantizer.from_pretrained(model)
    quantizer.quantize(
        save_dir=int8_directory,
        quantization_config=quantization_config(),
    )
    tokenizer.save_pretrained(int8_directory)
    print(f"Exported quantized identity model to {int8_directory}")


if __name__ == "__main__":
    main()
