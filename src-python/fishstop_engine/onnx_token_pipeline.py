"""Small ONNX Runtime token-classification adapter used by the identity NER."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np
import onnxruntime as ort


class OnnxTokenClassificationPipeline:
    """Expose the subset of the Transformers pipeline API FishStop needs.

    Keeping inference here avoids coupling the packaged sidecar to Optimum's
    dynamic imports.  The tokenizer still comes from Transformers, while ONNX
    Runtime executes the quantized encoder directly.
    """

    def __init__(self, model_directory: Path, tokenizer: Any) -> None:
        model_files = sorted(model_directory.glob("*.onnx"))
        if not model_files:
            raise FileNotFoundError(f"No ONNX model found in {model_directory}")

        config = json.loads((model_directory / "config.json").read_text(encoding="utf-8"))
        self._labels = {int(key): str(value) for key, value in config["id2label"].items()}
        self._tokenizer = tokenizer
        self._session = ort.InferenceSession(
            str(model_files[0]),
            providers=["CPUExecutionProvider"],
        )
        self._input_names = {item.name for item in self._session.get_inputs()}

    @staticmethod
    def _softmax_confidence(logits: np.ndarray, index: int) -> float:
        shifted = logits - np.max(logits)
        probabilities = np.exp(shifted) / np.exp(shifted).sum()
        return float(probabilities[index])

    def __call__(self, text: str) -> list[dict[str, Any]]:
        encoded = self._tokenizer(
            text,
            return_offsets_mapping=True,
            return_special_tokens_mask=True,
            return_tensors="np",
            truncation=True,
            max_length=512,
        )
        offsets = encoded.pop("offset_mapping")[0]
        special_tokens = encoded.pop("special_tokens_mask")[0]
        feed = {
            key: np.asarray(value, dtype=np.int64)
            for key, value in encoded.items()
            if key in self._input_names
        }
        logits = self._session.run(["logits"], feed)[0][0]

        token_entities: list[dict[str, Any]] = []
        for position, token_logits in enumerate(logits):
            if special_tokens[position]:
                continue
            label_index = int(np.argmax(token_logits))
            label = self._labels.get(label_index, "O")
            start, end = (int(value) for value in offsets[position])
            if label == "O" or end <= start:
                continue
            prefix, _, entity_type = label.partition("-")
            token_entities.append({
                "position": position,
                "prefix": prefix,
                "entity_group": entity_type or label,
                "score": self._softmax_confidence(token_logits, label_index),
                "start": start,
                "end": end,
            })

        grouped: list[dict[str, Any]] = []
        for token in token_entities:
            previous = grouped[-1] if grouped else None
            continues_previous = (
                token["prefix"] == "I"
                and previous is not None
                and previous["entity_group"] == token["entity_group"]
                and token["position"] == previous["last_position"] + 1
                and token["start"] >= previous["end"]
            )
            if continues_previous:
                previous["end"] = token["end"]
                previous["last_position"] = token["position"]
                previous["scores"].append(token["score"])
                continue
            grouped.append({
                "entity_group": token["entity_group"],
                "start": token["start"],
                "end": token["end"],
                "last_position": token["position"],
                "scores": [token["score"]],
            })

        return [
            {
                "entity_group": item["entity_group"],
                "score": float(np.mean(item.pop("scores"))),
                "word": text[item["start"]:item["end"]],
                "start": item["start"],
                "end": item["end"],
            }
            for item in grouped
        ]
