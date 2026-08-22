"""FishStop desktop analysis engine invoked by the Tauri backend."""

from __future__ import annotations

import json
import hashlib
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

ENGINE_ROOT = Path(__file__).resolve().parent
if str(ENGINE_ROOT) not in sys.path:
    sys.path.insert(0, str(ENGINE_ROOT))

from fishstop_engine.analysis_limits import EmailAnalysisLimitError, MAX_EML_BYTES
from fishstop_engine.analyzer import EmlSOCAnalyzer
from fishstop_engine.parser import _sanitize_eml_bytes
from fishstop_engine.reputation import enrich as enrich_reputation

_BERT_RUNTIME: dict[str, Any] | None = None


def _json_safe(value: Any) -> Any:
    """Remove binary-only fields while preserving the full report structure."""
    if isinstance(value, bytes):
        return None
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items() if key != "raw_eml_bytes"}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


def analyze(path_value: str) -> dict[str, Any]:
    path = Path(path_value).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError("Il file EML selezionato non esiste più.")
    if path.suffix.lower() != ".eml":
        raise ValueError("FishStop supporta esclusivamente file .eml.")
    if path.stat().st_size > MAX_EML_BYTES:
        raise EmailAnalysisLimitError("Il file EML supera il limite supportato di 10 MB.")

    raw = path.read_bytes()
    # Do not write next to the user-selected file: it may be read-only.
    with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as normalized_file:
        normalized_path = Path(normalized_file.name)
        normalized_file.write(_sanitize_eml_bytes(raw))
    try:
        report = EmlSOCAnalyzer().analyze(str(normalized_path))
    finally:
        normalized_path.unlink(missing_ok=True)
    report["eml_sha256"] = hashlib.sha256(raw).hexdigest()
    enrich_reputation(
        report,
        os.getenv("VIRUSTOTAL_API_KEY", ""),
        os.getenv("ABUSEIPDB_API_KEY", ""),
    )
    return _json_safe(report)


def analyze_bert(report_path: str) -> dict[str, Any]:
    """Run the calibrated FishStop DistilBERT content classifier."""
    global _BERT_RUNTIME
    try:
        import torch
        from huggingface_hub import hf_hub_download
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        from fishstop_engine.bert_calibration import (
            DEFAULT_BAND, DEFAULT_POSITIVE_LABEL_ID, DEFAULT_TEMPERATURE,
            DEFAULT_THRESHOLD, calibrated_probabilities, classify,
        )
        from fishstop_engine.bert_inference import predict_email_logits
        from fishstop_engine.bert_input import prepare_bert_input
    except ImportError as error:
        raise RuntimeError(
            "BERT richiede le dipendenze AI. Installa src-python/requirements.txt."
        ) from error

    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    model_id = "eugenioderodev/fishstop-bert"
    revision = "b29e3334457d942bb5c05fe8f6639edeccf59692"
    if _BERT_RUNTIME is None:
        tokenizer = AutoTokenizer.from_pretrained(model_id, revision=revision)
        model = AutoModelForSequenceClassification.from_pretrained(model_id, revision=revision)
        model.eval()
        calibration = {
            "temperature": DEFAULT_TEMPERATURE, "threshold": DEFAULT_THRESHOLD,
            "band": DEFAULT_BAND, "positive_label_id": DEFAULT_POSITIVE_LABEL_ID,
            "source": "default",
        }
        try:
            calibration_path = hf_hub_download(repo_id=model_id, filename="calibration.json", revision=revision)
            calibration.update(json.loads(Path(calibration_path).read_text(encoding="utf-8")))
            calibration["source"] = "huggingface"
        except Exception:
            pass
        _BERT_RUNTIME = {"tokenizer": tokenizer, "model": model, "calibration": calibration}
    tokenizer = _BERT_RUNTIME["tokenizer"]
    model = _BERT_RUNTIME["model"]
    calibration = _BERT_RUNTIME["calibration"]
    text = prepare_bert_input(
        str(report.get("subject") or ""),
        str(report.get("body_for_ai") or report.get("body_ai") or report.get("body_clean") or ""),
    )
    if not text:
        return {"status": "skipped", "message": "Nessun testo utile per l'analisi BERT."}
    positive_label_id = int(calibration.get("positive_label_id", 1))
    logits, chunk_count = predict_email_logits(model, tokenizer, text, positive_label_id=positive_label_id)
    probabilities = calibrated_probabilities(logits, float(calibration["temperature"])).flatten().tolist()
    negative_label_id = 1 - positive_label_id
    return {
        "status": "ok",
        "classification": classify(probabilities[positive_label_id], float(calibration["threshold"]), float(calibration["band"])),
        "probability_legitimate": probabilities[negative_label_id] * 100,
        "probability_malicious": probabilities[positive_label_id] * 100,
        "chunk_count": chunk_count,
        "model": f"{model_id}@{revision}",
        "calibration": calibration,
    }


def analyze_phi4(report_path: str) -> dict[str, Any]:
    """Run the original structured Phi-4-mini policy pipeline."""
    from fishstop_engine.analyzer.llm_context_analyzer import stream_phi4_email_analysis

    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    last_event: dict[str, Any] = {}
    for event in stream_phi4_email_analysis(report):
        last_event = event
        if event.get("status") == "error":
            raise RuntimeError(str(event.get("message") or "Analisi Phi-4 non riuscita."))
    if last_event.get("status") != "ok":
        raise RuntimeError("Phi-4 non ha restituito un risultato finale.")
    return _json_safe({
        "status": "ok", "analysis": last_event.get("analysis"),
        "backend": last_event.get("backend"), "model": last_event.get("model"),
        "analyzed_sections": last_event.get("analyzed_sections"),
    })


def bert_worker() -> None:
    """Keep the BERT weights in memory and handle JSON-line requests."""
    for raw_line in sys.stdin:
        report_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".json", delete=False) as handle:
                handle.write(raw_line)
                report_path = Path(handle.name)
            result = analyze_bert(str(report_path))
            print(json.dumps({"ok": True, "result": result}, ensure_ascii=False), flush=True)
        except Exception as error:
            print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=False), flush=True)
        finally:
            if report_path:
                report_path.unlink(missing_ok=True)


def main() -> None:
    if len(sys.argv) == 2 and sys.argv[1] == "bert-worker":
        bert_worker()
        return
    if len(sys.argv) == 2:
        command, value = "static", sys.argv[1]
    elif len(sys.argv) == 3:
        command, value = sys.argv[1], sys.argv[2]
    else:
        raise SystemExit("Uso: main.py [static|bert|phi4] <file>")
    try:
        result = {
            "static": analyze,
            "bert": analyze_bert,
            "phi4": analyze_phi4,
        }.get(command)
        if result is None:
            raise ValueError(f"Comando sconosciuto: {command}")
        payload = result(value)
        key = "report" if command == "static" else "result"
        print(json.dumps({"ok": True, key: payload}, ensure_ascii=False))
    except Exception as error:
        print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=False))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
