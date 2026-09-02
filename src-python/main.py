"""FishStop desktop analysis engine invoked by the Tauri backend."""

from __future__ import annotations

import json
import hashlib
import importlib.util
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

_IDENTITY_RUNTIME: dict[str, Any] | None = None
IDENTITY_MODEL_ID = "Davlan/distilbert-base-multilingual-cased-ner-hrl"
IDENTITY_MODEL_REVISION = "d421f57d5b1d36b375408588669e9340f9b11a89"


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
        raise FileNotFoundError("The selected EML file no longer exists.")
    if path.suffix.lower() != ".eml":
        raise ValueError("FishStop supports .eml files only.")
    if path.stat().st_size > MAX_EML_BYTES:
        raise EmailAnalysisLimitError("The EML file exceeds the supported 10 MB limit.")

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


def analyze_identity(report_path: str) -> dict[str, Any]:
    """Run local multilingual organisation extraction for impersonation evidence."""
    global _IDENTITY_RUNTIME
    try:
        from transformers import AutoModelForTokenClassification, AutoTokenizer, pipeline
        from fishstop_engine.brand_intelligence import assess_brand_coherence
        from fishstop_engine.identity_analysis import extract_organisations
    except ImportError as error:
        raise RuntimeError(
            "Identity analysis requires AI dependencies. Install src-python/requirements.txt."
        ) from error

    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    if _IDENTITY_RUNTIME is None:
        tokenizer = AutoTokenizer.from_pretrained(IDENTITY_MODEL_ID, revision=IDENTITY_MODEL_REVISION)
        model = AutoModelForTokenClassification.from_pretrained(IDENTITY_MODEL_ID, revision=IDENTITY_MODEL_REVISION)
        model.eval()
        _IDENTITY_RUNTIME = {
            "pipeline": pipeline(
                "token-classification", model=model, tokenizer=tokenizer,
                aggregation_strategy="simple", device=-1,
            ),
        }
    result = extract_organisations(report, _IDENTITY_RUNTIME["pipeline"])
    if result.get("status") == "ok":
        result["coherence"] = assess_brand_coherence(report, result.get("entities") or [])
    result["model"] = f"{IDENTITY_MODEL_ID}@{IDENTITY_MODEL_REVISION}"
    return result


def analyze_phi4(report_path: str) -> dict[str, Any]:
    """Run the original structured Phi-4-mini policy pipeline."""
    from fishstop_engine.analyzer.llm_context_analyzer import stream_phi4_email_analysis

    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    last_event: dict[str, Any] = {}
    for event in stream_phi4_email_analysis(report):
        last_event = event
        if event.get("status") == "error":
            raise RuntimeError(str(event.get("message") or "Phi-4 analysis failed."))
    if last_event.get("status") != "ok":
        raise RuntimeError("Phi-4 did not return a final result.")
    return _json_safe({
        "status": "ok", "analysis": last_event.get("analysis"),
        "backend": last_event.get("backend"), "model": last_event.get("model"),
        "analyzed_sections": last_event.get("analyzed_sections"),
    })


def analyze_summary(report_path: str) -> dict[str, Any]:
    """Generate the plain-language final explanation from completed analysis."""
    from fishstop_engine.analyzer.llm_context_analyzer import generate_analysis_summary

    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    semantic = ((report.get("phi4_analysis") or {}).get("analysis") or report.get("semantic_analysis") or {})
    if not semantic:
        raise RuntimeError("Semantic intent analysis is required before generating the summary.")
    return _json_safe(generate_analysis_summary(report, semantic))


def analyze_content_summary(report_path: str) -> dict[str, Any]:
    """Generate the content-only prose for the Content panel."""
    from fishstop_engine.analyzer.llm_context_analyzer import generate_content_summary

    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    return _json_safe(generate_content_summary(report))


def identity_worker() -> None:
    """Keep the NER weights in memory and handle JSON-line requests."""
    for raw_line in sys.stdin:
        report_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".json", delete=False) as handle:
                handle.write(raw_line)
                report_path = Path(handle.name)
            result = analyze_identity(str(report_path))
            print(json.dumps({"ok": True, "result": result}, ensure_ascii=False), flush=True)
        except Exception as error:
            print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=False), flush=True)
        finally:
            if report_path:
                report_path.unlink(missing_ok=True)


def health_check(component: str | None = None) -> None:
    """Report that the packaged engine can start, optionally checking AI imports."""
    if component not in (None, "identity"):
        raise ValueError(f"Unsupported health-check component: {component}")
    if component == "identity":
        required = ("huggingface_hub", "torch", "transformers")
        missing = [name for name in required if importlib.util.find_spec(name) is None]
        if missing:
            raise RuntimeError(f"Missing identity dependencies: {', '.join(missing)}")
    print(json.dumps({"ok": True, "component": component or "engine"}))


def main() -> None:
    if len(sys.argv) in (2, 3) and sys.argv[1] == "--health":
        health_check(sys.argv[2] if len(sys.argv) == 3 else None)
        return
    if len(sys.argv) == 2 and sys.argv[1] == "identity-worker":
        identity_worker()
        return
    if len(sys.argv) == 2:
        command, value = "static", sys.argv[1]
    elif len(sys.argv) == 3:
        command, value = sys.argv[1], sys.argv[2]
    else:
        raise SystemExit("Usage: main.py [static|identity|phi4|content-summary|summary] <file>")
    try:
        result = {
            "static": analyze,
            "identity": analyze_identity,
            "phi4": analyze_phi4,
            "content-summary": analyze_content_summary,
            "summary": analyze_summary,
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
