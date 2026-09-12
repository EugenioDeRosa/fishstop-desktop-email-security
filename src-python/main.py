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
from fishstop_engine.otx_intelligence import apply_on_demand_otx_intelligence
from fishstop_engine.parser import _sanitize_eml_bytes_with_findings
from fishstop_engine.reputation import enrich as enrich_reputation

def _json_safe(value: Any) -> Any:
    """Remove binary-only fields while preserving the full report structure."""
    if isinstance(value, bytes):
        return None
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items() if key != "raw_eml_bytes"}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


def _json_bytes(payload: Any) -> bytes:
    """Serialize one protocol message as valid UTF-8 bytes."""
    return json.dumps(payload, ensure_ascii=False).encode("utf-8", errors="replace")


def _write_json(payload: Any, *, flush: bool = False) -> None:
    """Write JSON without relying on the platform's text-stream encoding."""
    encoded = _json_bytes(payload) + b"\n"
    binary_stdout = getattr(sys.stdout, "buffer", None)
    if binary_stdout is not None:
        binary_stdout.write(encoded)
        if flush:
            binary_stdout.flush()
        return

    # Some test runners replace stdout with a text-only stream.
    sys.stdout.write(encoded.decode("utf-8"))
    if flush:
        sys.stdout.flush()


def _write_analysis_progress(stage: str, message: str, completed_check: int | None = None) -> None:
    """Send live AI progress on stderr without contaminating the JSON result."""
    payload: dict[str, Any] = {
        "type": "analysis-progress",
        "stage": stage,
        "message": message,
    }
    if completed_check is not None:
        payload["completed_check"] = completed_check
    encoded = _json_bytes(payload) + b"\n"
    binary_stderr = getattr(sys.stderr, "buffer", None)
    if binary_stderr is not None:
        binary_stderr.write(encoded)
        binary_stderr.flush()
        return
    sys.stderr.write(encoded.decode("utf-8"))
    sys.stderr.flush()


def _stdin_lines() -> Any:
    """Read protocol messages as UTF-8 even when Windows uses a legacy code page."""
    binary_stdin = getattr(sys.stdin, "buffer", None)
    if binary_stdin is None:
        yield from sys.stdin
        return
    for raw_line in binary_stdin:
        yield raw_line.decode("utf-8")


def analyze(path_value: str) -> dict[str, Any]:
    path = Path(path_value).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError("The selected EML file no longer exists.")
    if path.suffix.lower() != ".eml":
        raise ValueError("FishStop supports .eml files only.")
    if path.stat().st_size > MAX_EML_BYTES:
        raise EmailAnalysisLimitError("The EML file exceeds the supported 10 MB limit.")

    raw = path.read_bytes()
    normalized_bytes, source_mime_findings = _sanitize_eml_bytes_with_findings(raw)
    # Do not write next to the user-selected file: it may be read-only.
    with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as normalized_file:
        normalized_path = Path(normalized_file.name)
        normalized_file.write(normalized_bytes)
    try:
        report = EmlSOCAnalyzer().analyze(
            str(normalized_path),
            source_mime_findings=source_mime_findings,
        )
    finally:
        normalized_path.unlink(missing_ok=True)
    report["eml_sha256"] = hashlib.sha256(raw).hexdigest()
    enrich_reputation(
        report,
        os.getenv("VIRUSTOTAL_API_KEY", ""),
        os.getenv("ABUSEIPDB_API_KEY", ""),
    )
    apply_on_demand_otx_intelligence(report, os.getenv("OTX_API_KEY", ""))
    return _json_safe(report)


def analyze_phi4(report_path: str) -> dict[str, Any]:
    """Run the original structured Phi-4-mini policy pipeline."""
    from fishstop_engine.analyzer.llm_context_analyzer import stream_phi4_email_analysis

    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    last_event: dict[str, Any] = {}
    for event in stream_phi4_email_analysis(report):
        last_event = event
        if event.get("status") == "progress":
            stage = str(event.get("stage") or "content")
            current = int(event.get("current") or 0)
            total = int(event.get("total") or 0)
            if stage == "merge":
                message = "The AI model finished reading the email and is combining the results…"
            elif stage == "retry":
                message = "The AI model is refining the structured analysis…"
            elif total > 1 and current > 0:
                message = f"The AI model is analyzing email section {current} of {total}…"
            else:
                message = "The AI model is analyzing the complete email…"
            completed_check = 2 if stage == "merge" else None
            _write_analysis_progress(stage, message, completed_check)
        if event.get("status") == "error":
            raise RuntimeError(str(event.get("message") or "Phi-4 analysis failed."))
    if last_event.get("status") != "ok":
        raise RuntimeError("Phi-4 did not return a final result.")
    _write_analysis_progress(
        "identity",
        "Declared identity and domain coherence have been evaluated.",
        3,
    )
    _write_analysis_progress(
        "verdict",
        "The risk policy has produced the final verdict.",
        4,
    )
    return _json_safe({
        "status": "ok", "analysis": last_event.get("analysis"),
        "backend": last_event.get("backend"), "model": last_event.get("model"),
        "analyzed_sections": last_event.get("analyzed_sections"),
        "performance": last_event.get("performance"),
        "identity_analysis": last_event.get("identity_analysis"),
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


def health_check(component: str | None = None) -> None:
    """Report that the packaged engine can start."""
    if component is not None:
        raise ValueError(f"Unsupported health-check component: {component}")
    _write_json({"ok": True, "component": component or "engine"})


def main() -> None:
    if len(sys.argv) in (2, 3) and sys.argv[1] == "--health":
        health_check(sys.argv[2] if len(sys.argv) == 3 else None)
        return
    if len(sys.argv) == 2:
        command, value = "static", sys.argv[1]
    elif len(sys.argv) == 3:
        command, value = sys.argv[1], sys.argv[2]
    else:
        raise SystemExit(
            "Usage: main.py [static|phi4|content-summary|summary] <file>"
        )
    try:
        result = {
            "static": analyze,
            "phi4": analyze_phi4,
            "content-summary": analyze_content_summary,
            "summary": analyze_summary,
        }.get(command)
        if result is None:
            raise ValueError(f"Comando sconosciuto: {command}")
        payload = result(value)
        key = "report" if command == "static" else "result"
        _write_json({"ok": True, key: payload})
    except Exception as error:
        _write_json({"ok": False, "error": str(error)})
        raise SystemExit(1)


if __name__ == "__main__":
    main()
