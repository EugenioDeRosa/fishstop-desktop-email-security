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
from fishstop_engine.analyzer.conversation import (
    apply_conversation_selection,
    inspect_conversation_bytes,
    public_conversation_manifest,
)
from fishstop_engine.analyzer.lookalike import check_lookalike_domains
from fishstop_engine.otx_intelligence import apply_on_demand_otx_intelligence
from fishstop_engine.parser import _sanitize_eml_bytes
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


def _validated_eml_path(path_value: str) -> Path:
    path = Path(path_value).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError("The selected EML file no longer exists.")
    if path.suffix.lower() != ".eml":
        raise ValueError("FishStop supports .eml files only.")
    if path.stat().st_size > MAX_EML_BYTES:
        raise EmailAnalysisLimitError("The EML file exceeds the supported 10 MB limit.")
    return path


def inspect(path_value: str) -> dict[str, Any]:
    path = _validated_eml_path(path_value)
    return _json_safe(public_conversation_manifest(inspect_conversation_bytes(path.read_bytes())))


def analyze(path_value: str) -> dict[str, Any]:
    path = _validated_eml_path(path_value)

    raw = path.read_bytes()
    conversation_manifest = inspect_conversation_bytes(raw)
    selection_value = os.getenv("FISHSTOP_CONVERSATION_SELECTION", "").strip()
    conversation_selection = json.loads(selection_value) if selection_value else None
    normalized_bytes = _sanitize_eml_bytes(raw)
    # Do not write next to the user-selected file: it may be read-only.
    with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as normalized_file:
        normalized_path = Path(normalized_file.name)
        normalized_file.write(normalized_bytes)
    try:
        report = EmlSOCAnalyzer().analyze(str(normalized_path))
    finally:
        normalized_path.unlink(missing_ok=True)
    apply_conversation_selection(report, conversation_manifest, conversation_selection)
    if conversation_selection and conversation_manifest.get("requires_selection"):
        report["lookalike_alerts"] = check_lookalike_domains([
            link for link in report.get("links") or []
            if str(link.get("scheme") or "").lower() in {"http", "https"}
            and link.get("actionable") is not False
        ])
        report["link_context_alerts"] = EmlSOCAnalyzer._assess_link_context(report)
        report["flags"] = EmlSOCAnalyzer._build_flags(report)
        if report.get("selected_target_authentication_scope") == "embedded_unavailable":
            transport_fields = {
                "spf", "dkim", "dmarc", "authentication-results", "received",
                "return-path", "reply-to", "display name",
            }
            report["flags"] = [
                finding for finding in report["flags"]
                if str(finding.get("field") or "").strip().casefold() not in transport_fields
            ]
        report["flags"].insert(0, {
            "level": "INFO",
            "field": "Conversation scope",
            "message": conversation_manifest["technical_scope_message"],
        })
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
                message = "Preparing the final assessment…"
            elif stage == "primary-complete":
                message = "Reviewing important details…"
            elif stage == "verification":
                message = "Reviewing the message context…"
            elif stage == "retry":
                message = "Finalizing the analysis…"
            elif total > 1 and current > 0:
                message = f"The AI model is analyzing email section {current} of {total}…"
            else:
                message = "The AI model is analyzing the complete email…"
            completed_check = 3 if stage == "merge" else 2 if stage == "primary-complete" else None
            _write_analysis_progress(stage, message, completed_check)
        if event.get("status") == "error":
            raise RuntimeError(str(event.get("message") or "Phi-4 analysis failed."))
    if last_event.get("status") != "ok":
        raise RuntimeError("Phi-4 did not return a final result.")
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
            "Usage: main.py [inspect|static|phi4|content-summary|summary] <file>"
        )
    try:
        result = {
            "static": analyze,
            "inspect": inspect,
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
