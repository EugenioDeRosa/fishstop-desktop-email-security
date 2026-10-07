"""Bounded, local Office inspection. Documents are parsed, never executed."""
from __future__ import annotations

import io
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path

OLE_EXTENSIONS = {"doc", "dot", "xls", "xlt", "ppt", "pps", "pot", "pub"}
OOXML_EXTENSIONS = {"docx", "docm", "dotx", "dotm", "xlsx", "xlsm", "xlsb", "xltx", "xltm", "pptx", "pptm", "ppsx", "ppsm", "potx", "potm"}
OFFICE_EXTENSIONS = OLE_EXTENSIONS | OOXML_EXTENSIONS | {"rtf", "slk"}
MAX_OFFICE_BYTES = 10 * 1024 * 1024
MAX_RESULT_BYTES = 128 * 1024
WORKER_TIMEOUT = 8.0


@dataclass
class OfficeAnalysisBudget:
    """One time/file budget shared by all attachments of an email."""
    max_seconds: float = 20.0
    max_files: int = 5
    elapsed_seconds: float = 0.0
    files_seen: int = 0


def _result(status: str = "ok", summary: str = "No VBA/XLM/DDE indicators detected within the supported checks.") -> dict:
    return {"engine": "oletools", "status": status, "analysis_complete": status == "ok",
            "risk_level": "clean" if status == "ok" else "unknown", "summary": summary,
            "vba_macros": False, "xlm_macros": False, "autoexec": [],
            "suspicious_keywords": [], "iocs": [], "urls": [], "findings": []}


def _bounded_strings(values, limit: int = 20) -> list[str]:
    return list(dict.fromkeys(str(value)[:300] for value in values))[:limit]


def _exact_urls(values) -> list[str]:
    # Never submit a truncated URL to the existing reputation checks.
    return list(dict.fromkeys(str(value) for value in values
                             if re.match(r"(?i)^https?://", str(value)) and len(str(value)) <= 2048))[:25]


def _apply_macro_indicators(result: dict, rows) -> None:
    """Presence is informational; dangerous behavior combinations need review."""
    result["autoexec"] = _bounded_strings(row[1] for row in rows if row[0] == "AutoExec")
    result["suspicious_keywords"] = _bounded_strings(row[1] for row in rows if row[0] == "Suspicious")
    result["iocs"] = _bounded_strings(row[1] for row in rows if row[0] == "IOC")
    result["urls"] = _exact_urls(row[1] for row in rows if row[0] == "IOC")
    if result["vba_macros"]:
        result["findings"].append({"key": "vba_present", "severity": "low", "label": "VBA macros present (presence alone is not proof of malware)"})
    if result["xlm_macros"]:
        result["findings"].append({"key": "xlm_present", "severity": "medium", "label": "Excel 4/XLM macro sheet present"})
    if result["autoexec"]:
        result["findings"].append({"key": "macro_autoexec", "severity": "medium", "label": "Automatic macro entry point", "evidence": ", ".join(result["autoexec"])})
    if result["suspicious_keywords"]:
        execution = any(re.search(r"(?i)(shell|powershell|exec|createobject|wscript|write|download|virtualalloc|createthread|stomp)", keyword) for keyword in result["suspicious_keywords"])
        severity = "high" if execution and result["autoexec"] else "medium"
        result["findings"].append({"key": "macro_behavior", "severity": severity, "label": "Automatic macro with potentially unsafe behavior" if severity == "high" else "Potentially unsafe macro features", "evidence": ", ".join(result["suspicious_keywords"])})


def _finish(result: dict) -> dict:
    ranks = {"clean": 0, "low": 1, "medium": 2, "high": 3}
    if result["findings"]:
        result["risk_level"] = max((f["severity"] for f in result["findings"]), key=lambda value: ranks[value])
        result["summary"] = "; ".join(f["label"] for f in result["findings"])
    if not result["analysis_complete"]:
        if not result["findings"]:
            result["risk_level"] = "unknown"
        result["summary"] += " Office inspection incomplete; absence of indicators is not a clean verdict."
    result["urls"] = _exact_urls(result["urls"])
    return result


def _inspect_file(path: Path) -> dict:
    try:
        import olefile
        from oletools import crypto, msodde, olevba
    except ImportError:
        return _result("unavailable", "Office inspection unavailable: install the project Python requirements.")
    result = _result()
    if crypto.is_encrypted(str(path)):
        return _result("encrypted", "Encrypted Office document: content could not be inspected.")
    with path.open("rb") as stream:
        data_start = stream.read(8)
    if not (olefile.isOleFile(str(path)) or zipfile.is_zipfile(path) or data_start.startswith((b"{\\rtf", b"ID;"))):
        return _result("unsupported", "Office filename does not contain a supported Office document.")
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            if not set(archive.namelist()) & {"word/document.xml", "xl/workbook.xml", "xl/workbook.bin", "ppt/presentation.xml"}:
                return _result("unsupported", "ZIP package does not contain a supported Office document.")
    if data_start.startswith(b"{\\rtf"):
        result["summary"] = "No DDE indicators detected (RTF embedded objects not inspected)."
    parser = None
    try:
        # Disable optional XLM emulation: only static extraction is allowed.
        olevba.XLMDEOBFUSCATOR = False
        if not data_start.startswith(b"{\\rtf"):
            parser = olevba.VBA_Parser(str(path), relaxed=False)
            parser.detect_macros()
            result["vba_macros"] = bool(parser.contains_vba_macros)
            result["xlm_macros"] = bool(parser.contains_xlm_macros)
            _apply_macro_indicators(result, parser.analyze_macros() or [])
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as archive:
                # oletools' BIFF fallback does not detect OOXML XLM sheets.
                if any(re.match(r"(?i)^xl/macrosheets/[^/]+\.(xml|bin)$", name) for name in archive.namelist()):
                    if not result["xlm_macros"]:
                        result["xlm_macros"] = True
                        result["findings"].append({"key": "xlm_present", "severity": "medium", "label": "Excel 4/XLM macro sheet present (formulas not deobfuscated)"})
    except Exception:
        result["status"] = "partial"
        result["analysis_complete"] = False
    finally:
        if parser is not None:
            try:
                parser.close()
            except Exception:
                result["status"] = "partial"
                result["analysis_complete"] = False
    try:
        dde = msodde.process_file(str(path), field_filter_mode=msodde.FIELD_FILTER_DDE)
        if dde and dde.strip():
            commands = _bounded_strings(dde.splitlines(), 8)
            command_launch = bool(re.search(r"(?i)(\bcmd\b|powershell|mshta|wscript|cscript|rundll32)", dde))
            result["findings"].append({"key": "dde", "severity": "high" if command_launch else "medium", "label": "DDE field references a command launcher" if command_launch else "DDE/external data instructions present", "evidence": " | ".join(commands)[:1200]})
            result["urls"].extend(re.findall(r"https?://[^\s\"<>]+", dde, re.I)[:25])
    except Exception:
        result["status"] = "partial"
        result["analysis_complete"] = False
    return _finish(result)


def run_office_worker(input_path: str, output_path: str) -> None:
    try:
        result = _inspect_file(Path(input_path))
    except Exception:
        result = _result("error", "Office parser could not inspect this document.")
    encoded = json.dumps(result, ensure_ascii=True).encode("utf-8")
    if len(encoded) > MAX_RESULT_BYTES:
        encoded = json.dumps(_result("error", "Office parser output exceeded the report limit.")).encode("utf-8")
    Path(output_path).write_bytes(encoded)


def _stop_worker(process: subprocess.Popen) -> None:
    if os.name == "nt":
        # A frozen one-file worker can have a bootloader child; stop that too.
        try:
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            process.kill()
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if process.poll() is None:
        process.kill()
    process.wait(timeout=5)


def analyze_office_security(data: bytes, filename: str, content_type: str = "", budget: OfficeAnalysisBudget | None = None) -> dict | None:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    is_ole = data.startswith(bytes.fromhex("D0CF11E0A1B11AE1"))
    is_rtf = data.startswith(b"{\\rtf")
    is_office_zip = False
    archive = None
    try:
        if zipfile.is_zipfile(io.BytesIO(data)):
            archive = zipfile.ZipFile(io.BytesIO(data))
            is_office_zip = any(name.startswith(("word/", "xl/", "ppt/")) for name in archive.namelist())
        office_mime = content_type.split(";", 1)[0].lower() in {"application/msword", "application/vnd.ms-excel", "application/vnd.ms-powerpoint", "application/rtf", "text/rtf"} or "officedocument" in content_type.lower() or "macroenabled" in content_type.lower()
        if ext not in OFFICE_EXTENSIONS and not (is_ole or is_rtf or is_office_zip or office_mime):
            return None
        if len(data) > MAX_OFFICE_BYTES:
            return _result("skipped", "Office document exceeds the 10 MiB inspection limit.")
        if archive is not None:
            members = archive.infolist()
            if len(members) > 250 or sum(m.file_size for m in members) > 32 * 1024 * 1024 or any(m.file_size > 8 * 1024 * 1024 or m.file_size > max(m.compress_size, 1) * 200 for m in members):
                return _result("skipped", "Office package exceeds safe decompression limits.")
            if any(m.flag_bits & 1 for m in members):
                return _result("encrypted", "Encrypted Office package: content could not be inspected.")
    except (zipfile.BadZipFile, OSError):
        return _result("error", "Invalid Office package.") if ext in OFFICE_EXTENSIONS or is_ole or is_rtf else None
    finally:
        if archive is not None:
            archive.close()
    budget = budget if budget is not None else OfficeAnalysisBudget()
    timeout = min(WORKER_TIMEOUT, budget.max_seconds - budget.elapsed_seconds)
    if budget.files_seen >= budget.max_files or timeout <= 0:
        return _result("skipped", "Shared email Office inspection budget exhausted.")
    budget.files_seen += 1
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix="fishstop-office-") as directory:
            input_path = Path(directory) / ("attachment." + (ext if ext in OFFICE_EXTENSIONS else "doc"))
            output_path = Path(directory) / "result.json"
            input_path.write_bytes(data)
            entrypoint = [] if getattr(sys, "frozen", False) else [str(Path(__file__).resolve().parents[1] / "main.py")]
            options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {"start_new_session": True}
            process = subprocess.Popen([sys.executable, *entrypoint, "--office-scan", str(input_path), str(output_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **options)
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                _stop_worker(process)
                return _result("timeout", "Office inspection timed out; document requires review.")
            if process.returncode != 0 or not output_path.exists() or output_path.stat().st_size > MAX_RESULT_BYTES:
                return _result("error", "Office inspection failed; document requires review.")
            result = json.loads(output_path.read_text(encoding="utf-8"))
            if not isinstance(result, dict) or result.get("engine") != "oletools":
                return _result("error", "Invalid Office inspection response.")
            return result
    except (OSError, ValueError, subprocess.SubprocessError):
        return _result("error", "Office inspection could not run; document requires review.")
    finally:
        budget.elapsed_seconds += time.monotonic() - started
