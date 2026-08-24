"""Bounded, in-memory inspection of ZIP and OOXML email attachments."""

from __future__ import annotations

import io
import re
import zipfile
from collections import Counter


MAX_ARCHIVE_DEPTH = 2
MAX_ARCHIVE_ENTRIES = 250
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 50 * 1024 * 1024
MAX_ARCHIVE_MEMBER_READ_BYTES = 2 * 1024 * 1024
MAX_COMPRESSION_RATIO = 100

_ARCHIVE_EXTENSIONS = {"zip", "docx", "xlsx", "pptx", "xlsm", "docm", "pptm"}
_DANGEROUS_EXTENSIONS = {"exe", "dll", "scr", "com", "msi", "lnk", "js", "jse", "vbs", "vbe", "ps1", "bat", "cmd", "hta", "jar", "iso", "img"}
_DECOY_EXTENSIONS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "txt"}
_DDE_RE = re.compile(rb"(?:\bDDE(?:AUTO)?\b|\bCMD\s*\|)", re.IGNORECASE)
_EXTERNAL_REL_RE = re.compile(rb"TargetMode\s*=\s*[\"']External[\"']|Target\s*=\s*[\"'](?:https?:|file:|\\\\)", re.IGNORECASE)
_WEB_URL_RE = re.compile(rb"https?://[^\s<>()\[\]{}\"']+", re.IGNORECASE)


def _extension(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def _is_double_extension(name: str) -> bool:
    parts = [part.lower() for part in name.rsplit("/", 1)[-1].split(".") if part]
    return len(parts) >= 3 and parts[-1] in _DANGEROUS_EXTENSIONS and parts[-2] in _DECOY_EXTENSIONS


def _empty() -> dict:
    return {"is_archive": True, "risk_level": "clean", "entry_count": 0, "total_uncompressed_bytes": 0, "encrypted_entry_count": 0, "nested_archive_count": 0, "findings": [], "urls": [], "summary": "No risky archive structure detected."}


def analyze_archive_security(raw: bytes, filename: str = "", depth: int = 0) -> dict:
    """Inspect archive metadata and selected members without writing them to disk."""
    result = _empty()
    findings: Counter[str] = Counter()
    samples: dict[str, list[str]] = {}

    def add(key: str, sample: str = "") -> None:
        findings[key] += 1
        if sample and len(samples.setdefault(key, [])) < 4:
            samples[key].append(sample[:160])

    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
        entries = archive.infolist()
    except (zipfile.BadZipFile, OSError, RuntimeError) as error:
        return {**result, "risk_level": "medium", "findings": [{"key": "invalid_archive", "severity": "medium", "label": "archive cannot be parsed", "count": 1, "samples": [str(error)[:160]]}], "summary": "Archive could not be parsed safely."}

    result["entry_count"] = len(entries)
    if len(entries) > MAX_ARCHIVE_ENTRIES:
        add("entry_limit", str(len(entries)))
    total_uncompressed = sum(max(0, int(item.file_size)) for item in entries)
    result["total_uncompressed_bytes"] = total_uncompressed
    if total_uncompressed > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
        add("uncompressed_limit", str(total_uncompressed))

    for item in entries[:MAX_ARCHIVE_ENTRIES]:
        name = item.filename.replace("\\", "/")
        if item.is_dir():
            continue
        compressed = max(1, int(item.compress_size))
        if item.file_size / compressed > MAX_COMPRESSION_RATIO and item.file_size > 64 * 1024:
            add("high_compression_ratio", name)
        if item.flag_bits & 0x1:
            result["encrypted_entry_count"] += 1
            add("encrypted_entry", name)
        if "\u202e" in name:
            add("rtl_override", name)
        extension = _extension(name)
        if extension in _DANGEROUS_EXTENSIONS:
            add("dangerous_file", name)
        if _is_double_extension(name):
            add("double_extension", name)
        lowered = name.lower()
        if lowered.endswith("vbaproject.bin") or lowered.endswith("vbadata.xml"):
            add("office_macro", name)
        if lowered.endswith(".rels") and item.file_size <= MAX_ARCHIVE_MEMBER_READ_BYTES:
            try:
                relation_data = archive.read(item)
                if _EXTERNAL_REL_RE.search(relation_data):
                    add("external_relationship", name)
                for value in _WEB_URL_RE.findall(relation_data):
                    url = value.decode("utf-8", errors="ignore")
                    if url and url not in result["urls"]:
                        result["urls"].append(url[:500])
            except (RuntimeError, OSError, zipfile.BadZipFile):
                add("unreadable_member", name)
        if (lowered.endswith((".xml", ".rels", ".txt")) and item.file_size <= MAX_ARCHIVE_MEMBER_READ_BYTES):
            try:
                if _DDE_RE.search(archive.read(item)):
                    add("dde_instruction", name)
            except (RuntimeError, OSError, zipfile.BadZipFile):
                add("unreadable_member", name)
        is_nested = extension in _ARCHIVE_EXTENSIONS
        if is_nested:
            result["nested_archive_count"] += 1
            if depth >= MAX_ARCHIVE_DEPTH:
                add("nested_depth_limit", name)
            elif item.file_size <= MAX_ARCHIVE_MEMBER_READ_BYTES and not (item.flag_bits & 0x1):
                try:
                    nested = analyze_archive_security(archive.read(item), name, depth + 1)
                    for finding in nested.get("findings") or []:
                        if finding.get("severity") in {"high", "critical"}:
                            add("nested_risky_content", name)
                            break
                except (RuntimeError, OSError, zipfile.BadZipFile):
                    add("unreadable_member", name)

    severity = {
        "entry_limit": "high", "uncompressed_limit": "high", "high_compression_ratio": "high",
        "encrypted_entry": "medium", "dangerous_file": "high", "double_extension": "high", "rtl_override": "high",
        "office_macro": "high", "dde_instruction": "high", "external_relationship": "high",
        "nested_risky_content": "high", "nested_depth_limit": "medium", "unreadable_member": "medium",
    }
    labels = {
        "entry_limit": "too many archive entries", "uncompressed_limit": "archive exceeds safe uncompressed size",
        "high_compression_ratio": "high compression ratio / possible zip bomb", "encrypted_entry": "encrypted archive member",
        "dangerous_file": "executable or script member", "double_extension": "double-extension disguised member",
        "rtl_override": "right-to-left override filename", "office_macro": "Office VBA macro project",
        "dde_instruction": "DDE instruction", "external_relationship": "external Office relationship/template",
        "nested_risky_content": "risky content in nested archive", "nested_depth_limit": "nested archive depth limit reached",
        "unreadable_member": "archive member could not be inspected",
    }
    ordered = sorted(findings, key=lambda key: (0 if severity[key] == "high" else 1, key))
    result["findings"] = [{"key": key, "severity": severity[key], "label": labels[key], "count": count, "samples": samples.get(key, [])} for key, count in ((key, findings[key]) for key in ordered)]
    if any(severity[key] == "high" for key in findings):
        result["risk_level"] = "high"
    elif findings:
        result["risk_level"] = "medium"
    result["summary"] = "; ".join(f"{labels[key]} x{findings[key]}" for key in ordered[:5]) or result["summary"]
    result["urls"] = result["urls"][:25]
    return result
