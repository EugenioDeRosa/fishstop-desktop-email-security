"""Bounded, in-memory inspection of ZIP and OOXML email attachments."""

from __future__ import annotations

import io
import re
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from time import monotonic
from urllib.parse import urlsplit
from xml.etree import ElementTree

from fishstop_engine.analysis_limits import (
    MAX_ARCHIVE_ANALYSIS_SECONDS,
    MAX_ARCHIVE_DECOMPRESSED_BYTES,
    MAX_ARCHIVE_DEPTH,
    MAX_ARCHIVE_ENTRIES,
    MAX_ARCHIVE_MEMBER_READ_BYTES,
    MAX_ARCHIVE_UNCOMPRESSED_BYTES,
)

from .constants import DANGEROUS_ATTACHMENT_EXTENSIONS, DECOY_ATTACHMENT_EXTENSIONS


MAX_COMPRESSION_RATIO = 100
_READ_CHUNK_BYTES = 64 * 1024

_ARCHIVE_EXTENSIONS = {"zip", "docx", "xlsx", "pptx", "xlsm", "docm", "pptm"}
_OOXML_EXTENSIONS = {"docx", "xlsx", "pptx", "xlsm", "docm", "pptm"}
_DDE_FIELD_RE = re.compile(r"(?:\bDDE(?:AUTO)?\b|\bCMD\s*\|)", re.IGNORECASE)
_HYPERLINK_FIELD_RE = re.compile(
    r"""\bHYPERLINK\s*(?:\(\s*)?(?:"(?P<double>https?://[^"]+)"|'(?P<single>https?://[^']+)'|(?P<bare>https?://[^\s,;)]+))""",
    re.IGNORECASE,
)

# External hyperlinks and linked images are common in legitimate Office files. They
# are still returned as URLs for the reputation pipeline, but only relationship
# types capable of loading active content are archive-level threats.
_ACTIVE_EXTERNAL_RELATIONSHIP_TYPES = {
    "attachedtemplate",
    "externallinkpath",
    "oleobject",
    "package",
}


@dataclass
class ArchiveAnalysisBudget:
    """Shared resource budget for every archive found in one email."""

    max_entries: int = MAX_ARCHIVE_ENTRIES
    max_uncompressed_bytes: int = MAX_ARCHIVE_UNCOMPRESSED_BYTES
    max_decompressed_bytes: int = MAX_ARCHIVE_DECOMPRESSED_BYTES
    max_depth: int = MAX_ARCHIVE_DEPTH
    max_seconds: float = MAX_ARCHIVE_ANALYSIS_SECONDS
    entries_seen: int = 0
    uncompressed_bytes_seen: int = 0
    decompressed_bytes: int = 0
    archives_seen: int = 0
    exhausted: bool = False
    stop_reason: str = ""
    started_at: float = field(default_factory=monotonic)

    def stop(self, reason: str) -> bool:
        if not self.exhausted:
            self.exhausted = True
            self.stop_reason = reason
        return False

    def check_time(self) -> bool:
        if self.exhausted:
            return False
        if monotonic() - self.started_at >= self.max_seconds:
            return self.stop(
                f"archive analysis exceeded the {self.max_seconds:g} second time budget"
            )
        return True

    def reserve_archive(self, entry_count: int, uncompressed_bytes: int) -> bool:
        if not self.check_time():
            return False
        if self.entries_seen + entry_count > self.max_entries:
            return self.stop(
                "global archive entry budget exceeded "
                f"({self.entries_seen + entry_count} > {self.max_entries})"
            )
        if self.uncompressed_bytes_seen + uncompressed_bytes > self.max_uncompressed_bytes:
            return self.stop(
                "global declared-uncompressed-byte budget exceeded "
                f"({self.uncompressed_bytes_seen + uncompressed_bytes} > "
                f"{self.max_uncompressed_bytes})"
            )
        self.entries_seen += entry_count
        self.uncompressed_bytes_seen += uncompressed_bytes
        self.archives_seen += 1
        return True

    def consume_decompressed(self, amount: int) -> bool:
        if not self.check_time():
            return False
        if self.decompressed_bytes + amount > self.max_decompressed_bytes:
            return self.stop(
                "global archive decompression budget exceeded "
                f"({self.decompressed_bytes + amount} > {self.max_decompressed_bytes})"
            )
        self.decompressed_bytes += amount
        return True

    def snapshot(self) -> dict:
        return {
            "limits": {
                "entries": self.max_entries,
                "uncompressed_bytes": self.max_uncompressed_bytes,
                "decompressed_bytes": self.max_decompressed_bytes,
                "depth": self.max_depth,
                "seconds": self.max_seconds,
            },
            "usage": {
                "archives": self.archives_seen,
                "entries": self.entries_seen,
                "uncompressed_bytes": self.uncompressed_bytes_seen,
                "decompressed_bytes": self.decompressed_bytes,
                "elapsed_ms": max(0, round((monotonic() - self.started_at) * 1000)),
            },
            "exhausted": self.exhausted,
            "stop_reason": self.stop_reason or None,
        }


def _extension(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def _is_double_extension(name: str) -> bool:
    parts = [part.lower() for part in name.rsplit("/", 1)[-1].split(".") if part]
    return (
        len(parts) >= 3
        and parts[-1] in DANGEROUS_ATTACHMENT_EXTENSIONS
        and parts[-2] in DECOY_ATTACHMENT_EXTENSIONS
    )


def _local_xml_name(value: str) -> str:
    return value.rsplit("}", 1)[-1].rsplit("/", 1)[-1].lower()


def _relationship_is_active_external(element: ElementTree.Element) -> bool:
    attributes = {_local_xml_name(key): value for key, value in element.attrib.items()}
    if str(attributes.get("targetmode", "")).lower() != "external":
        return False
    relationship_type = _local_xml_name(str(attributes.get("type", "")))
    if relationship_type not in _ACTIVE_EXTERNAL_RELATIONSHIP_TYPES:
        return False

    target = str(attributes.get("target", "")).strip()
    scheme = urlsplit(target).scheme.lower()
    is_remote = scheme in {"http", "https", "ftp"} or target.startswith(("\\\\", "//"))
    return is_remote


def _inspect_relationships(data: bytes) -> tuple[bool, list[str]]:
    """Return active external-content status and ordinary web targets."""
    try:
        root = ElementTree.fromstring(data)
    except (ElementTree.ParseError, ValueError):
        return False, []

    active_external = False
    urls: list[str] = []
    for element in root.iter():
        if _local_xml_name(element.tag) != "relationship":
            continue
        attributes = {_local_xml_name(key): value for key, value in element.attrib.items()}
        target = str(attributes.get("target", "")).strip()
        if target.lower().startswith(("http://", "https://")) and target not in urls:
            urls.append(target)
        if _relationship_is_active_external(element):
            active_external = True
    return active_external, urls


def _inspect_ooxml_fields(data: bytes) -> tuple[bool, list[str]]:
    """Inspect executable Office fields without treating document prose as code."""
    try:
        root = ElementTree.fromstring(data)
    except (ElementTree.ParseError, ValueError):
        return False, []

    instructions: list[str] = []
    for element in root.iter():
        local_name = _local_xml_name(element.tag)
        if local_name in {"instrtext", "f"} and element.text:
            instructions.append(element.text)
        for key, value in element.attrib.items():
            if _local_xml_name(key) == "instr":
                instructions.append(str(value))

    combined = " ".join(instructions)
    urls: list[str] = []
    for match in _HYPERLINK_FIELD_RE.finditer(combined):
        url = next((value for value in match.groupdict().values() if value), "")
        if url and url not in urls:
            urls.append(url)
    return bool(_DDE_FIELD_RE.search(combined)), urls


def _empty() -> dict:
    return {
        "is_archive": True,
        "risk_level": "clean",
        "entry_count": 0,
        "inspected_entry_count": 0,
        "total_uncompressed_bytes": 0,
        "encrypted_entry_count": 0,
        "nested_archive_count": 0,
        "analysis_complete": True,
        "budget_exhausted": False,
        "stop_reason": None,
        "budget": {},
        "findings": [],
        "urls": [],
        "summary": "No risky archive structure detected.",
    }


def _read_member(
    archive: zipfile.ZipFile,
    item: zipfile.ZipInfo,
    budget: ArchiveAnalysisBudget,
) -> bytes | None:
    """Read one member once, checking the shared byte/time budget per chunk."""
    if item.file_size > MAX_ARCHIVE_MEMBER_READ_BYTES:
        return None
    data = bytearray()
    with archive.open(item, "r") as member:
        while True:
            if not budget.check_time():
                return None
            remaining = MAX_ARCHIVE_MEMBER_READ_BYTES - len(data)
            chunk = member.read(min(_READ_CHUNK_BYTES, remaining + 1))
            if not chunk:
                break
            if len(data) + len(chunk) > MAX_ARCHIVE_MEMBER_READ_BYTES:
                budget.stop(
                    f"archive member '{item.filename}' exceeded the per-member read limit"
                )
                return None
            if not budget.consume_decompressed(len(chunk)):
                return None
            data.extend(chunk)
    return bytes(data)


def _finalize(
    result: dict,
    findings: Counter[str],
    samples: dict[str, list[str]],
    budget: ArchiveAnalysisBudget,
) -> dict:
    severity = {
        "entry_limit": "high",
        "uncompressed_limit": "high",
        "decompression_limit": "high",
        "analysis_time_limit": "high",
        "global_budget_exhausted": "high",
        "high_compression_ratio": "high",
        "encrypted_entry": "medium",
        "dangerous_file": "high",
        "double_extension": "high",
        "rtl_override": "high",
        "office_macro": "high",
        "dde_instruction": "high",
        "external_relationship": "high",
        "nested_risky_content": "high",
        "nested_depth_limit": "high",
        "member_read_limit": "medium",
        "unreadable_member": "medium",
    }
    labels = {
        "entry_limit": "too many archive entries",
        "uncompressed_limit": "archive exceeds safe uncompressed size",
        "decompression_limit": "archive decompression byte budget reached",
        "analysis_time_limit": "archive analysis time budget reached",
        "global_budget_exhausted": "archive analysis stopped immediately at the global safety budget",
        "high_compression_ratio": "high compression ratio / possible zip bomb",
        "encrypted_entry": "encrypted archive member",
        "dangerous_file": "executable or script member",
        "double_extension": "double-extension disguised member",
        "rtl_override": "right-to-left override filename",
        "office_macro": "Office VBA macro project",
        "dde_instruction": "DDE instruction",
        "external_relationship": "active external Office content/template",
        "nested_risky_content": "risky content in nested archive",
        "nested_depth_limit": "nested archive depth budget reached",
        "member_read_limit": "archive member exceeds the safe inspection size",
        "unreadable_member": "archive member could not be inspected",
    }

    if budget.exhausted:
        findings["global_budget_exhausted"] = max(
            1, findings["global_budget_exhausted"]
        )
        if budget.stop_reason and not samples.get("global_budget_exhausted"):
            samples["global_budget_exhausted"] = [budget.stop_reason[:160]]
        reason = budget.stop_reason.lower()
        if "entry budget" in reason:
            findings["entry_limit"] = max(1, findings["entry_limit"])
        elif "declared-uncompressed" in reason:
            findings["uncompressed_limit"] = max(1, findings["uncompressed_limit"])
        elif "decompression budget" in reason:
            findings["decompression_limit"] = max(1, findings["decompression_limit"])
        elif "time budget" in reason:
            findings["analysis_time_limit"] = max(1, findings["analysis_time_limit"])

    ordered = sorted(
        findings,
        key=lambda key: (0 if severity.get(key) == "high" else 1, key),
    )
    result["findings"] = [
        {
            "key": key,
            "severity": severity[key],
            "label": labels[key],
            "count": findings[key],
            "samples": samples.get(key, []),
        }
        for key in ordered
    ]
    if any(severity[key] == "high" for key in findings):
        result["risk_level"] = "high"
    elif findings:
        result["risk_level"] = "medium"
    result["analysis_complete"] = not budget.exhausted
    result["budget_exhausted"] = budget.exhausted
    result["stop_reason"] = budget.stop_reason or None
    result["budget"] = budget.snapshot()
    result["summary"] = (
        "; ".join(f"{labels[key]} x{findings[key]}" for key in ordered[:5])
        or result["summary"]
    )
    result["urls"] = result["urls"][:25]
    return result


def analyze_archive_security(
    raw: bytes,
    filename: str = "",
    depth: int = 0,
    budget: ArchiveAnalysisBudget | None = None,
) -> dict:
    """Inspect an archive under one shared, fail-closed resource budget."""
    budget = budget or ArchiveAnalysisBudget()
    result = _empty()
    findings: Counter[str] = Counter()
    samples: dict[str, list[str]] = {}

    def add(key: str, sample: str = "") -> None:
        findings[key] += 1
        if sample and len(samples.setdefault(key, [])) < 4:
            samples[key].append(sample[:160])

    if not budget.check_time():
        return _finalize(result, findings, samples, budget)
    if depth > budget.max_depth:
        add("nested_depth_limit", filename)
        budget.stop(f"archive nesting depth exceeded ({depth} > {budget.max_depth})")
        return _finalize(result, findings, samples, budget)

    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
        entries = archive.infolist()
    except (zipfile.BadZipFile, OSError, RuntimeError) as error:
        result.update(
            {
                "risk_level": "medium",
                "findings": [
                    {
                        "key": "invalid_archive",
                        "severity": "medium",
                        "label": "archive cannot be parsed",
                        "count": 1,
                        "samples": [str(error)[:160]],
                    }
                ],
                "summary": "Archive could not be parsed safely.",
                "budget": budget.snapshot(),
            }
        )
        return result

    with archive:
        result["entry_count"] = len(entries)
        total_uncompressed = sum(max(0, int(item.file_size)) for item in entries)
        result["total_uncompressed_bytes"] = total_uncompressed

        if len(entries) > budget.max_entries:
            add("entry_limit", str(len(entries)))
        if total_uncompressed > budget.max_uncompressed_bytes:
            add("uncompressed_limit", str(total_uncompressed))
        if not budget.reserve_archive(len(entries), total_uncompressed):
            return _finalize(result, findings, samples, budget)

        for item in entries:
            if not budget.check_time():
                break
            result["inspected_entry_count"] += 1
            name = item.filename.replace("\\", "/")
            if item.is_dir():
                continue
            compressed = max(1, int(item.compress_size))
            if item.file_size / compressed > MAX_COMPRESSION_RATIO and item.file_size > 64 * 1024:
                add("high_compression_ratio", name)
                budget.stop(f"possible ZIP bomb detected at archive member '{name}'")
                break
            if item.flag_bits & 0x1:
                result["encrypted_entry_count"] += 1
                add("encrypted_entry", name)
            if "\u202e" in name:
                add("rtl_override", name)
            extension = _extension(name)
            if extension in DANGEROUS_ATTACHMENT_EXTENSIONS:
                add("dangerous_file", name)
            if _is_double_extension(name):
                add("double_extension", name)
            lowered = name.lower()
            if lowered.endswith("vbaproject.bin") or lowered.endswith("vbadata.xml"):
                add("office_macro", name)

            is_nested = extension in _ARCHIVE_EXTENSIONS
            needs_text = lowered.endswith((".xml", ".rels", ".txt"))
            member_data: bytes | None = None
            if (needs_text or is_nested) and not (item.flag_bits & 0x1):
                if item.file_size > MAX_ARCHIVE_MEMBER_READ_BYTES:
                    add("member_read_limit", name)
                else:
                    try:
                        member_data = _read_member(archive, item, budget)
                    except (RuntimeError, OSError, zipfile.BadZipFile):
                        add("unreadable_member", name)
                    if budget.exhausted:
                        break

            if member_data is not None and lowered.endswith(".rels"):
                active_external, relationship_urls = _inspect_relationships(member_data)
                if active_external:
                    add("external_relationship", name)
                for url in relationship_urls:
                    if url and url not in result["urls"]:
                        result["urls"].append(url[:500])
            if (
                member_data is not None
                and _extension(filename) in _OOXML_EXTENSIONS
                and lowered.endswith(".xml")
            ):
                has_dde_field, field_urls = _inspect_ooxml_fields(member_data)
                if has_dde_field:
                    add("dde_instruction", name)
                for url in field_urls:
                    if url not in result["urls"]:
                        result["urls"].append(url[:500])

            if is_nested:
                result["nested_archive_count"] += 1
                if depth >= budget.max_depth:
                    add("nested_depth_limit", name)
                    budget.stop(
                        f"archive nesting depth budget reached at member '{name}'"
                    )
                    break
                if member_data is not None:
                    nested = analyze_archive_security(
                        member_data,
                        name,
                        depth + 1,
                        budget,
                    )
                    if any(
                        finding.get("severity") in {"high", "critical"}
                        for finding in nested.get("findings") or []
                    ):
                        add("nested_risky_content", name)
                    if budget.exhausted:
                        break

    return _finalize(result, findings, samples, budget)
