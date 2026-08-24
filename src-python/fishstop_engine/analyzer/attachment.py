"""Attachment analysis helpers."""

import hashlib
import io
import re
import zipfile
from collections import Counter
from typing import Optional
from urllib.parse import parse_qsl, unquote, urlparse

from .constants import CONTENT_TYPE_TO_EXT, MAGIC_BYTES
from .archive_analysis import analyze_archive_security

ZIP_CONTAINER_EXTS = {"docx", "xlsx", "pptx", "zip"}

PDF_ANALYSIS_MAX_BYTES = 25 * 1024 * 1024
PDF_OBJECT_WALK_LIMIT = 5000

PDF_RISK_DEFINITIONS: dict[str, dict] = {
    "javascript": {
        "names": {"/JavaScript", "/JS"},
        "label": "embedded JavaScript",
        "severity": "high",
    },
    "open_action": {
        "names": {"/OpenAction"},
        "label": "automatic action on document open",
        "severity": "medium",
    },
    "additional_action": {
        "names": {"/AA"},
        "label": "additional automatic action",
        "severity": "high",
    },
    "launch_action": {
        "names": {"/Launch"},
        "label": "launch action",
        "severity": "critical",
    },
    "embedded_file": {
        "names": {"/EmbeddedFile", "/Filespec", "/EmbeddedFiles"},
        "label": "embedded file or attachment reference",
        "severity": "high",
    },
    "acroform": {
        "names": {"/AcroForm"},
        "label": "interactive form",
        "severity": "low",
    },
    "xfa": {
        "names": {"/XFA"},
        "label": "XFA form content",
        "severity": "high",
    },
    "uri": {
        "names": {"/URI"},
        "label": "external URI action",
        "severity": "low",
    },
    "submit_form": {
        "names": {"/SubmitForm"},
        "label": "form submission action",
        "severity": "high",
    },
    "rich_media": {
        "names": {"/RichMedia", "/Movie", "/Sound", "/3D"},
        "label": "active media content",
        "severity": "high",
    },
    "remote_goto": {
        "names": {"/GoToR", "/GoToE"},
        "label": "remote or embedded go-to action",
        "severity": "low",
    },
    "import_data": {
        "names": {"/ImportData"},
        "label": "external data import action",
        "severity": "high",
    },
    "jbig2": {
        "names": {"/JBIG2Decode"},
        "label": "JBIG2 compressed stream",
        "severity": "low",
    },
    "object_stream": {
        "names": {"/ObjStm", "/XRefStm"},
        "label": "compressed object/xref stream",
        "severity": "info",
    },
    "uri_nested_redirect": {
        "names": set(),
        "label": "URI action with nested redirect URL",
        "severity": "high",
    },
    "uri_tracked_redirect": {
        "names": set(),
        "label": "tracked redirect URI action",
        "severity": "high",
    },
    "public_site_landing": {
        "names": set(),
        "label": "URI action to public site-builder landing page",
        "severity": "high",
    },
}

PDF_NAME_TO_KEY = {
    name: key
    for key, definition in PDF_RISK_DEFINITIONS.items()
    for name in definition["names"]
}


PDF_MALICIOUS_ACTION_KEYS = {
    "javascript",
    "additional_action",
    "launch_action",
    "embedded_file",
    "xfa",
    "submit_form",
    "rich_media",
    "import_data",
    "uri_nested_redirect",
    "uri_tracked_redirect",
    "public_site_landing",
}

PDF_CONTEXT_ONLY_KEYS = {
    "uri",
    "remote_goto",
    "jbig2",
    "object_stream",
    "acroform",
}


def _indicator_keys(indicators: list[dict]) -> set[str]:
    return {str(item.get("key") or "") for item in indicators}


def _indicator_count(indicators: list[dict], key: str) -> int:
    for item in indicators:
        if item.get("key") == key:
            return int(item.get("count") or 0)
    return 0


def _pdf_behavior_findings(indicators: list[dict]) -> list[dict]:
    keys = _indicator_keys(indicators)
    findings: list[dict] = []

    def add(key: str, label: str, severity: str) -> None:
        count = _indicator_count(indicators, key) or 1
        findings.append({"key": key, "label": label, "severity": severity, "count": count})

    if "launch_action" in keys:
        add("launch_action", "launches an external command or file", "critical")
    if "javascript" in keys:
        add("javascript", "contains executable JavaScript", "high")
    if "submit_form" in keys:
        add("submit_form", "submits form data externally", "high")
    if "import_data" in keys:
        add("import_data", "imports external data", "high")
    if "xfa" in keys:
        add("xfa", "contains XFA active form content", "high")
    if "embedded_file" in keys:
        add("embedded_file", "contains embedded file attachment references", "high")
    if "rich_media" in keys:
        add("rich_media", "contains active rich media", "high")
    if "additional_action" in keys:
        add("additional_action", "contains additional automatic actions", "high")
    if "uri_nested_redirect" in keys:
        add("uri_nested_redirect", "contains a URI action with a hidden redirect URL", "high")
    if "uri_tracked_redirect" in keys:
        add("uri_tracked_redirect", "uses tracking or analytics parameters before redirecting", "high")
    if "public_site_landing" in keys:
        add("public_site_landing", "points to a public site-builder landing page", "high")
    if "open_action" in keys and keys & {"javascript", "launch_action", "submit_form", "rich_media", "import_data"}:
        add("open_action", "runs an action when the document opens", "high")

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(findings, key=lambda item: (severity_order.get(item["severity"], 9), item["label"]))


def _risk_level(indicators: list[dict], encrypted: bool, parser_error: str | None, behaviors: list[dict]) -> str:
    if any(item.get("severity") == "critical" for item in behaviors):
        return "critical"
    if behaviors:
        return "high"
    if encrypted or parser_error:
        return "medium"
    if any(item.get("key") in PDF_CONTEXT_ONLY_KEYS for item in indicators):
        return "low"
    return "clean"


PDF_NAME_RE = re.compile(r"/[A-Za-z0-9_.:+#-]+")
PDF_HEX_ESCAPE_RE = re.compile(r"#([0-9A-Fa-f]{2})")
URL_RE = re.compile(rb"https?://|mailto:", re.IGNORECASE)
PDF_URL_TEXT_RE = re.compile(r"https?://[^\s<>()\[\]{}\"']+", re.IGNORECASE)
PDF_OBJECT_RE = re.compile(r"(?P<object>\d+\s+\d+\s+obj)(?P<body>.*?)(?:endobj|$)", re.IGNORECASE | re.DOTALL)
PDF_REDIRECT_PARAM_NAMES = {"url", "u", "uri", "target", "to", "dest", "destination", "redirect", "redirect_uri", "return", "returnurl", "next", "continue", "__url"}
PDF_TRACKING_PARAM_MARKERS = ("uid", "analytics", "track", "click", "pixel", "count", "campaign", "visitor", "session")
PDF_PUBLIC_SITE_LANDING_HOSTS = {"sites.google.com", "forms.gle", "docs.google.com", "forms.office.com"}


def identify_magic_bytes(raw: bytes) -> Optional[str]:
    """Return the format identified by magic bytes, if known."""
    for fmt, signatures in MAGIC_BYTES.items():
        if any(raw.startswith(signature) for signature in signatures):
            return fmt
    return None


def ext_from_filename(filename: str) -> Optional[str]:
    """Extract a lower-case extension from a filename."""
    if "." not in filename:
        return None
    return filename.rsplit(".", 1)[-1].lower()


def _payload_to_bytes(raw_payload) -> tuple[bytes | None, str | None]:
    if raw_payload is None:
        return None, "Attachment payload empty or not decodable"
    if isinstance(raw_payload, bytes):
        return raw_payload, None
    if isinstance(raw_payload, bytearray):
        return bytes(raw_payload), None
    if isinstance(raw_payload, str):
        return raw_payload.encode("utf-8", errors="ignore"), (
            "Attachment payload was not decoded by email parser"
        )
    return None, f"Unsupported attachment payload type: {type(raw_payload).__name__}"


def _decode_pdf_name_escapes(value: str) -> str:
    def repl(match: re.Match) -> str:
        return chr(int(match.group(1), 16))

    return PDF_HEX_ESCAPE_RE.sub(repl, value)


def _add_indicator(counter: Counter, key: str, count: int = 1) -> None:
    if key and count > 0:
        counter[key] += count


def _indicator_list(counter: Counter) -> list[dict]:
    indicators = []
    for key, count in counter.items():
        definition = PDF_RISK_DEFINITIONS.get(key, {})
        indicators.append({
            "key": key,
            "label": definition.get("label", key),
            "severity": definition.get("severity", "info"),
            "count": count,
        })
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(
        indicators,
        key=lambda item: (severity_order.get(item["severity"], 9), -item["count"], item["label"]),
    )


def _decode_url_repeated(value: str) -> str:
    decoded = value
    for _ in range(3):
        next_decoded = unquote(decoded)
        if next_decoded == decoded:
            break
        decoded = next_decoded
    return decoded


def _normalized_host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower().strip(".")
    except Exception:
        return ""


def _is_public_site_landing(url: str) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower().strip(".")
    path = (parsed.path or "").lower()
    if host == "sites.google.com" and path.startswith("/view/"):
        return True
    if host in PDF_PUBLIC_SITE_LANDING_HOSTS - {"sites.google.com", "docs.google.com"}:
        return True
    if host == "docs.google.com" and path.startswith("/forms/"):
        return True
    return False


def _find_nested_redirect_urls(url: str) -> list[str]:
    nested: list[str] = []
    parsed = urlparse(url)
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        decoded_value = _decode_url_repeated(value)
        if name.lower() in PDF_REDIRECT_PARAM_NAMES and decoded_value.lower().startswith(("http://", "https://")):
            nested.append(decoded_value)
        else:
            nested.extend(PDF_URL_TEXT_RE.findall(decoded_value))
    decoded_url = _decode_url_repeated(url)
    if decoded_url != url:
        for nested_url in PDF_URL_TEXT_RE.findall(decoded_url):
            if nested_url != url and nested_url not in nested:
                nested.append(nested_url)
    return nested[:10]


def _has_tracking_params(url: str) -> bool:
    parsed = urlparse(url)
    host_path = f"{parsed.hostname or ''} {parsed.path or ''}".lower()
    query_names = [name.lower() for name, _ in parse_qsl(parsed.query, keep_blank_values=True)]
    if any(marker in host_path for marker in ("analytics", "tracking", "track", "pixel", "count")):
        return True
    return any(any(marker in name for marker in PDF_TRACKING_PARAM_MARKERS) for name in query_names)


def _empty_uri_evidence() -> dict:
    return {
        "url_count": 0,
        "uri_action_url_count": 0,
        "nested_redirect_count": 0,
        "tracked_redirect_count": 0,
        "public_site_landing_count": 0,
        "samples": [],
        "signatures": [],
        "urls": [],
    }


def _uri_evidence_from_action_urls(action_urls: list[dict], url_count: int | None = None) -> dict:
    evidence = _empty_uri_evidence()
    evidence["url_count"] = len(action_urls) if url_count is None else int(url_count)
    evidence["uri_action_url_count"] = len(action_urls)
    seen_details: set[str] = set()
    seen_signatures: set[str] = set()

    for item in action_urls:
        url = str(item.get("url") or "")
        if not url:
            continue
        nested_urls = _find_nested_redirect_urls(url)
        has_redirect = bool(nested_urls)
        has_tracking = _has_tracking_params(url)
        targets = nested_urls or [url]
        for target in [url, *nested_urls]:
            if target not in evidence["urls"]:
                evidence["urls"].append(target)
        has_public_landing = any(_is_public_site_landing(target) for target in targets)
        signature = "|".join([url] + nested_urls)
        if signature in seen_signatures:
            continue
        seen_signatures.add(signature)

        if has_redirect:
            evidence["nested_redirect_count"] += 1
            if has_tracking:
                evidence["tracked_redirect_count"] += 1
        if has_public_landing:
            evidence["public_site_landing_count"] += 1
        if has_redirect or has_public_landing:
            object_label = f"object {item['object']}" if item.get("object") else "PDF URI"
            hosts = [_normalized_host(url)] + [_normalized_host(target) for target in nested_urls]
            hosts = [host for host in hosts if host]
            detail = f"{object_label}: " + " -> ".join(dict.fromkeys(hosts))
            if detail not in seen_details:
                evidence["samples"].append(detail)
                seen_details.add(detail)

    evidence["samples"] = evidence["samples"][:5]
    evidence["signatures"] = sorted(seen_signatures)[:50]
    evidence["urls"] = evidence["urls"][:25]
    return evidence


def _merge_uri_evidence(*items: dict) -> dict:
    merged = _empty_uri_evidence()
    seen_signatures: set[str] = set()
    seen_samples: set[str] = set()
    for item in items:
        if not item:
            continue
        merged["url_count"] += int(item.get("url_count") or 0)
        merged["uri_action_url_count"] += int(item.get("uri_action_url_count") or 0)
        signatures = set(item.get("signatures") or [])
        duplicate = bool(signatures and signatures <= seen_signatures)
        if not duplicate:
            merged["nested_redirect_count"] += int(item.get("nested_redirect_count") or 0)
            merged["tracked_redirect_count"] += int(item.get("tracked_redirect_count") or 0)
            merged["public_site_landing_count"] += int(item.get("public_site_landing_count") or 0)
        seen_signatures.update(signatures)
        for sample in item.get("samples") or []:
            if sample not in seen_samples:
                merged["samples"].append(sample)
                seen_samples.add(sample)
        for url in item.get("urls") or []:
            if url not in merged["urls"]:
                merged["urls"].append(url)
    merged["samples"] = merged["samples"][:5]
    merged["signatures"] = sorted(seen_signatures)[:50]
    merged["urls"] = merged["urls"][:25]
    return merged


def _extract_pdf_uri_evidence(text: str) -> dict:
    all_urls = PDF_URL_TEXT_RE.findall(text)
    action_urls: list[dict] = []
    for match in PDF_OBJECT_RE.finditer(text):
        obj_name = " ".join(match.group("object").split()[:2])
        body = match.group("body")
        if "/URI" not in body:
            continue
        for url in PDF_URL_TEXT_RE.findall(body):
            action_urls.append({"object": obj_name, "url": url})

    if not action_urls:
        action_urls = [{"object": None, "url": url} for url in all_urls]

    return _uri_evidence_from_action_urls(action_urls, url_count=len(all_urls))


def _static_pdf_indicators(raw: bytes) -> tuple[Counter, dict]:
    counter: Counter = Counter()
    raw_text = raw.decode("latin-1", errors="ignore")
    suspicious_name_escapes = len(PDF_HEX_ESCAPE_RE.findall(raw_text))
    text = _decode_pdf_name_escapes(raw_text)
    names = PDF_NAME_RE.findall(text)
    name_counts = Counter(names)

    for name, count in name_counts.items():
        key = PDF_NAME_TO_KEY.get(name)
        if key:
            _add_indicator(counter, key, count)

    uri_count = len(URL_RE.findall(raw))
    uri_evidence = _extract_pdf_uri_evidence(text)
    if uri_evidence["nested_redirect_count"]:
        _add_indicator(counter, "uri_nested_redirect", uri_evidence["nested_redirect_count"])
    if uri_evidence["tracked_redirect_count"]:
        _add_indicator(counter, "uri_tracked_redirect", uri_evidence["tracked_redirect_count"])
    if uri_evidence["public_site_landing_count"]:
        _add_indicator(counter, "public_site_landing", uri_evidence["public_site_landing_count"])
    object_count = len(re.findall(rb"\b\d+\s+\d+\s+obj\b", raw))
    stream_count = len(re.findall(rb"\bstream\b", raw))
    encrypted = b"/Encrypt" in raw or "/Encrypt" in text
    eof_count = raw.count(b"%%EOF")

    return counter, {
        "uri_count": uri_count,
        "object_count": object_count,
        "stream_count": stream_count,
        "encrypted": encrypted,
        "suspicious_name_escapes": suspicious_name_escapes,
        "eof_count": eof_count,
        "uri_evidence": uri_evidence,
    }


def _safe_pdf_str(value) -> str:
    try:
        return str(value)
    except Exception:
        return ""


def _scan_pypdf_object(obj, counter: Counter, stats: dict, seen: set[int], depth: int = 0, object_label: str | None = None) -> None:
    if obj is None or depth > 35 or stats["walked_nodes"] >= PDF_OBJECT_WALK_LIMIT:
        return

    obj_id = id(obj)
    if obj_id in seen:
        return
    seen.add(obj_id)
    stats["walked_nodes"] += 1

    try:
        if hasattr(obj, "get_object") and obj.__class__.__name__ == "IndirectObject":
            ref_label = object_label
            idnum = getattr(obj, "idnum", None)
            generation = getattr(obj, "generation", None)
            if idnum is not None and generation is not None:
                ref_label = f"{idnum} {generation}"
            _scan_pypdf_object(obj.get_object(), counter, stats, seen, depth + 1, ref_label)
            return
    except Exception as exc:
        stats["parser_warnings"].append(f"Indirect object read failed: {exc}")
        return

    if isinstance(obj, dict):
        for raw_key, raw_value in obj.items():
            key = _decode_pdf_name_escapes(_safe_pdf_str(raw_key))
            indicator_key = PDF_NAME_TO_KEY.get(key)
            if indicator_key:
                _add_indicator(counter, indicator_key)
            value_name = _decode_pdf_name_escapes(_safe_pdf_str(raw_value))
            value_indicator_key = PDF_NAME_TO_KEY.get(value_name)
            if value_indicator_key:
                _add_indicator(counter, value_indicator_key)
            if key == "/URI":
                urls = PDF_URL_TEXT_RE.findall(value_name)
                if not urls and value_name.lower().startswith(("http://", "https://")):
                    urls = [value_name]
                if urls:
                    uri_evidence = _uri_evidence_from_action_urls([
                        {"object": object_label, "url": url} for url in urls
                    ], url_count=len(urls))
                    stats["uri_evidence"] = _merge_uri_evidence(stats.get("uri_evidence") or {}, uri_evidence)
                    if uri_evidence["nested_redirect_count"]:
                        _add_indicator(counter, "uri_nested_redirect", uri_evidence["nested_redirect_count"])
                    if uri_evidence["tracked_redirect_count"]:
                        _add_indicator(counter, "uri_tracked_redirect", uri_evidence["tracked_redirect_count"])
                    if uri_evidence["public_site_landing_count"]:
                        _add_indicator(counter, "public_site_landing", uri_evidence["public_site_landing_count"])
            _scan_pypdf_object(raw_value, counter, stats, seen, depth + 1, object_label)
        return

    if isinstance(obj, (list, tuple)):
        for item in obj:
            _scan_pypdf_object(item, counter, stats, seen, depth + 1, object_label)
        return

    obj_text = _decode_pdf_name_escapes(_safe_pdf_str(obj))
    indicator_key = PDF_NAME_TO_KEY.get(obj_text)
    if indicator_key:
        _add_indicator(counter, indicator_key)


def _pypdf_structural_scan(raw: bytes) -> tuple[Counter, dict]:
    counter: Counter = Counter()
    stats = {
        "parser": "pypdf-unavailable",
        "parser_available": False,
        "parser_error": "pypdf is not installed",
        "parser_warnings": [],
        "page_count": None,
        "field_count": 0,
        "embedded_attachment_count": 0,
        "is_encrypted": False,
        "is_decrypted_with_empty_password": False,
        "has_xfa": False,
        "has_open_destination": False,
        "page_mode": None,
        "walked_nodes": 0,
        "uri_evidence": _empty_uri_evidence(),
    }

    try:
        from pypdf import PdfReader
    except Exception:
        return counter, stats

    stats.update({"parser": "pypdf", "parser_available": True, "parser_error": None})
    try:
        reader = PdfReader(io.BytesIO(raw), strict=False, root_object_recovery_limit=20000)
        stats["is_encrypted"] = bool(reader.is_encrypted)
        if reader.is_encrypted:
            try:
                stats["is_decrypted_with_empty_password"] = bool(reader.decrypt(""))
            except Exception as exc:
                stats["parser_warnings"].append(f"Encrypted PDF could not be decrypted with empty password: {exc}")

        try:
            stats["page_count"] = len(reader.pages)
        except Exception as exc:
            stats["parser_warnings"].append(f"Page count unavailable: {exc}")

        try:
            fields = reader.get_fields() or {}
            stats["field_count"] = len(fields)
            if fields:
                _add_indicator(counter, "acroform")
        except Exception as exc:
            stats["parser_warnings"].append(f"Form fields unavailable: {exc}")

        try:
            xfa = getattr(reader, "xfa", None)
            stats["has_xfa"] = bool(xfa)
            if xfa:
                _add_indicator(counter, "xfa")
        except Exception as exc:
            stats["parser_warnings"].append(f"XFA unavailable: {exc}")

        try:
            embedded = getattr(reader, "attachments", {}) or {}
            stats["embedded_attachment_count"] = sum(len(value) for value in embedded.values())
            if stats["embedded_attachment_count"]:
                _add_indicator(counter, "embedded_file", stats["embedded_attachment_count"])
        except Exception as exc:
            stats["parser_warnings"].append(f"Embedded attachments unavailable: {exc}")

        try:
            open_destination = getattr(reader, "open_destination", None)
            stats["has_open_destination"] = bool(open_destination)
            if open_destination:
                _add_indicator(counter, "open_action")
        except Exception as exc:
            stats["parser_warnings"].append(f"Open destination unavailable: {exc}")

        try:
            stats["page_mode"] = _safe_pdf_str(getattr(reader, "page_mode", None) or "") or None
            if stats["page_mode"] == "/UseAttachments":
                _add_indicator(counter, "embedded_file")
        except Exception as exc:
            stats["parser_warnings"].append(f"Page mode unavailable: {exc}")

        try:
            _scan_pypdf_object(reader.root_object, counter, stats, set())
        except Exception as exc:
            stats["parser_warnings"].append(f"Catalog walk failed: {exc}")
    except Exception as exc:
        stats["parser_error"] = str(exc)

    return counter, stats


def analyze_pdf_security(raw: bytes) -> dict:
    """Run static PDF risk checks without executing or rendering the document."""
    if not raw.startswith(b"%PDF"):
        return {
            "is_pdf": False,
            "risk_level": "not_pdf",
            "suspicious": False,
            "indicators": [],
            "behaviors": [],
            "summary": "Not a PDF document",
            "uri_count": 0,
            "object_count": 0,
            "stream_count": 0,
            "encrypted": False,
            "parser": "not_pdf",
            "parser_available": False,
            "parser_error": None,
            "parser_warnings": [],
        }

    if len(raw) > PDF_ANALYSIS_MAX_BYTES:
        return {
            "is_pdf": True,
            "risk_level": "medium",
            "suspicious": False,
            "indicators": [],
            "behaviors": [],
            "summary": f"PDF too large for deep static scan ({len(raw)} bytes)",
            "uri_count": 0,
            "object_count": 0,
            "stream_count": 0,
            "encrypted": False,
            "parser": "skipped-size-limit",
            "parser_available": False,
            "parser_error": "PDF exceeds static analysis size limit",
            "parser_warnings": [],
        }

    static_counter, static_stats = _static_pdf_indicators(raw)
    structural_counter, structural_stats = _pypdf_structural_scan(raw)
    total_counter = static_counter + structural_counter
    uri_evidence = _merge_uri_evidence(
        static_stats.get("uri_evidence") or {},
        structural_stats.get("uri_evidence") or {},
    )
    for key, evidence_key in (
        ("uri_nested_redirect", "nested_redirect_count"),
        ("uri_tracked_redirect", "tracked_redirect_count"),
        ("public_site_landing", "public_site_landing_count"),
    ):
        if uri_evidence[evidence_key]:
            total_counter[key] = uri_evidence[evidence_key]
    indicators = _indicator_list(total_counter)

    encrypted = bool(static_stats["encrypted"] or structural_stats.get("is_encrypted"))
    parser_error = structural_stats.get("parser_error")
    parser_error_for_risk = None
    if structural_stats.get("parser_available") and parser_error:
        has_static_risk_context = bool(
            indicators
            or encrypted
            or static_stats["suspicious_name_escapes"]
            or static_stats["eof_count"] > 1
        )
        parser_error_for_risk = parser_error if has_static_risk_context else None
    behaviors = _pdf_behavior_findings(indicators)
    risk_level = _risk_level(indicators, encrypted, parser_error_for_risk, behaviors)
    suspicious = bool(behaviors)

    summary_parts = [f"{item['label']} x{item['count']}" for item in indicators[:8]]
    if encrypted:
        summary_parts.append("encrypted PDF")
    if static_stats["suspicious_name_escapes"]:
        summary_parts.append(f"obfuscated PDF names x{static_stats['suspicious_name_escapes']}")
    if static_stats["eof_count"] > 1:
        summary_parts.append(f"multiple EOF markers x{static_stats['eof_count']}")
    if static_stats["uri_count"] and not any(item["key"] == "uri" for item in indicators):
        summary_parts.append(f"URL-like strings x{static_stats['uri_count']}")
    uri_samples = uri_evidence.get("samples") or []
    if uri_samples:
        summary_parts.append("URI evidence: " + "; ".join(uri_samples[:3]))
    if parser_error_for_risk:
        summary_parts.append(f"structured parser error: {parser_error_for_risk}")
    elif parser_error:
        structural_stats["parser_warnings"] = (
            structural_stats.get("parser_warnings", [])
            + [f"Structured parser could not fully parse PDF: {parser_error}"]
        )

    return {
        "is_pdf": True,
        "risk_level": risk_level,
        "suspicious": suspicious,
        "indicators": indicators,
        "behaviors": behaviors,
        "summary": "; ".join(summary_parts) if summary_parts else "No active PDF features detected",
        "uri_count": static_stats["uri_count"],
        "uri_evidence": uri_evidence,
        "object_count": static_stats["object_count"],
        "stream_count": static_stats["stream_count"],
        "encrypted": encrypted,
        "suspicious_name_escapes": static_stats["suspicious_name_escapes"],
        "eof_count": static_stats["eof_count"],
        "parser": structural_stats.get("parser"),
        "parser_available": structural_stats.get("parser_available"),
        "parser_error": parser_error,
        "parser_warnings": structural_stats.get("parser_warnings", [])[:5],
        "page_count": structural_stats.get("page_count"),
        "field_count": structural_stats.get("field_count"),
        "embedded_attachment_count": structural_stats.get("embedded_attachment_count"),
        "has_xfa": structural_stats.get("has_xfa"),
        "has_open_destination": structural_stats.get("has_open_destination"),
        "page_mode": structural_stats.get("page_mode"),
        "walked_nodes": structural_stats.get("walked_nodes"),
    }


def analyze_attachment(
    filename: str,
    content_type: str,
    encoding: str,
    raw_payload,
) -> dict:
    """Analyze an attachment and flag extension/content/magic-byte mismatches."""
    entry: dict = {
        "filename": filename,
        "content_type": content_type,
        "encoding": encoding,
        "magic_bytes_hex": None,
        "magic_detected_format": None,
        "extension_from_filename": ext_from_filename(filename),
        "extension_match": None,
        "anomaly": None,
        "hash_md5": None,
        "hash_sha1": None,
        "hash_sha256": None,
        "size_bytes": None,
        "pdf_security": None,
        "archive_security": None,
        "embedded_urls": [],
    }

    raw_bytes, payload_warning = _payload_to_bytes(raw_payload)
    if raw_bytes is None:
        entry["anomaly"] = payload_warning
        return entry

    entry["magic_bytes_hex"] = raw_bytes[:16].hex().upper()
    entry["magic_detected_format"] = identify_magic_bytes(raw_bytes)
    entry["size_bytes"] = len(raw_bytes)
    entry["hash_md5"] = hashlib.md5(raw_bytes).hexdigest()
    entry["hash_sha1"] = hashlib.sha1(raw_bytes).hexdigest()
    entry["hash_sha256"] = hashlib.sha256(raw_bytes).hexdigest()

    if entry["magic_detected_format"] == "pdf" or entry["extension_from_filename"] == "pdf":
        entry["pdf_security"] = analyze_pdf_security(raw_bytes)
    if zipfile.is_zipfile(io.BytesIO(raw_bytes)) or entry["extension_from_filename"] in ZIP_CONTAINER_EXTS:
        entry["archive_security"] = analyze_archive_security(raw_bytes, filename)

    ct_base = content_type.split(";", 1)[0].strip().lower()
    expected_exts = CONTENT_TYPE_TO_EXT.get(ct_base, [])
    file_ext = entry["extension_from_filename"]
    magic_fmt = entry["magic_detected_format"]

    mismatches = []
    if file_ext and expected_exts and file_ext not in expected_exts:
        mismatches.append(
            f"Content-Type '{ct_base}' expects {expected_exts} but filename has '.{file_ext}'"
        )
    if magic_fmt and file_ext and magic_fmt != file_ext:
        if not (magic_fmt == "zip" and file_ext in ZIP_CONTAINER_EXTS):
            mismatches.append(
                f"Magic bytes identify format as '{magic_fmt}' but filename extension is '.{file_ext}'"
            )
    if magic_fmt and expected_exts and magic_fmt not in expected_exts:
        if not (magic_fmt == "zip" and bool(set(expected_exts) & ZIP_CONTAINER_EXTS)):
            mismatches.append(
                f"Magic bytes identify '{magic_fmt}' but Content-Type expects {expected_exts}"
            )

    entry["extension_match"] = not mismatches
    anomaly_parts = [part for part in (payload_warning, "; ".join(mismatches)) if part]
    pdf_security = entry.get("pdf_security") or {}
    if pdf_security.get("suspicious"):
        anomaly_parts.append(
            f"PDF risk {str(pdf_security.get('risk_level')).upper()}: {pdf_security.get('summary')}"
        )
    archive_security = entry.get("archive_security") or {}
    if archive_security.get("risk_level") in {"high", "medium"}:
        anomaly_parts.append(
            f"Archive risk {str(archive_security.get('risk_level')).upper()}: {archive_security.get('summary')}"
        )
    pdf_urls = ((entry.get("pdf_security") or {}).get("uri_evidence") or {}).get("urls") or []
    archive_urls = archive_security.get("urls") or []
    entry["embedded_urls"] = list(dict.fromkeys([*pdf_urls, *archive_urls]))[:25]
    entry["anomaly"] = "; ".join(anomaly_parts) if anomaly_parts else None
    return entry
