"""Attachment analysis helpers."""

import hashlib
import io
import re
import unicodedata
import zipfile
from collections import Counter
from typing import Optional
from urllib.parse import parse_qsl, unquote, urlparse

from .constants import (
    CONTENT_TYPE_TO_EXT,
    DANGEROUS_ATTACHMENT_EXTENSIONS,
    DANGEROUS_ATTACHMENT_MIME_TYPES,
    DANGEROUS_MAGIC_FORMATS,
    DECOY_ATTACHMENT_EXTENSIONS,
    MAGIC_BYTES,
)
from .archive_analysis import ArchiveAnalysisBudget, analyze_archive_security
from fishstop_engine.office_analysis import (
    OfficeAnalysisBudget, OLE_EXTENSIONS, OOXML_EXTENSIONS, analyze_office_security,
)

ZIP_CONTAINER_EXTS = OOXML_EXTENSIONS | {"zip"}
UNSUPPORTED_ARCHIVE_EXTS = {"rar", "7z", "tar", "gz", "tgz", "bz2", "xz", "zst", "cab", "iso", "img", "dmg"}
UNSUPPORTED_ARCHIVE_MIMES = {
    "application/vnd.rar", "application/x-rar-compressed", "application/x-7z-compressed",
    "application/x-tar", "application/gzip", "application/x-gzip", "application/x-bzip2",
    "application/x-xz", "application/zstd", "application/vnd.ms-cab-compressed",
    "application/x-iso9660-image", "application/x-apple-diskimage",
}

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
_BIDI_FILENAME_CONTROLS = frozenset({
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069",
})


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


def _analyze_attachment_file_type(
    filename: str,
    content_type: str,
    magic_format: str | None,
) -> dict:
    """Classify inherently risky attachment delivery formats."""
    findings: list[dict] = []

    def add(key: str, label: str, evidence: str) -> None:
        findings.append({
            "key": key,
            "severity": "high",
            "label": label,
            "evidence": evidence,
        })

    original_name = filename or ""
    normalized_name = unicodedata.normalize("NFKC", original_name)
    basename = re.split(r"[\\/]", normalized_name)[-1].rstrip(" .")
    name_parts = [part.strip().lower() for part in basename.split(".") if part.strip()]
    extension = name_parts[-1] if len(name_parts) >= 2 else ""
    mime_type = (content_type or "").split(";", 1)[0].strip().lower()
    if len(name_parts) >= 3 and extension in {"html", "htm"} and name_parts[-2] in DECOY_ATTACHMENT_EXTENSIONS:
        findings.append({"key": "html_document_disguise", "severity": "medium",
                         "label": f"HTML attachment filename suggests a '.{name_parts[-2]}' document",
                         "evidence": basename})

    if any(character in _BIDI_FILENAME_CONTROLS for character in original_name):
        add(
            "bidirectional_filename_control",
            "bidirectional control character can disguise the displayed filename",
            original_name,
        )
    if (
        len(name_parts) >= 3
        and extension in DANGEROUS_ATTACHMENT_EXTENSIONS
        and name_parts[-2] in DECOY_ATTACHMENT_EXTENSIONS
    ):
        add(
            "double_extension",
            f"double extension disguises '.{extension}' as '.{name_parts[-2]}'",
            basename,
        )
    if extension in DANGEROUS_ATTACHMENT_EXTENSIONS:
        add(
            "dangerous_extension",
            f"potentially executable or active attachment extension '.{extension}'",
            extension,
        )
    if mime_type in DANGEROUS_ATTACHMENT_MIME_TYPES:
        add(
            "dangerous_mime_type",
            f"MIME type declares potentially executable or script content '{mime_type}'",
            mime_type,
        )
    if magic_format in DANGEROUS_MAGIC_FORMATS:
        add(
            "dangerous_magic_bytes",
            f"magic bytes identify potentially executable content '{magic_format}'",
            magic_format,
        )

    return {
        "risk_level": "high" if any(f["severity"] == "high" for f in findings) else "medium" if findings else "clean",
        "findings": findings,
        "summary": (
            "; ".join(item["label"] for item in findings)
            if findings
            else "No inherently dangerous attachment file type detected."
        ),
    }


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
        # The same action is observed once by the raw syntax scan and once by
        # pypdf.  Include its object reference so those observations collapse,
        # while two distinct annotations pointing to the same URL remain two
        # actions.
        signature = "|".join([
            str(item.get("object") or "unknown-object"),
            url,
            *nested_urls,
        ])
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
    evidence["url_count"] = len(evidence["urls"])
    evidence["uri_action_url_count"] = len(evidence["signatures"])
    return evidence


def _merge_uri_evidence(*items: dict) -> dict:
    merged = _empty_uri_evidence()
    seen_signatures: set[str] = set()
    seen_samples: set[str] = set()
    for item in items:
        if not item:
            continue
        signatures = set(item.get("signatures") or [])
        duplicate = bool(signatures and signatures <= seen_signatures)
        if not duplicate:
            # Both scanners inspect the same document. Maxima retain findings
            # available to only one scanner without adding the same action
            # twice when their evidence overlaps.
            merged["nested_redirect_count"] = max(
                merged["nested_redirect_count"],
                int(item.get("nested_redirect_count") or 0),
            )
            merged["tracked_redirect_count"] = max(
                merged["tracked_redirect_count"],
                int(item.get("tracked_redirect_count") or 0),
            )
            merged["public_site_landing_count"] = max(
                merged["public_site_landing_count"],
                int(item.get("public_site_landing_count") or 0),
            )
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
    merged["url_count"] = len(merged["urls"])
    merged["uri_action_url_count"] = len(merged["signatures"])
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


def _pdf_syntax_without_stream_data(raw: bytes) -> bytes:
    """Remove stream payloads before scanning PDF names.

    Compressed stream bytes are arbitrary binary data.  Interpreting them as
    PDF syntax creates false names such as ``#fb`` and, more seriously, can
    invent active-feature tokens that do not exist in the object structure.
    """
    return re.sub(
        rb"(?s)\bstream\r?\n.*?\bendstream\b",
        b"stream\nendstream",
        raw,
    )


def _static_pdf_indicators(raw: bytes) -> tuple[Counter, dict]:
    counter: Counter = Counter()
    syntax_raw = _pdf_syntax_without_stream_data(raw)
    raw_text = syntax_raw.decode("latin-1", errors="ignore")
    suspicious_name_escapes = len(PDF_HEX_ESCAPE_RE.findall(raw_text))
    text = _decode_pdf_name_escapes(raw_text)
    names = PDF_NAME_RE.findall(text)
    name_counts = Counter(names)

    for name, count in name_counts.items():
        key = PDF_NAME_TO_KEY.get(name)
        if key:
            _add_indicator(counter, key, count)

    uri_count = len(URL_RE.findall(syntax_raw))
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
    if obj is None:
        return

    obj_id = id(obj)
    if obj_id in seen:
        return
    if depth > 35 or stats["walked_nodes"] >= PDF_OBJECT_WALK_LIMIT:
        stats["walk_limit_reached"] = True
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
        # Count each feature once per PDF dictionary.  For example a URI
        # action normally contains both ``/S /URI`` and ``/URI (url)``; those
        # describe one action, not two independent URI actions.
        local_indicators: set[str] = set()
        for raw_key, raw_value in obj.items():
            key = _decode_pdf_name_escapes(_safe_pdf_str(raw_key))
            value_name = _decode_pdf_name_escapes(_safe_pdf_str(raw_value))
            for name in (key, value_name):
                indicator_key = PDF_NAME_TO_KEY.get(name)
                if indicator_key:
                    local_indicators.add(indicator_key)
        for indicator_key in local_indicators:
            _add_indicator(counter, indicator_key)

        for raw_key, raw_value in obj.items():
            key = _decode_pdf_name_escapes(_safe_pdf_str(raw_key))
            value_name = _decode_pdf_name_escapes(_safe_pdf_str(raw_value))
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
        "walk_limit_reached": False,
        "uri_evidence": _empty_uri_evidence(),
        "text_excerpt": "",
        "text_extraction_status": "unavailable",
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

        # Reuse the parsed document to expose bounded, untrusted visible text
        # for identity and intent analysis. No document actions are executed.
        try:
            texts = []
            for page in list(reader.pages[:3]):
                contents = page.get_contents()
                if contents and len(contents.get_data()) > 2 * 1024 * 1024:
                    stats["text_extraction_status"] = "partial"
                    break
                text = page.extract_text() or ""
                if len(text) > 6000:
                    stats["text_extraction_status"] = "partial"
                texts.append(text[:6000])
            joined = "\n".join(texts)
            if len(joined) > 12000:
                stats["text_extraction_status"] = "partial"
            stats["text_excerpt"] = joined[:12000].strip()
            if stats["text_extraction_status"] != "partial":
                stats["text_extraction_status"] = "partial" if len(reader.pages) > 3 else "extracted" if stats["text_excerpt"] else "empty"
        except Exception:
            stats["text_extraction_status"] = "unavailable"

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
            "analysis_complete": False,
            "status": "invalid",
            "risk_level": "unknown",
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
            "analysis_complete": False,
            "status": "skipped",
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
    # Prefer counts from the parsed reachable object graph. Raw syntax remains
    # a fallback for malformed or orphaned constructs that pypdf cannot expose,
    # but the same feature is never added twice merely because two scanners saw
    # it.
    total_counter = Counter(static_counter)
    for key, count in structural_counter.items():
        total_counter[key] = count
    if structural_stats.get("parser_available") and not structural_stats.get("parser_error"):
        field_count = int(structural_stats.get("field_count") or 0)
        if field_count:
            total_counter["acroform"] = field_count
        else:
            total_counter.pop("acroform", None)
    uri_evidence = _merge_uri_evidence(
        static_stats.get("uri_evidence") or {},
        structural_stats.get("uri_evidence") or {},
    )
    if uri_evidence["uri_action_url_count"]:
        total_counter["uri"] = uri_evidence["uri_action_url_count"]
    else:
        total_counter.pop("uri", None)
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
    analysis_complete = bool(
        structural_stats.get("parser_available")
        and not parser_error
        and not structural_stats.get("parser_warnings")
        and not structural_stats.get("walk_limit_reached")
        and (not encrypted or structural_stats.get("is_decrypted_with_empty_password"))
    )
    behaviors = _pdf_behavior_findings(indicators)
    risk_level = _risk_level(indicators, encrypted, parser_error, behaviors)
    if not analysis_complete and risk_level in {"clean", "low"}:
        risk_level = "unknown"
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
    if parser_error:
        summary_parts.append(f"structured parser error: {parser_error}")
    if structural_stats.get("walk_limit_reached"):
        summary_parts.append("PDF object/depth inspection limit reached")
    if not analysis_complete:
        summary_parts.append("PDF inspection incomplete; requires review")

    return {
        "is_pdf": True,
        "analysis_complete": analysis_complete,
        "status": "ok" if analysis_complete else "partial",
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
        "text_excerpt": structural_stats.get("text_excerpt", ""),
        "text_extraction_status": structural_stats.get("text_extraction_status", "unavailable"),
    }


def analyze_attachment(
    filename: str,
    content_type: str,
    encoding: str,
    raw_payload,
    archive_budget: ArchiveAnalysisBudget | None = None,
    office_budget: OfficeAnalysisBudget | None = None,
    archive_depth: int = 0,
    from_domain: str = "",
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
        "attachment_security": None,
        "pdf_security": None,
        "archive_security": None,
        "office_security": None,
        "embedded_urls": [],
    }

    raw_bytes, payload_warning = _payload_to_bytes(raw_payload)
    if raw_bytes is None:
        entry["attachment_security"] = _analyze_attachment_file_type(
            filename,
            content_type,
            None,
        )
        anomaly_parts = [payload_warning] if payload_warning else []
        if entry["attachment_security"]["risk_level"] == "high":
            anomaly_parts.append(
                f"High-risk attachment: {entry['attachment_security']['summary']}"
            )
        entry["anomaly"] = "; ".join(anomaly_parts) if anomaly_parts else None
        entry["inspection"] = {"status": "partial", "analysis_complete": False,
                               "summary": "Attachment payload could not be inspected."}
        return entry

    entry["magic_bytes_hex"] = raw_bytes[:16].hex().upper()
    entry["magic_detected_format"] = identify_magic_bytes(raw_bytes)
    entry["size_bytes"] = len(raw_bytes)
    entry["hash_md5"] = hashlib.md5(raw_bytes).hexdigest()
    entry["hash_sha1"] = hashlib.sha1(raw_bytes).hexdigest()
    entry["hash_sha256"] = hashlib.sha256(raw_bytes).hexdigest()
    entry["attachment_security"] = _analyze_attachment_file_type(
        filename,
        content_type,
        entry["magic_detected_format"],
    )

    if entry["magic_detected_format"] == "pdf" or entry["extension_from_filename"] == "pdf":
        entry["pdf_security"] = analyze_pdf_security(raw_bytes)
    if zipfile.is_zipfile(io.BytesIO(raw_bytes)) or entry["extension_from_filename"] in ZIP_CONTAINER_EXTS:
        entry["archive_security"] = analyze_archive_security(
            raw_bytes,
            filename,
            depth=archive_depth,
            budget=archive_budget,
            office_budget=office_budget,
        )

    ct_base = content_type.split(";", 1)[0].strip().lower()
    if entry["archive_security"] is None and (
        entry["extension_from_filename"] in UNSUPPORTED_ARCHIVE_EXTS
        or entry["magic_detected_format"] in UNSUPPORTED_ARCHIVE_EXTS
        or ct_base in UNSUPPORTED_ARCHIVE_MIMES
        or raw_bytes.startswith((b"7z\xbc\xaf\x27\x1c", b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00", b"\x28\xb5\x2f\xfd"))
        or raw_bytes[257:262] == b"ustar"
    ):
        entry["archive_security"] = {
            "is_archive": True, "status": "unsupported", "analysis_complete": False,
            "risk_level": "unknown", "findings": [], "urls": [],
            "summary": "Archive format not supported: contents were not inspected.",
        }

    entry["office_security"] = analyze_office_security(raw_bytes, filename, content_type, office_budget)
    expected_exts = CONTENT_TYPE_TO_EXT.get(ct_base, [])
    file_ext = entry["extension_from_filename"]
    magic_fmt = entry["magic_detected_format"]

    mismatches = []
    if file_ext and expected_exts and file_ext not in expected_exts:
        mismatches.append(
            f"Content-Type '{ct_base}' expects {expected_exts} but filename has '.{file_ext}'"
        )
    if magic_fmt and file_ext and magic_fmt != file_ext:
        if not ((magic_fmt == "html" and file_ext == "htm")
                or (magic_fmt == "zip" and file_ext in ZIP_CONTAINER_EXTS)
                or (magic_fmt == "doc" and file_ext in OLE_EXTENSIONS)):
            mismatches.append(
                f"Magic bytes identify format as '{magic_fmt}' but filename extension is '.{file_ext}'"
            )
    if magic_fmt and expected_exts and magic_fmt not in expected_exts:
        if not ((magic_fmt == "zip" and bool(set(expected_exts) & ZIP_CONTAINER_EXTS))
                or (magic_fmt == "doc" and bool(set(expected_exts) & OLE_EXTENSIONS))):
            mismatches.append(
                f"Magic bytes identify '{magic_fmt}' but Content-Type expects {expected_exts}"
            )

    entry["extension_match"] = not mismatches
    anomaly_parts = [part for part in (payload_warning, "; ".join(mismatches)) if part]
    attachment_security = entry.get("attachment_security") or {}
    if ct_base == "text/html" or file_ext in {"html", "htm"} or magic_fmt == "html":
        from .html_attachment_analysis import analyze_html_attachment
        entry["html_security"] = analyze_html_attachment(raw_bytes, from_domain)
        html_security = entry["html_security"]
        if html_security["risk_level"] in {"medium", "high"}:
            previous = attachment_security["summary"] if attachment_security["findings"] else ""
            attachment_security["findings"].extend(html_security["findings"])
            if attachment_security["risk_level"] != "high":
                attachment_security["risk_level"] = html_security["risk_level"]
            attachment_security["summary"] = "; ".join(filter(None, [previous, html_security["summary"]]))
            if html_security["risk_level"] == "high":
                anomaly_parts.append(html_security["summary"])
    if attachment_security.get("risk_level") == "high":
        anomaly_parts.append(
            f"High-risk attachment: {attachment_security.get('summary')}"
        )
    pdf_security = entry.get("pdf_security") or {}
    if pdf_security.get("suspicious"):
        anomaly_parts.append(
            f"PDF risk {str(pdf_security.get('risk_level')).upper()}: {pdf_security.get('summary')}"
        )
    archive_security = entry.get("archive_security") or {}
    if archive_security.get("risk_level") in {"high", "critical"}:
        anomaly_parts.append(
            f"Archive risk {str(archive_security.get('risk_level')).upper()}: {archive_security.get('summary')}"
        )
    pdf_urls = ((entry.get("pdf_security") or {}).get("uri_evidence") or {}).get("urls") or []
    archive_urls = archive_security.get("urls") or []
    office_urls = (entry.get("office_security") or {}).get("urls") or []
    html_urls = (entry.get("html_security") or {}).get("urls") or []
    entry["embedded_urls"] = list(dict.fromkeys([*pdf_urls, *archive_urls, *office_urls, *html_urls]))[:25]
    entry["anomaly"] = "; ".join(anomaly_parts) if anomaly_parts else None
    scans = [entry[key] for key in ("pdf_security", "archive_security", "office_security", "html_security") if entry.get(key)]
    incomplete = [scan for scan in scans if scan.get("analysis_complete") is False]
    entry["inspection"] = {
        "status": "partial" if incomplete else "complete" if scans else "type_only",
        "analysis_complete": bool(scans) and not incomplete,
        "type_checks_complete": True,
        "content_inspected": bool(scans),
        "summary": "; ".join(scan["summary"] for scan in incomplete)
            if incomplete else "Supported local checks completed." if scans
            else "File type checks only; no content scanner is available for this format.",
    }
    return entry
