"""
analyzer/soc_analyzer.py - Motore di analisi statica ed euristica per il SOC.

Main class:
  EmlSOCAnalyzer.analyze(eml_path) -> dict

Coordina tutti i sotto-moduli dell'analyzer:
  - received_parser  : parsing catena Received e Authentication-Results
  - link_extractor   : URL extraction from the body
  - lookalike        : rilevamento domini lookalike
  - attachment       : analisi allegati via magic bytes e hash
  - html_utils       : stripping HTML per body_clean
"""

import email
import html as html_lib
import ipaddress
import re
import unicodedata
from collections import Counter
from difflib import SequenceMatcher
from email import policy
from typing import Optional

from fishstop_engine.analysis_limits import (
    EmailAnalysisLimitError,
    MAX_AI_BODY_CHARS,
    MAX_ATTACHMENTS,
    MAX_DECODED_TEXT_CHARS,
    MAX_MIME_DEPTH,
    MAX_MIME_PARTS,
    MAX_RECEIVED_HOPS,
)
from fishstop_engine.domain_utils import registered_domain, same_registered_domain
from .archive_analysis import ArchiveAnalysisBudget
from .attachment      import analyze_attachment
from .body_context    import select_body_for_ai
from .html_deception  import analyze_html_copy_deception
from .html_form_analysis import analyze_html_forms
from .html_utils      import (
    recover_mislabelled_utf7_html,
    sanitize_html_for_preview,
    strip_html,
    strip_html_for_intent,
)
from .link_extractor  import extract_links
from .lookalike       import check_lookalike_domains
from .received_parser import (
    build_authentication_checkpoints,
    parse_auth_results,
    parse_received_hop,
    parse_received_spf_results,
    select_effective_auth_results,
)


NO_REPLY_LOCAL_PARTS = {
    "no-reply",
    "noreply",
    "do-not-reply",
    "donotreply",
    "notification",
    "notifications",
    "newsletter",
    "news",
    "mail",
    "mailer",
}

GENERIC_REPLY_LOCAL_PARTS = {
    "support",
    "help",
    "helpdesk",
    "contact",
    "contacts",
    "info",
    "assistenza",
    "assistance",
    "customer",
    "customerservice",
    "customer-service",
    "service",
    "reply",
    "replies",
}

RAW_EML_PREVIEW_MAX_CHARS = 750_000


def _redacted_eml_preview(raw_bytes: bytes) -> str:
    """Serialize an inspectable EML source without attachment payloads.

    The preview keeps the message headers, MIME structure and text bodies. Any
    named or explicitly attached leaf part is replaced with a readable marker,
    preventing large Base64/binary blocks from overwhelming the Technical tab.
    A separate parse is used so redaction can never affect the analysis itself.
    """
    preview_message = email.message_from_bytes(raw_bytes, policy=policy.default)
    for part in preview_message.walk():
        filename = str(part.get_filename() or "").strip()
        disposition = str(part.get_content_disposition() or "").lower()
        if disposition != "attachment" and not filename:
            continue
        try:
            decoded_payload = part.get_payload(decode=True)
        except Exception:
            decoded_payload = None
        size_label = (
            f"{len(decoded_payload) / 1_000_000:.2f} MB"
            if isinstance(decoded_payload, bytes)
            else "size unavailable"
        )
        safe_filename = re.sub(r"[\r\n\t]+", " ", filename).strip()[:160]
        marker = (
            "[FishStop attachment payload omitted"
            f"; filename={safe_filename or 'unnamed'}"
            f"; content-type={part.get_content_type()}"
            f"; decoded-size={size_label}]"
        )
        part.set_payload(marker)
        while part.get("Content-Transfer-Encoding") is not None:
            del part["Content-Transfer-Encoding"]
        part["Content-Transfer-Encoding"] = "8bit"
        part["X-FishStop-Attachment-Payload"] = "omitted from Technical preview"

    rendered = preview_message.as_string(
        policy=policy.default.clone(linesep="\n", max_line_length=0)
    )
    if len(rendered) <= RAW_EML_PREVIEW_MAX_CHARS:
        return rendered
    return (
        rendered[:RAW_EML_PREVIEW_MAX_CHARS]
        + "\n\n[FishStop raw EML preview truncated at "
        + f"{RAW_EML_PREVIEW_MAX_CHARS} characters]"
    )

BULK_OR_CRM_HEADERS = {
    "List-Unsubscribe",
    "List-Unsubscribe-Post",
    "List-Id",
    "List-Help",
    "List-Owner",
    "List-Post",
    "List-Subscribe",
    "Precedence",
    "Auto-Submitted",
    "X-Mailer",
    "X-Campaign",
    "X-Campaign-Id",
    "X-Mailgun-Tag",
    "X-Mailgun-Sid",
    "X-MC-User",
    "X-Mandrill-User",
    "X-SES-Outgoing",
    "X-SFDC-LK",
    "X-SG-EID",
    "X-SMTPAPI",
}

BULK_SENDER_SIGNAL_THRESHOLD = 4
_ENCODED_NOISE_LINE_RE = re.compile(r"[A-Za-z0-9+/=_-]{64,}")
_ENCODED_NOISE_MIN_LINES = 8
_ENCODED_NOISE_MIN_CHARS = 4096
_FINANCIAL_REQUEST_RE = re.compile(
    r"\b(?:invoice|invoices|facture|fattura|fatture|faktura|faktury|payment|pagamento|"
    r"pagamenti|płatno(?:ść|ści)|przelew|transfer|bonifico)\b",
    re.IGNORECASE,
)
_ATTACHMENT_CLAIM_RE = re.compile(
    r"\b(?:attached|attachment|enclosed|in attachment|in allegato|allegata|załącz(?:niku|niku|am)|"
    r"w załączeniu|zalaczniku)\b",
    re.IGNORECASE,
)
_MIME_ROOT_SINGLETON_HEADERS = {
    "from", "sender", "subject", "date", "message-id", "reply-to", "return-path",
    "mime-version", "content-type", "content-transfer-encoding",
}
_MIME_PART_SINGLETON_HEADERS = {
    "content-type", "content-transfer-encoding", "content-disposition",
    "content-id", "mime-version",
}
_MIME_FINDING_LIMIT = 50
_MIME_DEFECT_DESCRIPTIONS = {
    "InvalidBase64CharactersDefect": "Base64 payload contains invalid characters.",
    "InvalidBase64PaddingDefect": "Base64 payload has invalid or missing padding.",
    "InvalidMultipartContentTransferEncodingDefect": "Multipart container declares an invalid transfer encoding.",
    "StartBoundaryNotFoundDefect": "Declared MIME start boundary was not found.",
    "CloseBoundaryNotFoundDefect": "MIME closing boundary was not found.",
    "MultipartInvariantViolationDefect": "MIME content type and parsed multipart structure disagree.",
    "NoBoundaryInMultipartDefect": "Multipart content type does not declare a boundary.",
    "MissingHeaderBodySeparatorDefect": "A MIME part has no valid header/body separator.",
    "MalformedHeaderDefect": "A malformed header line was encountered.",
    "InvalidBase64LengthDefect": "Base64 payload length is invalid and could not be decoded reliably.",
    "FirstHeaderLineIsContinuationDefect": "A MIME part starts with an orphaned folded header line.",
    "MisplacedEnvelopeHeaderDefect": "A Unix envelope line appears inside the header block.",
    "InvalidDateDefect": "The Date header could not be parsed; its original value was retained.",
    "InvalidHeaderDefect": "A structured header contains invalid syntax.",
    "HeaderMissingRequiredValue": "A structured header is missing a required value.",
    "NonASCIILocalPartDefect": "An address contains a non-ASCII local part.",
    "NonPrintableDefect": "A header contains non-printable characters.",
    "ObsoleteHeaderDefect": "A header uses obsolete but parseable syntax.",
    "UndecodableBytesDefect": "A header contains bytes that could not be decoded cleanly.",
}

# Only defects that can change where headers stop, how parts are separated, or
# what transfer-decoded bytes a scanner sees should influence the risk verdict.
# The email package also reports interoperability/metadata defects (for example
# an invalid Date); surfacing those is useful, but treating them as phishing
# evidence creates avoidable false positives.
_MIME_REVIEW_DEFECTS = {
    "NoBoundaryInMultipartDefect",
    "StartBoundaryNotFoundDefect",
    "MultipartInvariantViolationDefect",
    "InvalidMultipartContentTransferEncodingDefect",
    "MissingHeaderBodySeparatorDefect",
    "FirstHeaderLineIsContinuationDefect",
    "InvalidBase64LengthDefect",
    "InvalidBase64CharactersDefect",
}
_MIME_LOW_DEFECTS = {
    "CloseBoundaryNotFoundDefect",
    "InvalidBase64PaddingDefect",
    "MisplacedEnvelopeHeaderDefect",
    "InvalidHeaderDefect",
    "HeaderMissingRequiredValue",
    "NonPrintableDefect",
    "UndecodableBytesDefect",
}
_MIME_INFORMATIONAL_DEFECTS = {
    "InvalidDateDefect",
    "NonASCIILocalPartDefect",
    "ObsoleteHeaderDefect",
}


def _mime_defect_level(code: str) -> str:
    if code in _MIME_REVIEW_DEFECTS:
        return "MEDIUM"
    if code in _MIME_LOW_DEFECTS:
        return "LOW"
    if code in _MIME_INFORMATIONAL_DEFECTS:
        return "INFO"
    # Unknown defects remain visible but cannot affect the verdict until their
    # parser semantics have been reviewed explicitly.
    return "LOW"


def _duplicate_mime_header_level(header_name: str, path: str) -> str:
    if path == "1":
        if header_name in {
            "from", "sender", "subject", "reply-to", "return-path",
            "content-type", "content-transfer-encoding",
        }:
            return "MEDIUM"
        if header_name in {"date", "message-id"}:
            return "LOW"
        return "INFO"
    if header_name in {"content-type", "content-transfer-encoding", "content-disposition"}:
        return "MEDIUM"
    return "LOW"


def _extract_domain(email_or_addr: str) -> str:
    """Returns the domain portion of an email address, lowercased."""
    m = re.search(r"@([\w.\-]+)", email_or_addr or "")
    return m.group(1).lower() if m else ""


def _claims_financial_attachment(text: str) -> bool:
    """Detect a financial message that says its actionable document is attached."""
    value = text or ""
    return bool(_FINANCIAL_REQUEST_RE.search(value) and _ATTACHMENT_CLAIM_RE.search(value))


def _local_part(address: str | None) -> str:
    if not address or "@" not in address:
        return ""
    return address.rsplit("@", 1)[0].lower().strip()


def _bulk_sender_signals(msg) -> list[str]:
    signals: list[str] = []
    for name in sorted(BULK_OR_CRM_HEADERS):
        value = str(msg.get(name) or "").strip()
        if value:
            signals.append(name)

    auto_submitted = str(msg.get("Auto-Submitted") or "").lower().strip()
    precedence = str(msg.get("Precedence") or "").lower().strip()
    if auto_submitted in {"auto-generated", "auto-replied"}:
        signal = f"Auto-Submitted={auto_submitted}"
        if signal not in signals:
            signals.append(signal)
    if precedence in {"bulk", "list"}:
        signal = f"Precedence={precedence}"
        if signal not in signals:
            signals.append(signal)
    return signals


def _has_bulk_or_crm_headers(msg) -> bool:
    return bool(_bulk_sender_signals(msg))


def _reply_to_mismatch_looks_legitimate(msg, from_addr: str | None, reply_addr: str | None) -> bool:
    if not from_addr or not reply_addr:
        return False

    from_domain = _extract_domain(from_addr)
    reply_domain = _extract_domain(reply_addr)
    if same_registered_domain(from_domain, reply_domain):
        return True

    from_local = _local_part(from_addr)
    reply_local = _local_part(reply_addr)
    if not _has_bulk_or_crm_headers(msg):
        return False

    return (
        from_local in NO_REPLY_LOCAL_PARTS
        and reply_local in GENERIC_REPLY_LOCAL_PARTS
    )


def _pdf_indicator_flag_level(severity: str) -> str:
    severity = (severity or "").lower()
    if severity in {"critical", "high"}:
        return "HIGH"
    if severity == "medium":
        return "MEDIUM"
    return "INFO"


def _non_pdf_attachment_anomaly(att: dict) -> str | None:
    anomaly = str(att.get("anomaly") or "").strip()
    if not anomaly:
        return None
    if anomaly.startswith("PDF risk "):
        return None
    return anomaly


def _decode_text_part(part) -> str:
    payload = part.get_payload(decode=True)
    charset = part.get_content_charset() or "utf-8"

    if payload is not None:
        candidates = []
        for candidate in (charset, "utf-8", "cp1252", "latin-1"):
            if candidate and candidate.lower() not in {item.lower() for item in candidates}:
                candidates.append(candidate)
        for candidate in candidates:
            try:
                return html_lib.unescape(recover_mislabelled_utf7_html(payload.decode(candidate, errors="strict")))
            except (LookupError, UnicodeDecodeError):
                continue
        return html_lib.unescape(recover_mislabelled_utf7_html(payload.decode("utf-8", errors="replace")))

    raw_payload = part.get_payload(decode=False)
    if isinstance(raw_payload, str):
        return html_lib.unescape(recover_mislabelled_utf7_html(raw_payload))
    return ""


def _looks_like_html(value: str) -> bool:
    if not value:
        return False
    return bool(re.search(
        r"(?is)<\s*(?:!doctype\s+html|html|body|table|div|span|p|br|a|img|style|head)\b",
        value,
    ))


_RAW_URL_TOKEN_RE = re.compile(r"https?://[^\s<>()]+", re.IGNORECASE)


def _prefer_html_over_link_heavy_plain(plain: str, html: str) -> bool:
    """Prefer visible HTML text when the plain alternative is tracking-URL noise.

    Marketing systems often generate a valid ``text/plain`` alternative by
    inserting a full redirect URL after every button.  The HTML alternative
    retains the same visible message without exposing those opaque tracking
    parameters to the AI models.  This is a content-quality decision, not a
    sender/domain allowlist: HTML is selected only when it contains meaningful
    visible text and raw URLs dominate the plain alternative.
    """
    if len(plain) < 1_200 or len(html) < 120:
        return False
    urls = _RAW_URL_TOKEN_RE.findall(plain)
    if len(urls) < 6:
        return False
    url_characters = sum(len(url) for url in urls)
    visible_plain = _RAW_URL_TOKEN_RE.sub(" ", plain)
    visible_words = re.findall(r"[A-Za-zÀ-ÖØ-öø-ÿ0-9]{2,}", visible_plain)
    html_words = re.findall(r"[A-Za-zÀ-ÖØ-öø-ÿ0-9]{2,}", html)
    return (
        url_characters >= len(plain) * 0.45
        and len(html_words) >= 20
        and len(html) >= min(240, len(" ".join(visible_words)) * 0.45)
    )


def _strip_plaintext_noise_blocks(value: str) -> tuple[str, int, int]:
    """Remove large encoded/random padding blocks while preserving isolated tokens.

    Spam campaigns sometimes copy a hidden HTML poison block into the plain-text
    MIME alternative. A single hash, token, URL, or encoded line is legitimate,
    so removal requires a long consecutive run and a large aggregate size.
    """
    lines = (value or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    output: list[str] = []
    candidate: list[str] = []
    removed_lines = 0
    removed_chars = 0

    def flush_candidate() -> None:
        nonlocal removed_lines, removed_chars
        if (
            len(candidate) >= _ENCODED_NOISE_MIN_LINES
            and sum(len(line.strip()) for line in candidate) >= _ENCODED_NOISE_MIN_CHARS
        ):
            removed_lines += len(candidate)
            removed_chars += sum(len(line) for line in candidate)
        else:
            output.extend(candidate)
        candidate.clear()

    for line in lines:
        stripped = line.strip()
        if _ENCODED_NOISE_LINE_RE.fullmatch(stripped) and len(set(stripped)) >= 12:
            candidate.append(line)
            continue
        flush_candidate()
        output.append(line)
    flush_candidate()
    cleaned = re.sub(r"\n{3,}", "\n\n", "\n".join(output)).strip()
    return cleaned, removed_lines, removed_chars


def _iter_body_leaf_parts(part, path: str = "1", alternative_groups: tuple[str, ...] = ()):
    """Yield body leaves with their MIME path and alternative ancestors."""
    disposition = str(part.get("Content-Disposition") or "").lower()
    if "attachment" in disposition or part.get_filename():
        return
    if part.get_content_type() == "message/rfc822":
        return
    if part.is_multipart():
        child_groups = alternative_groups
        if part.get_content_subtype().lower() == "alternative":
            child_groups = alternative_groups + (path,)
        for index, child in enumerate(part.iter_parts(), 1):
            yield from _iter_body_leaf_parts(
                child,
                f"{path}.{index}",
                child_groups,
            )
        return
    yield part, path, alternative_groups


def _iter_mime_parts(part, path: str = "1"):
    yield part, path
    if part.is_multipart():
        for index, child in enumerate(part.iter_parts(), 1):
            yield from _iter_mime_parts(child, f"{path}.{index}")


def _collect_mime_findings(msg) -> tuple[list[dict], int, int, int, int]:
    """Collect parser defects and security-relevant duplicate singleton headers."""
    findings: list[dict] = []
    defect_count = 0
    duplicate_count = 0
    review_count = 0
    notice_count = 0
    seen: set[tuple[str, str, str, str]] = set()

    def add(finding: dict) -> bool:
        nonlocal review_count, notice_count
        key = (
            str(finding.get("part_path") or ""),
            str(finding.get("kind") or ""),
            str(finding.get("code") or ""),
            str(finding.get("header") or ""),
        )
        if key in seen:
            return False
        seen.add(key)
        if finding.get("level") in {"HIGH", "MEDIUM"}:
            review_count += 1
        else:
            notice_count += 1
        findings.append(finding)
        return True

    for part, path in _iter_mime_parts(msg):
        if not part.is_multipart() and part.get_content_type() != "message/rfc822":
            # The stdlib records some transfer-decoding defects lazily.
            try:
                part.get_payload(decode=True)
            except Exception as exc:  # Defensive: malformed input must still produce a report.
                if add({
                    "kind": "decode_error",
                    "code": type(exc).__name__,
                    "level": "MEDIUM",
                    "part_path": path,
                    "message": f"MIME part {path} could not be transfer-decoded ({type(exc).__name__}).",
                }):
                    defect_count += 1

        allowed_singletons = (
            _MIME_ROOT_SINGLETON_HEADERS
            if path == "1"
            else _MIME_PART_SINGLETON_HEADERS
        )
        header_counts: dict[str, int] = {}
        for name, _ in part.raw_items():
            normalized_name = str(name).lower()
            header_counts[normalized_name] = header_counts.get(normalized_name, 0) + 1
        for header_name, count in header_counts.items():
            if header_name not in allowed_singletons or count <= 1:
                continue
            display_name = "-".join(piece.capitalize() for piece in header_name.split("-"))
            if add({
                "kind": "duplicate_header",
                "code": "DuplicateSingletonHeader",
                "level": _duplicate_mime_header_level(header_name, path),
                "part_path": path,
                "header": display_name,
                "count": count,
                "message": f"MIME part {path} contains {count} `{display_name}` headers; interpretation is ambiguous.",
            }):
                duplicate_count += 1

        defect_sources = [("message", defect) for defect in getattr(part, "defects", ())]
        try:
            for header_name, header_value in part.items():
                defect_sources.extend(
                    (str(header_name), defect)
                    for defect in getattr(header_value, "defects", ())
                )
        except Exception as exc:
            defect_sources.append(("header", exc))

        for source, defect in defect_sources:
            code = type(defect).__name__
            description = _MIME_DEFECT_DESCRIPTIONS.get(code) or str(defect).strip()
            if not description:
                description = "The email parser reported a malformed MIME construct."
            if add({
                "kind": "parser_defect",
                "code": code,
                "level": _mime_defect_level(code),
                "part_path": path,
                "header": None if source == "message" else source,
                "message": f"MIME part {path}: {description}",
            }):
                defect_count += 1

    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    findings.sort(key=lambda item: severity_order.get(str(item.get("level") or ""), 4))
    return findings[:_MIME_FINDING_LIMIT], defect_count, duplicate_count, review_count, notice_count


def _alternative_comparison_tokens(value: str) -> list[str]:
    value = unicodedata.normalize("NFKC", value or "").lower()
    # Link destinations are analysed separately. Ignore their raw length here
    # so ordinary marketing text/plain fallbacks do not look divergent merely
    # because they spell out tracking URLs hidden behind HTML buttons.
    value = _RAW_URL_TOKEN_RE.sub(" ", value)
    return re.findall(r"[\w@.-]{2,}", value, flags=re.UNICODE)


def _alternative_pair_is_divergent(left: dict, right: dict, similarity: float) -> bool:
    largest = max(int(left.get("token_count") or 0), int(right.get("token_count") or 0))
    if largest < 6:
        return False
    smallest = min(int(left.get("token_count") or 0), int(right.get("token_count") or 0))
    severe_length_gap = smallest / max(largest, 1) < 0.30
    return similarity < 0.55 or (severe_length_gap and similarity < 0.72)


def _alternative_similarity(left_tokens: list[str], right_tokens: list[str]) -> float:
    """Compare meaning-bearing tokens without over-penalising HTML reordering.

    Sequence similarity catches substitutions, while multiset Dice overlap
    recognizes equivalent text whose layout changes token order. Taking the
    stronger score reduces false positives without hiding a large extra lure
    inserted into only one alternative.
    """
    if not left_tokens and not right_tokens:
        return 1.0
    if not left_tokens or not right_tokens:
        return 0.0
    left_counts = Counter(left_tokens)
    right_counts = Counter(right_tokens)
    shared = sum((left_counts & right_counts).values())
    dice = (2.0 * shared) / (len(left_tokens) + len(right_tokens))
    sequence = SequenceMatcher(None, left_tokens, right_tokens).ratio()
    return max(sequence, dice)


def _analyze_mime_alternatives(body_variants: list[dict]) -> tuple[dict, set[str]]:
    groups: dict[str, list[dict]] = {}
    for variant in body_variants:
        for group_path in variant.get("alternative_groups") or ():
            groups.setdefault(group_path, []).append(variant)

    group_results: list[dict] = []
    divergent_paths: set[str] = set()
    for group_path, variants in groups.items():
        if len(variants) < 2:
            continue
        metadata = []
        token_sequences: dict[str, list[str]] = {}
        for variant in variants:
            tokens = _alternative_comparison_tokens(str(variant.get("text") or ""))
            token_sequences[variant["path"]] = tokens
            metadata.append({
                "part_path": variant["path"],
                "content_type": variant["content_type"],
                "effective_content_type": variant["effective_content_type"],
                "character_count": len(str(variant.get("text") or "")),
                "token_count": len(tokens),
            })

        minimum_similarity = 1.0
        divergent = False
        for left_index, left in enumerate(metadata):
            for right in metadata[left_index + 1:]:
                left_tokens = token_sequences[left["part_path"]]
                right_tokens = token_sequences[right["part_path"]]
                if not left_tokens and not right_tokens:
                    similarity = 1.0
                else:
                    similarity = _alternative_similarity(left_tokens, right_tokens)
                minimum_similarity = min(minimum_similarity, similarity)
                if _alternative_pair_is_divergent(left, right, similarity):
                    divergent = True
                    divergent_paths.update({left["part_path"], right["part_path"]})

        group_results.append({
            "part_path": group_path,
            "alternative_count": len(metadata),
            "content_types": list(dict.fromkeys(item["content_type"] for item in metadata)),
            "minimum_similarity": round(minimum_similarity, 3),
            "divergent": divergent,
            "alternatives": metadata,
        })

    divergent_count = sum(1 for group in group_results if group["divergent"])
    if not group_results:
        status = "not_applicable"
        message = "No multipart/alternative body with multiple text variants was found."
    elif divergent_count:
        status = "divergent"
        message = (
            f"{divergent_count} multipart/alternative group(s) contain substantially "
            "different visible content; every divergent variant is included in AI analysis."
        )
    else:
        status = "consistent"
        message = "MIME text alternatives contain materially consistent visible content."
    return ({
        "status": status,
        "groups_analyzed": len(group_results),
        "divergent_group_count": divergent_count,
        "groups": group_results,
        "message": message,
    }, divergent_paths)


def _combine_divergent_alternatives(body_variants: list[dict], paths: set[str]) -> str:
    sections: list[str] = []
    seen_content: set[str] = set()
    for variant in body_variants:
        if variant.get("path") not in paths:
            continue
        selected = select_body_for_ai(str(variant.get("text") or ""))
        text = str(selected.get("body_ai") or variant.get("text") or "").strip()
        comparison_key = " ".join(_alternative_comparison_tokens(text))
        if not text or comparison_key in seen_content:
            continue
        seen_content.add(comparison_key)
        content_type = variant.get("effective_content_type") or variant.get("content_type") or "text"
        sections.append(
            f"[MIME alternative: {content_type}, part {variant['path']}]\n{text}"
        )
    return "\n\n".join(sections).strip()


def _validate_mime_structure(msg) -> None:
    """Reject MIME trees designed to consume excessive parser resources."""
    stack = [(msg, 1)]
    part_count = 0
    while stack:
        part, depth = stack.pop()
        part_count += 1
        if part_count > MAX_MIME_PARTS:
            raise EmailAnalysisLimitError(
                f"Email contains more than {MAX_MIME_PARTS} MIME parts."
            )
        if depth > MAX_MIME_DEPTH:
            raise EmailAnalysisLimitError(
                f"Email MIME nesting exceeds {MAX_MIME_DEPTH} levels."
            )
        if part.is_multipart():
            stack.extend(
                (child, depth + 1)
                for child in reversed(list(part.iter_parts()))
            )


def _is_public_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        return ipaddress.ip_address(value.strip("[]")).is_global
    except ValueError:
        return False


class EmlSOCAnalyzer:
    """
    Parsa un file .eml grezzo e restituisce un report strutturato per il triage SOC.
    All logic is extracted dynamically from the email - no hardcoding
    legato a messaggi specifici.
    """

    def analyze(
        self,
        eml_path: str,
        source_mime_findings: Optional[list[dict]] = None,
    ) -> dict:
        with open(eml_path, "rb") as f:
            raw_bytes = f.read()
        msg = email.message_from_bytes(raw_bytes, policy=policy.default)
        _validate_mime_structure(msg)
        report: dict = {}
        report["raw_eml_bytes"] = raw_bytes
        try:
            report["raw_eml_preview"] = _redacted_eml_preview(raw_bytes)
        except Exception as exc:
            # Source rendering is an investigation aid and must never prevent
            # the underlying security analysis of an unusual but parseable EML.
            report["raw_eml_preview"] = ""
            report["raw_eml_preview_error"] = (
                f"Raw EML preview could not be generated: {type(exc).__name__}"
            )

        # ── 1. Campi envelope ──────────────────────────────────────────────
        report["delivered_to"] = self._header(msg, "Delivered-To")
        report["to"]           = self._header(msg, "To")
        report["from_"]        = self._header(msg, "From")
        report["from_registered_domain"] = registered_domain(
            _extract_domain(report["from_"] or "")
        )
        report["subject"]      = self._header(msg, "Subject")
        report["date"]         = self._header(msg, "Date")
        report["message_id"]   = self._header(msg, "Message-Id")
        report["importance"]   = self._header(msg, "Importance") or self._header(msg, "X-Priority")
        report["mime_version"] = self._header(msg, "MIME-Version")
        report["content_type"] = self._header(msg, "Content-Type")
        bulk_sender_signals = _bulk_sender_signals(msg)
        report["bulk_sender_signals"] = bulk_sender_signals
        report["bulk_sender_signal_count"] = len(bulk_sender_signals)
        report["is_bulk_sender"] = len(bulk_sender_signals) >= BULK_SENDER_SIGNAL_THRESHOLD

        # ── 2. Return-Path / Errors-To / Reply-To ─────────────────────────
        return_path = self._header(msg, "Return-Path")
        if return_path == "<>":
            return_path = None
        report["return_path"] = return_path
        report["errors_to"]   = self._header(msg, "Errors-To")
        reply_to              = self._header(msg, "Reply-To")
        report["reply_to"]    = reply_to

        from_addr  = self._extract_address(report["from_"])
        reply_addr = self._extract_address(reply_to)
        reply_to_mismatch_raw = bool(
            reply_addr and from_addr and reply_addr.lower() != from_addr.lower()
        )
        report["reply_to_mismatch_legitimate"] = (
            reply_to_mismatch_raw
            and _reply_to_mismatch_looks_legitimate(msg, from_addr, reply_addr)
        )
        report["reply_to_mismatch"] = bool(
            reply_to_mismatch_raw and not report["reply_to_mismatch_legitimate"]
        )

        return_path_addr   = self._extract_address(report["return_path"])
        return_path_domain = _extract_domain(return_path_addr or "") if return_path_addr else ""
        from_domain        = _extract_domain(from_addr or "") if from_addr else ""
        report["return_path_domain_mismatch"] = bool(
            return_path_domain and from_domain
            and not same_registered_domain(return_path_domain, from_domain)
        )
        report["return_path_domain"] = return_path_domain

        # Display Name Spoofing: the display name contains an address different from the real sender
        display_name_email_match = None
        if report["from_"]:
            dn_match = re.match(r'^"?([^"<]+)"?\s*<', report["from_"])
            if dn_match:
                dn = dn_match.group(1).strip()
                embedded = re.search(r"[\w.+\-]+@[\w.\-]+", dn)
                if embedded:
                    embedded_addr = embedded.group(0).lower()
                    if from_addr and embedded_addr != from_addr.lower():
                        display_name_email_match = embedded_addr
        report["display_name_spoofing"] = display_name_email_match

        # ── 3. Metadata Google / routing ──────────────────────────────────
        report["x_google_smtp_source"] = self._header(msg, "X-Google-Smtp-Source")
        report["x_received"]           = self._header(msg, "X-Received")

        # ── 4. Header ARC ─────────────────────────────────────────────────
        report["arc_seal"]                   = self._header(msg, "ARC-Seal")
        report["arc_message_signature"]      = self._header(msg, "ARC-Message-Signature")
        report["arc_authentication_results"] = "\n".join(
            self._headers(msg, "ARC-Authentication-Results")
        )

        # ── 5. Catena Received ────────────────────────────────────────────
        raw_received = msg.get_all("Received") or []
        if len(raw_received) > MAX_RECEIVED_HOPS:
            raise EmailAnalysisLimitError(
                f"Email contains more than {MAX_RECEIVED_HOPS} routing hops."
            )
        hops = [parse_received_hop(r) for r in raw_received]
        report["received_hops"]         = hops
        report["closest_to_recipient"]  = hops[0]  if hops else {}
        report["injection_server"]      = hops[1]  if len(hops) > 1 else {}
        report["closest_to_sender"]     = hops[-1] if hops else {}
        report["injection_sender_ip"]   = self._extract_injection_sender_ip(msg, hops)

        # ── 6. Received-SPF raw ───────────────────────────────────────────
        received_spf_headers = self._headers(msg, "Received-SPF")
        report["received_spf_raw"] = "\n".join(received_spf_headers)
        report["received_spf_results"] = parse_received_spf_results(received_spf_headers)

        # ── 7. Authentication-Results ─────────────────────────────────────
        auth_headers = self._headers(msg, "Authentication-Results")
        arc_auth_headers = self._headers(msg, "ARC-Authentication-Results")
        auth_raw     = "\n".join(auth_headers)
        arc_auth_raw = "\n".join(arc_auth_headers)
        report["authentication_results_raw"] = auth_raw
        report["auth_results"]     = parse_auth_results(auth_raw)
        report["arc_auth_results"] = parse_auth_results(arc_auth_raw)
        report["effective_auth_results"] = select_effective_auth_results(
            auth_headers,
            arc_auth_headers,
            received_spf_headers,
        )
        report["authentication_checkpoints"] = build_authentication_checkpoints(
            auth_headers,
            arc_auth_headers,
            received_spf_headers,
            hops,
        )

        # ── 8. Firma DKIM ─────────────────────────────────────────────────
        dkim_headers = self._headers(msg, "DKIM-Signature")
        report["dkim_signature_present"] = bool(dkim_headers)
        report["dkim_signature_raw"]     = "\n".join(dkim_headers)

        # ── 9. Body e allegati ────────────────────────────────────────────
        body_parts       = []
        html_parts       = []
        body_variants    = []
        attachments_info = []
        archive_budget = ArchiveAnalysisBudget()
        plain_noise_removed_lines = 0
        plain_noise_removed_chars = 0
        decoded_text_chars = 0

        for part in msg.walk():
            ct       = part.get_content_type()
            disp     = str(part.get("Content-Disposition") or "")
            encoding = str(part.get("Content-Transfer-Encoding") or "").lower().strip()
            filename = part.get_filename() or ""
            is_attach = "attachment" in disp.lower()

            if is_attach or filename:
                if len(attachments_info) >= MAX_ATTACHMENTS:
                    raise EmailAnalysisLimitError(
                        f"Email contains more than {MAX_ATTACHMENTS} attachments."
                    )
                raw_payload = part.get_payload(decode=True)
                attachment_info = analyze_attachment(
                    filename=filename,
                    content_type=ct,
                    encoding=encoding,
                    raw_payload=raw_payload,
                    archive_budget=archive_budget,
                )
                disposition_type = str(part.get_content_disposition() or "").lower()
                content_id = str(part.get("Content-ID") or "").strip().strip("<>")
                is_inline_resource = (
                    not is_attach
                    and (
                        disposition_type == "inline"
                        or (bool(content_id) and ct.startswith("image/"))
                    )
                )
                attachment_info.update({
                    "content_disposition": disposition_type,
                    "content_id": content_id,
                    "mime_role": (
                        "inline_resource"
                        if is_inline_resource
                        else "attachment"
                    ),
                    "actionable": not is_inline_resource,
                })
                attachments_info.append(attachment_info)

        for part, part_path, alternative_groups in _iter_body_leaf_parts(msg):
            ct = part.get_content_type()
            if ct == "text/plain":
                text = _decode_text_part(part)
                effective_content_type = "text/plain"
                variant_text = ""
                if text and text.strip():
                    decoded_text_chars += len(text)
                    if decoded_text_chars > MAX_DECODED_TEXT_CHARS:
                        raise EmailAnalysisLimitError(
                            "Decoded email text exceeds the supported analysis limit."
                        )
                    if _looks_like_html(text):
                        html_parts.append(text)
                        effective_content_type = "text/html"
                        variant_text = strip_html_for_intent(text)
                    else:
                        text, removed_lines, removed_chars = _strip_plaintext_noise_blocks(text)
                        plain_noise_removed_lines += removed_lines
                        plain_noise_removed_chars += removed_chars
                        if text:
                            body_parts.append(text)
                            variant_text = text
                if alternative_groups:
                    body_variants.append({
                        "path": part_path,
                        "alternative_groups": alternative_groups,
                        "content_type": ct,
                        "effective_content_type": effective_content_type,
                        "text": variant_text,
                    })
            elif ct == "text/html":
                text = _decode_text_part(part)
                variant_text = ""
                if text and text.strip():
                    decoded_text_chars += len(text)
                    if decoded_text_chars > MAX_DECODED_TEXT_CHARS:
                        raise EmailAnalysisLimitError(
                            "Decoded email text exceeds the supported analysis limit."
                        )
                    html_parts.append(text)
                    variant_text = strip_html_for_intent(text)
                if alternative_groups:
                    body_variants.append({
                        "path": part_path,
                        "alternative_groups": alternative_groups,
                        "content_type": ct,
                        "effective_content_type": "text/html",
                        "text": variant_text,
                    })

        combined_html = "\n".join(html_parts)
        html_clean = strip_html(combined_html) if combined_html else ""
        plain_clean = re.sub(r"\n{3,}", "\n\n", "\n".join(body_parts)).strip() if body_parts else ""
        mime_alternative_analysis, divergent_alternative_paths = _analyze_mime_alternatives(
            body_variants
        )
        prefer_html_for_ai = _prefer_html_over_link_heavy_plain(plain_clean, html_clean)
        body_clean = html_clean if prefer_html_for_ai else (plain_clean or html_clean)

        report["body"] = body_clean
        report["body_html"] = combined_html.strip() if html_parts else None
        report["body_html_safe"] = sanitize_html_for_preview(combined_html) if html_parts else None
        report["body_html_clean"] = html_clean
        report["body_plain_clean"] = plain_clean
        report["mime_alternative_analysis"] = mime_alternative_analysis
        report["html_form_analysis"] = analyze_html_forms(
            combined_html,
            from_domain=_extract_domain(from_addr or ""),
        )
        report["html_copy_deception"] = analyze_html_copy_deception(combined_html)
        report["body_clean"] = body_clean

        report["body_source"] = (
            "text/html (preferred over link-heavy plain text)"
            if prefer_html_for_ai
            else "text/plain" if body_parts else ("text/html" if html_parts else "empty")
        )
        report["html_strip_applied"] = bool(html_parts)
        report["body_plain_tracking_url_count"] = len(_RAW_URL_TOKEN_RE.findall(plain_clean))
        report["body_selected_html_for_ai"] = prefer_html_for_ai
        report["body_plain_noise_removed_lines"] = plain_noise_removed_lines
        report["body_plain_noise_removed_chars"] = plain_noise_removed_chars
        report["attachments"] = attachments_info
        plain_ai_selection = select_body_for_ai(report["body_clean"])
        report.update(plain_ai_selection)
        plain_body_for_ai = report.get("body_ai") or report["body_clean"]
        report["body_clean_full"] = report["body_clean"]
        html_body_for_intent = (
            strip_html_for_intent(combined_html) if combined_html else ""
        )
        html_ai_selection = (
            select_body_for_ai(html_body_for_intent)
            if html_body_for_intent
            else {}
        )
        plain_is_structured = plain_ai_selection.get("body_context") in {"forwarded", "reply"}
        html_is_structured = html_ai_selection.get("body_context") in {"forwarded", "reply"}
        # HTML-to-text normalization can flatten a visible forwarding separator.
        # Preserve an already detected plain-text reply/forward boundary rather
        # than replacing it with a multi-year thread from the HTML alternative.
        if html_is_structured:
            report.update(html_ai_selection)
            selected_body_for_intent = html_ai_selection.get("body_ai") or html_body_for_intent
        elif plain_is_structured:
            selected_body_for_intent = plain_body_for_ai
        else:
            report.update(html_ai_selection)
            selected_body_for_intent = html_body_for_intent or plain_body_for_ai
        report["body_for_intent"] = selected_body_for_intent.strip()
        # Apply reply/signature/footer selection to the structurally cleaned
        # text when an explicit HTML signature was actually removed. Otherwise
        # retain the canonical plain alternative, which may contain legitimate
        # details omitted from a divergent HTML alternative.
        bert_source = report["body_for_intent"]
        if not plain_is_structured and not html_is_structured and not (
            combined_html and html_body_for_intent != html_clean
        ):
            bert_source = plain_body_for_ai
        final_ai_selection = select_body_for_ai(bert_source)
        report.update(final_ai_selection)
        if plain_is_structured and final_ai_selection.get("body_context") == "normal":
            # ``bert_source`` is already the selected payload, so it no longer
            # contains the delimiter that originally proved it was forwarded.
            report["body_context"] = plain_ai_selection["body_context"]
            for key in (
                "body_ai_removed_quoted_lines",
                "body_ai_removed_header_lines",
                "body_ai_removed_tail_lines",
            ):
                report[key] = plain_ai_selection.get(key, report.get(key, 0))
        report["body_extracted"] = report.get("body_ai") or bert_source
        report["body_for_ai"] = report["body_extracted"].strip()
        # Both AI engines must consume the same reply/forward/footer-cleaned
        # content. Keeping the earlier intent source here would reintroduce
        # legal notices and contact cards for Ollama only.
        report["body_for_intent"] = report["body_for_ai"]
        if mime_alternative_analysis["status"] == "divergent":
            combined_alternatives = _combine_divergent_alternatives(
                body_variants,
                divergent_alternative_paths,
            )
            if combined_alternatives:
                report["body_ai"] = combined_alternatives
                report["body_extracted"] = combined_alternatives
                report["body_for_ai"] = combined_alternatives
                report["body_for_intent"] = combined_alternatives
                report["body_context"] = "mime_alternatives"
                report["body_source"] = "multipart/alternative (all divergent variants)"

        (
            mime_findings,
            mime_defect_count,
            mime_duplicate_header_count,
            mime_review_finding_count,
            mime_notice_finding_count,
        ) = _collect_mime_findings(msg)
        if source_mime_findings:
            mime_findings.extend(dict(finding) for finding in source_mime_findings)
            mime_review_finding_count += sum(
                1 for finding in source_mime_findings
                if finding.get("level") in {"HIGH", "MEDIUM"}
            )
            mime_notice_finding_count += sum(
                1 for finding in source_mime_findings
                if finding.get("level") in {"LOW", "INFO"}
            )
            severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
            mime_findings.sort(
                key=lambda item: severity_order.get(str(item.get("level") or ""), 4)
            )
            mime_findings = mime_findings[:_MIME_FINDING_LIMIT]
        report["mime_findings"] = mime_findings
        report["mime_defect_count"] = mime_defect_count
        report["mime_duplicate_header_count"] = mime_duplicate_header_count
        report["mime_review_finding_count"] = mime_review_finding_count
        report["mime_notice_finding_count"] = mime_notice_finding_count
        report["mime_status"] = (
            "review"
            if report["mime_review_finding_count"] or mime_alternative_analysis["status"] == "divergent"
            else "notice" if mime_findings else "clean"
        )
        report["ai_analysis_supported"] = (
            len(report["body_for_ai"]) <= MAX_AI_BODY_CHARS
        )
        report["ai_analysis_limit_message"] = (
            ""
            if report["ai_analysis_supported"]
            else (
                "The email body exceeds the supported AI analysis limit "
                f"of {MAX_AI_BODY_CHARS:,} characters. Static checks remain available."
            )
        )

        # ── 10. Link e lookalike ──────────────────────────────────────────
        report["links"] = extract_links(
            body_plain=plain_clean,
            body_html=report.get("body_html") or "",
            embedded_urls=[
                {"url": url, "label": attachment.get("filename") or "Attachment URL", "source": "attachment"}
                for attachment in attachments_info
                for url in (attachment.get("embedded_urls") or [])
            ],
        )
        # `mailto:` actions are retained for identity coherence, but are not
        # web destinations and therefore must not alter Streamlit-equivalent
        # lookalike/typosquatting checks.
        report["lookalike_alerts"] = check_lookalike_domains([
            link for link in report["links"]
            if str(link.get("scheme") or "").lower() in {"http", "https"}
            and link.get("actionable") is not False
        ])
        report["link_context_alerts"] = self._assess_link_context(report)

        # ── 11. Flag SOC ──────────────────────────────────────────────────
        report["flags"] = self._build_flags(report)

        return report

    # ── Helpers ────────────────────────────────────────────────────────────

    @staticmethod
    def _assess_link_context(report: dict) -> list[dict]:
        """Correlate invoice claims with the actual downloadable resource.

        A third-party CDN is not inherently malicious. It becomes relevant only
        when a financial email claims a document is attached, no usable MIME
        attachment exists, and the recipient is instead directed to a foreign
        host. A script/executable filename upgrades that finding to high risk.
        """
        body = str(report.get("body_for_ai") or report.get("body_clean") or "")
        if not _claims_financial_attachment(body):
            return []
        if any(item.get("actionable") is not False for item in report.get("attachments", [])):
            return []

        sender_domain = registered_domain(_extract_domain(str(report.get("from_") or "")))
        if not sender_domain:
            return []

        alerts: list[dict] = []
        for link in report.get("links", []):
            if str(link.get("scheme") or "").lower() == "mailto":
                continue
            if link.get("actionable") is False:
                continue
            host = registered_domain(str(link.get("host") or ""))
            if not host or host == sender_domain:
                continue
            dangerous_download = bool(link.get("dangerous_download"))
            filename = str(link.get("download_filename") or "download")
            level = "HIGH" if dangerous_download else "MEDIUM"
            message = (
                "The message claims a financial document is attached, but no usable MIME attachment is present; "
                f"the actionable resource is hosted on unrelated domain `{host}`."
            )
            if dangerous_download:
                message += f" Its URL filename `{filename}` has a potentially executable/script extension."
            link["financial_attachment_mismatch"] = True
            link["context_risk_level"] = level.lower()
            link["context_risk_message"] = message
            alerts.append({"level": level, "host": host, "url": link.get("url") or "", "message": message})
        return alerts

    @staticmethod
    def _header(msg, name: str) -> Optional[str]:
        val = msg.get(name)
        if val is None:
            return None
        return re.sub(r"\s+", " ", str(val)).strip()

    @staticmethod
    def _headers(msg, name: str) -> list[str]:
        return [
            re.sub(r"\s+", " ", str(val)).strip()
            for val in (msg.get_all(name) or [])
            if val is not None
        ]

    @staticmethod
    def _extract_address(raw: Optional[str]) -> Optional[str]:
        if not raw:
            return None
        m = re.search(r"<([^>]+)>", raw)
        if m:
            return m.group(1).strip()
        m2 = re.search(r"[\w.+\-]+@[\w.\-]+", raw)
        return m2.group(0).strip() if m2 else None

    @staticmethod
    def _extract_injection_sender_ip(msg, hops: list) -> str | None:
        """
        Extract the public sender IP exposed by the delivery headers.

        Priority:
          1. client-ip= in the LAST Received-SPF (closest to the sender)
          2. smtp.remote-ip= in Authentication-Results
          3. First public IP in the oldest Received hop

        If the oldest hop is an internal MAPI/Exchange hand-off, no public
        SMTP boundary IP is available.
        """
        all_rcvd_spf = msg.get_all("Received-SPF") or []
        for rcvd_spf in reversed(all_rcvd_spf):
            m = re.search(r"client-ip=([\d.a-fA-F:]+)", str(rcvd_spf), re.IGNORECASE)
            if m and _is_public_ip(m.group(1)):
                return m.group(1)

        auth = str(msg.get("Authentication-Results") or "")
        m = re.search(r"smtp\.remote-ip=([\d.]+)", auth, re.IGNORECASE)
        if m and _is_public_ip(m.group(1)):
            return m.group(1)

        if hops:
            last_hop = hops[-1]
            for ip in (last_hop.get("all_ips") or []):
                if _is_public_ip(ip):
                    return ip

        return None

    @staticmethod
    def _build_flags(report: dict) -> list[dict]:
        flags = []

        def flag(level: str, field: str, message: str):
            flags.append({"level": level, "field": field, "message": message})

        # SPF: useful for triage, but auth-only findings should not dominate verdicts.
        effective = report.get("effective_auth_results") or {}
        spf = effective.get("SPF") or report["auth_results"].get("SPF") or report["arc_auth_results"].get("SPF")
        if spf:
            spf_status = (spf.get("status") or "unknown").lower()
            if spf.get("sender_boundary_selected") and spf.get("path_conflict"):
                delivery_status = str(spf.get("delivery_status") or "unknown").upper()
                origin_status = str(spf.get("origin_status") or "unknown").upper()
                flag(
                    "MEDIUM",
                    "SPF",
                    f"SPF {origin_status} at the sender boundary; the final receiver reported {delivery_status} for a later relay",
                )
            elif spf_status == "mixed":
                flag("MEDIUM", "SPF", "SPF results differ across the delivery path")
            elif spf_status != "pass":
                flag("MEDIUM", "SPF", f"SPF {spf_status.upper()} - sender authorization should be reviewed")
        # An EML export can legitimately omit all delivery/authentication
        # headers.  Absence of an SPF result is not equivalent to an SPF
        # failure, so keep it informational and let the UI show it as
        # unavailable rather than turning it into a risk signal.
        else:
            flag("INFO", "SPF", "No SPF result is available in this EML export")

        # DKIM: missing/none is an absence of evidence, not a strong malicious signal.
        dkim = effective.get("DKIM") or report["auth_results"].get("DKIM") or report["arc_auth_results"].get("DKIM")
        dkim_status = (dkim.get("status") or "") .lower() if dkim else ""
        if dkim_status == "none":
            flag("INFO", "DKIM", "No DKIM signature result is available in this EML export")
        elif dkim_status and dkim_status != "pass":
            flag("MEDIUM", "DKIM", f"DKIM {dkim_status.upper()} - signature validation should be reviewed")
        elif not report["dkim_signature_present"]:
            flag("INFO", "DKIM", "No DKIM signature is available in this EML export")

        # DMARC
        dmarc = effective.get("DMARC") or report["auth_results"].get("DMARC") or report["arc_auth_results"].get("DMARC")
        dmarc_status = str((dmarc or {}).get("status") or "").lower()
        if dmarc and dmarc_status == "none":
            flag("INFO", "DMARC", "No DMARC authentication result is available in this EML export")
        elif dmarc and dmarc_status not in ("pass", "bestguesspass"):
            flag("MEDIUM", "DMARC", f"DMARC {dmarc_status.upper()}")
        elif not dmarc:
            flag("INFO", "DMARC", "No DMARC result is available in this EML export")

        # Reply-To mismatch
        if report["reply_to_mismatch"]:
            flag("HIGH", "Reply-To",
                 f"Reply-To ({report['reply_to']}) differs da From ({report['from_']}) - possible harvesting")
        elif report.get("reply_to_mismatch_legitimate"):
            flag(
                "INFO",
                "Reply-To",
                f"Reply-To ({report['reply_to']}) differs from From ({report['from_']}), "
                "but matches a common legitimate routing pattern.",
            )

        # Return-Path domain mismatch
        if report.get("return_path_domain_mismatch"):
            _from_domain = _extract_domain(
                EmlSOCAnalyzer._extract_address(report.get("from_") or "") or ""
            )
            is_bulk_sender = bool(report.get("is_bulk_sender"))
            bulk_count = int(report.get("bulk_sender_signal_count") or 0)
            bulk_note = (
                f"Bulk sender detected ({bulk_count} header signals), so this mismatch can be legitimate."
                if is_bulk_sender
                else f"Bulk sender not detected ({bulk_count} header signals), so this mismatch is more suspicious."
            )
            mismatch = (
                f"The Return-Path domain (`{report['return_path_domain']}`) differs from "
                f"the From domain (`{_from_domain}`)."
            )
            if dmarc_status in {"pass", "bestguesspass"}:
                # DMARC already proves identifier alignment. Keep the raw mismatch
                # in the report, but do not turn normal envelope routing into a verdict signal.
                pass
            elif dmarc_status in {"fail", "softfail", "temperror", "permerror", "policy", "reject", "quarantine"}:
                flag(
                    "LOW" if is_bulk_sender else "MEDIUM",
                    "Return-Path",
                    f"{mismatch} DMARC did not pass ({dmarc_status.upper()}), so the mismatch is relevant technical context. {bulk_note}",
                )
            else:
                flag(
                    "LOW",
                    "Return-Path",
                    f"{mismatch} DMARC is unavailable, so this is weak evidence that must be correlated with other signals. {bulk_note}",
                )
        elif report.get("return_path") and not report.get("return_path_domain"):
            flag("LOW", "Return-Path", "Return-Path present but domain cannot be extracted")

        mime_findings = report.get("mime_findings") or []
        for finding in mime_findings[:10]:
            flag(
                str(finding.get("level") or "MEDIUM"),
                "MIME structure",
                str(finding.get("message") or "The MIME structure requires review."),
            )
        total_mime_findings = int(report.get("mime_review_finding_count") or 0) + int(
            report.get("mime_notice_finding_count") or 0
        )
        omitted_mime_findings = max(0, total_mime_findings - 10)
        if omitted_mime_findings:
            flag(
                "MEDIUM" if report.get("mime_review_finding_count") else "LOW",
                "MIME structure",
                f"{omitted_mime_findings} additional MIME finding(s) are available in the structured report.",
            )

        alternative_analysis = report.get("mime_alternative_analysis") or {}
        if alternative_analysis.get("status") == "divergent":
            flag(
                "MEDIUM",
                "MIME alternatives",
                str(alternative_analysis.get("message") or "Visible MIME alternatives differ substantially."),
            )

        # HTML stripping applicato
        if report.get("html_strip_applied"):
            body_source = str(report.get("body_source") or "")
            message = (
                "Email body is HTML: tags were removed before AI analysis. "
                "Possible hidden text obfuscation in tags."
                if body_source.startswith("text/html")
                else "An HTML alternative was normalized and compared with the plain-text body before AI analysis."
            )
            flag("INFO", "Body", message)

        form_analysis = report.get("html_form_analysis") or {}
        form_status = str(form_analysis.get("status") or "").lower()
        for form in (form_analysis.get("forms") or [])[:5]:
            risk = str(form.get("risk") or "").lower()
            if risk not in {"high", "medium"}:
                continue
            level = "HIGH" if risk == "high" else "MEDIUM"
            destination = form.get("action_host") or form.get("action_kind") or "unknown destination"
            sensitive = ", ".join(form.get("sensitive_fields") or [])
            detail = f"HTML form ({form.get('method') or 'GET'}) targets {destination}. {form.get('message') or ''}"
            if sensitive:
                detail += f" Sensitive fields: {sensitive}."
            flag(level, "HTML Form", detail)

        copy_deception = report.get("html_copy_deception") or {}
        for finding in (copy_deception.get("findings") or [])[:5]:
            severity = str(finding.get("severity") or "medium").lower()
            if severity not in {"high", "medium"}:
                continue
            paths = ", ".join(
                f"`{path}`" for path in (finding.get("dangerous_paths") or [])[:3]
            )
            detail = str(
                finding.get("message")
                or "The HTML contains a potentially deceptive copy/paste surface."
            )
            if paths:
                detail += f" Detected path: {paths}."
            flag(
                "HIGH" if severity == "high" else "MEDIUM",
                "HTML copy deception",
                detail,
            )

        # Display Name Spoofing
        dns_val = report.get("display_name_spoofing")
        if dns_val:
            flag(
                "HIGH", "Display Name",
                f"The Display Name in the From field contains an email address (`{dns_val}`). "
                "Classic Display Name Spoofing technique: email clients show "
                "the embedded address instead of the real sender."
            )

        # Injection server
        inj = report.get("injection_server", {})
        if inj.get("sender_ip"):
            flag("INFO", "Received",
                 f"Injection server: {inj.get('sender_domain') or inj.get('from_host', '?')} "
                 f"[{inj['sender_ip']}] - verify IP/domain reputation")

        # Anomalie allegati
        for att in report.get("attachments", []):
            attachment_anomaly = _non_pdf_attachment_anomaly(att)
            if attachment_anomaly:
                flag("HIGH", "Attachment",
                     f"'{att['filename']}': {attachment_anomaly}")
            pdf_security = att.get("pdf_security") or {}
            archive_security = att.get("archive_security") or {}
            for behavior in (pdf_security.get("behaviors") or [])[:8]:
                flag(
                    _pdf_indicator_flag_level(behavior.get("severity")),
                    "PDF Content",
                    f"'{att['filename']}': internal PDF behavior - "
                    f"{behavior.get('label') or behavior.get('key') or 'behavior'} "
                    f"x{behavior.get('count') or 1} "
                    f"(pdf_risk={pdf_security.get('risk_level') or 'unknown'})",
                )
            if pdf_security.get("suspicious"):
                flag(
                    "HIGH",
                    "PDF Attachment",
                    f"'{att['filename']}': risky PDF features detected - {pdf_security.get('summary')}",
                )
            elif pdf_security.get("risk_level") in {"medium", "low"}:
                flag(
                    "INFO",
                    "PDF Attachment",
                     f"'{att['filename']}': PDF static scan - {pdf_security.get('summary')}",
                )
            for finding in (archive_security.get("findings") or [])[:8]:
                risk = str(finding.get("severity") or "").lower()
                if risk not in {"high", "medium"}:
                    continue
                flag(
                    "HIGH" if risk == "high" else "MEDIUM",
                    "Archive / Office",
                    f"'{att['filename']}': {finding.get('label') or finding.get('key')} x{finding.get('count') or 1}",
                )
            if att.get("magic_bytes_hex"):
                flag("INFO", "Attachment",
                     f"'{att['filename']}': magic bytes {att['magic_bytes_hex'][:8]}... "
                     f"-> detected format: {att['magic_detected_format'] or 'unknown'}")

        # Link anomalie: IP-direct e lookalike
        html_ctas = [
            link for link in report.get("links", [])
            if link.get("html_call_to_action")
            and link.get("actionable") is not False
        ]
        if html_ctas:
            destinations = ", ".join(
                str(link.get("host") or "URL") for link in html_ctas[:3]
            )
            flag(
                "INFO",
                "HTML Call-to-Action",
                f"{len(html_ctas)} clickable HTML button/link destination(s) detected: {destinations}",
            )
        for alert in report.get("link_context_alerts", []):
            flag(
                str(alert.get("level") or "MEDIUM"),
                "Invoice delivery",
                str(alert.get("message") or "Financial document delivery requires review."),
            )
        for lnk in report.get("links", []):
            # Defense in depth for reports produced by older link parsers:
            # email actions are never downloadable resources.
            if str(lnk.get("scheme") or "").lower() == "mailto":
                continue
            # Signature redirects are retained for transparency, but a
            # resolved, non-actionable signature link is not a risk signal.
            if (
                lnk.get("signature_tracking_redirect")
                and not lnk.get("dangerous_download")
            ):
                continue
            if lnk.get("dangerous_download"):
                location = (
                    "nested redirect"
                    if lnk.get("download_source") == "redirect"
                    else "URL path"
                )
                filename = lnk.get("download_filename") or "download"
                flag(
                    "HIGH",
                    "Link",
                    f"{location} exposes potentially executable or script content "
                    f"through filename '{filename}': `{lnk['url']}`",
                )
            if lnk.get("is_ip"):
                flag(
                    "HIGH", "Link",
                    "URL with bare IP detected: `" + lnk["url"] + "` - avoids DNS lookup, "
                    "typical of phishing or C2",
                )
            if lnk.get("has_userinfo") or lnk.get("has_credentials"):
                flag("HIGH", "Link", f"URL uses userinfo before its destination host: `{lnk['url']}`")
            if lnk.get("nested_redirect_count"):
                targets = ", ".join(lnk.get("redirect_hosts") or []) or "hidden target"
                flag("MEDIUM", "Link", f"URL contains {lnk['nested_redirect_count']} nested redirect destination(s): {targets}")
            if lnk.get("nonstandard_port"):
                flag("MEDIUM", "Link", f"URL uses non-standard {lnk.get('scheme', 'web').upper()} port {lnk.get('port')}: `{lnk['url']}`")
            if lnk.get("unicode_path_or_query"):
                flag("MEDIUM", "Link", f"URL path or query contains Unicode characters: `{lnk['url']}`")

        for alert in report.get("lookalike_alerts", []):
            technique_label = {
                "edit_distance": "Edit-distance",
                "homoglyph":     "Unicode homoglyphs",
                "unicode_homoglyph": "Unicode homoglyphs in domain",
                "unicode_domain": "Unicode characters in domain",
                "punycode_idna": "Punycode/IDNA domain",
                "punycode_homograph": "Punycode homograph attack",
                "typosquatting": "Typosquatting",
            }.get(alert["technique"], alert["technique"])
            matched_brand = alert.get("matched_brand") or "-"
            if matched_brand == "-":
                message = technique_label + ": `" + alert["host"] + "` - " + alert["detail"]
            else:
                message = (
                    technique_label + ": `" + alert["host"] + "` looks like `"
                    + matched_brand + "` - " + alert["detail"]
                )
            level = str(alert.get("level") or "HIGH").upper()
            if level not in {"HIGH", "MEDIUM", "LOW", "INFO"}:
                level = "HIGH"
            flag(level, "Lookalike Domain", message)

        return flags
