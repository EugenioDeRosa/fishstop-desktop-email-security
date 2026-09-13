"""Discover and scope inline email conversations before full analysis."""

from __future__ import annotations

import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path

from .html_utils import strip_html_for_intent


_FORWARD_RE = re.compile(
    r"^\s*(?:-{2,}\s*)?(?:forwarded message|messaggio inoltrato|"
    r"inizio messaggio inoltrato)(?:\s*-{2,})?\s*:?-*\s*$",
    re.IGNORECASE,
)
_REPLY_RE = re.compile(
    r"^\s*(?P<label>(?:on|il giorno|luned[iì]|marted[iì]|mercoled[iì]|"
    r"gioved[iì]|venerd[iì]|sabato|domenica|am|le)\b.+?"
    r"(?:wrote|ha scritto|schrieb|a [ée]crit)\s*:)\s*$",
    re.IGNORECASE,
)
_HEADER_RE = re.compile(
    r"^\s*\*{0,2}(?P<label>from|da|de|sent|inviato(?: il)?|enviado el|"
    r"date|data|to|a|para|subject|oggetto|asunto)\*{0,2}\s*:\s*(?P<value>.*)$",
    re.IGNORECASE,
)
_HEADER_KEYS = {
    "from": "from", "da": "from", "de": "from",
    "sent": "date", "inviato": "date", "inviato il": "date",
    "enviado el": "date", "date": "date", "data": "date",
    "to": "to", "a": "to", "para": "to",
    "subject": "subject", "oggetto": "subject", "asunto": "subject",
}
_ACTION_PATTERNS = (
    (re.compile(r"\biban\b|\bbic\b|bank account|conto bancario|cuenta bancaria", re.I), 7),
    (re.compile(r"\bpayment\b|\bpagamento\b|\bpago\b|\btransfer(?:encia)?\b|\bbonifico\b", re.I), 4),
    (re.compile(r"comprobante de pago|proof of payment|prova di pagamento", re.I), 6),
    (re.compile(r"password|credential|credenzial|otp|recovery code", re.I), 7),
    (re.compile(r"https?://|www\.", re.I), 2),
)

_OUTER_DELIVERY_EVIDENCE_KEYS = (
    "from_", "to", "subject", "date", "delivered_to", "return_path", "reply_to",
    "errors_to", "auth_results", "arc_auth_results", "effective_auth_results",
    "received_spf_results", "authentication_checkpoints", "authentication_results_raw",
    "arc_authentication_results", "received_spf_raw", "dkim_signature_present",
    "dkim_signature_raw", "received_hops", "injection_sender_ip", "injection_server",
    "x_received", "spf_sender_aligned", "injection_ip_spf_authorized",
    "return_path_domain", "return_path_domain_mismatch", "reply_to_mismatch",
    "reply_to_mismatch_legitimate", "display_name_spoofing",
)


def _decode_text(part) -> str:
    try:
        value = part.get_content()
        return value if isinstance(value, str) else ""
    except Exception:
        payload = part.get_payload(decode=True)
        if not isinstance(payload, bytes):
            return str(payload or "")
        return payload.decode(part.get_content_charset() or "utf-8", errors="replace")


def _canonical_body(message) -> tuple[str, str]:
    plain_parts: list[str] = []
    html_parts: list[str] = []
    for part in message.walk():
        if part.is_multipart() or part.get_filename() or part.get_content_disposition() == "attachment":
            continue
        if part.get_content_type() == "text/plain":
            plain_parts.append(_decode_text(part))
        elif part.get_content_type() == "text/html":
            html_parts.append(_decode_text(part))
    plain = "\n".join(item for item in plain_parts if item.strip()).strip()
    if plain:
        return plain, "text/plain"
    html = "\n".join(item for item in html_parts if item.strip()).strip()
    return strip_html_for_intent(html).strip(), "text/html" if html else "empty"


def _clean_header_value(value: str) -> str:
    return re.sub(r"[*_`]+", "", re.sub(r"\s+", " ", value or "")).strip()


def _header_block(lines: list[str], start: int) -> tuple[dict[str, str], int]:
    fields: dict[str, str] = {}
    index = start
    saw_header = False
    while index < min(len(lines), start + 14):
        stripped = lines[index].strip()
        if not stripped:
            if saw_header:
                index += 1
                continue
            break
        match = _HEADER_RE.match(lines[index])
        if not match:
            break
        saw_header = True
        key = _HEADER_KEYS[match.group("label").casefold()]
        value = _clean_header_value(match.group("value"))
        if value and key not in fields:
            fields[key] = value
        index += 1
    while index < len(lines) and not lines[index].strip():
        index += 1
    return fields, index


def _reply_fields(label: str) -> dict[str, str]:
    value = re.sub(r"\s+", " ", label).strip()
    address_match = re.search(r"<([^<>\s]+@[^<>\s]+)>", value)
    if address_match:
        sender = address_match.group(1)
    else:
        addresses = re.findall(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", value)
        if addresses:
            sender = addresses[-1]
        else:
            prefix = re.sub(r"^(?:on|il giorno)\s+", "", value, flags=re.I)
            sender = re.sub(r"\s+(?:ha scritto|wrote|schrieb|a [ée]crit)\s*:\s*$", "", prefix, flags=re.I)
    return {"from": _clean_header_value(sender), "date": value}


def _action_score(text: str) -> int:
    return sum(weight for pattern, weight in _ACTION_PATTERNS if pattern.search(text or ""))


def _preview(text: str, limit: int = 230) -> str:
    compact = re.sub(r"\s+", " ", text or "").strip()
    return compact if len(compact) <= limit else compact[:limit].rstrip(" ,;:") + "…"


def _identity_fields(raw_from: str) -> tuple[str, str, str]:
    display_name, address = parseaddr(raw_from or "")
    address = address.lower().strip()
    domain = address.rsplit("@", 1)[-1] if "@" in address else ""
    return display_name, address, domain


def inspect_conversation_bytes(raw_bytes: bytes) -> dict:
    message = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    body, body_source = _canonical_body(message)
    lines = body.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    boundaries: list[dict] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if _FORWARD_RE.match(line):
            header_start = index + 1
            while header_start < len(lines) and not lines[header_start].strip():
                header_start += 1
            fields, content_start = _header_block(lines, header_start)
            boundaries.append({"start": index, "content_start": content_start, "fields": fields, "kind": "forwarded"})
            index = max(index + 1, content_start)
            continue
        header_match = _HEADER_RE.match(line)
        if header_match and _HEADER_KEYS[header_match.group("label").casefold()] == "from":
            fields, content_start = _header_block(lines, index)
            if fields.get("from") and len(fields) >= 2:
                boundaries.append({"start": index, "content_start": content_start, "fields": fields, "kind": "quoted"})
                index = max(index + 1, content_start)
                continue
        reply_match = _REPLY_RE.match(line)
        if reply_match:
            boundaries.append({
                "start": index,
                "content_start": index + 1,
                "fields": _reply_fields(reply_match.group("label")),
                "kind": "quoted",
            })
        index += 1

    outer_end = boundaries[0]["start"] if boundaries else len(lines)
    outer_text = "\n".join(lines[:outer_end]).strip()
    outer_from = str(message.get("From") or "")
    outer_display, outer_address, outer_domain = _identity_fields(outer_from)
    segments = [{
        "id": "outer",
        "position": 0,
        "kind": "delivered",
        "from": outer_from,
        "to": str(message.get("To") or ""),
        "date": str(message.get("Date") or ""),
        "subject": str(message.get("Subject") or ""),
        "display_name": outer_display,
        "address": outer_address,
        "domain": outer_domain,
        "preview": _preview(outer_text) or "No new message text before the forwarded conversation.",
        "text": outer_text,
        "authentication_scope": "outer_delivery",
        "authentication_status": "available",
        "detection_confidence": "verified",
        "action_score": _action_score(outer_text),
        "recommended_role": "context" if boundaries else "target",
        "locked_technical_analysis": True,
    }]
    for offset, boundary in enumerate(boundaries, 1):
        end = boundaries[offset]["start"] if offset < len(boundaries) else len(lines)
        text = "\n".join(lines[boundary["content_start"]:end]).strip()
        fields = boundary["fields"]
        display_name, address, domain = _identity_fields(fields.get("from", ""))
        segments.append({
            "id": f"message-{offset}",
            "position": offset,
            "kind": boundary["kind"],
            "from": fields.get("from", ""),
            "to": fields.get("to", ""),
            "date": fields.get("date", ""),
            "subject": fields.get("subject", str(message.get("Subject") or "")),
            "display_name": display_name,
            "address": address,
            "domain": domain,
            "preview": _preview(text) or "No message text was recovered for this turn.",
            "text": text,
            "authentication_scope": "embedded_content",
            "authentication_status": "unavailable",
            "detection_confidence": "high" if fields.get("from") else "medium",
            "action_score": _action_score(text),
            "recommended_role": "excluded",
            "locked_technical_analysis": False,
        })

    embedded = segments[1:]
    if embedded:
        target = max(embedded, key=lambda item: (item["action_score"], -item["position"]))
        target["recommended_role"] = "target"
        target_position = target["position"]
        for segment in segments:
            if segment["id"] == "outer":
                segment["recommended_role"] = "context"
            elif abs(segment["position"] - target_position) == 1:
                segment["recommended_role"] = "context"

    return {
        "status": "conversation" if len(segments) > 1 else "single",
        "requires_selection": len(segments) > 1,
        "body_source": body_source,
        "message_count": len(segments),
        "segments": segments,
        "technical_scope_message": (
            "SPF, DKIM, DMARC, routing hops and the injection IP apply only to the delivered outer message. "
            "MIME structure and attachments describe the complete delivered file and cannot be assigned with certainty "
            "to an embedded turn. Embedded senders are claims recovered from forwarded content."
            if len(segments) > 1 else
            "Authentication and routing evidence apply to this delivered message."
        ),
    }


def inspect_conversation(path_value: str) -> dict:
    return inspect_conversation_bytes(Path(path_value).read_bytes())


def public_conversation_manifest(manifest: dict) -> dict:
    """Remove full message bodies from UI/report metadata while retaining previews."""
    return {
        **manifest,
        "segments": [
            {key: value for key, value in segment.items() if key != "text"}
            for segment in manifest.get("segments") or []
        ],
    }


def apply_conversation_selection(report: dict, manifest: dict, selection: dict | None) -> dict:
    if not manifest.get("requires_selection") or not selection:
        report["conversation_analysis"] = public_conversation_manifest(manifest)
        return report
    by_id = {item["id"]: item for item in manifest.get("segments") or []}
    target_ids = [item for item in selection.get("target_ids") or [] if item in by_id]
    context_ids = [item for item in selection.get("context_ids") or [] if item in by_id and item not in target_ids]
    prior_context_ids = [
        item for item in selection.get("prior_context_ids") or []
        if item in context_ids
    ]
    later_context_ids = [
        item for item in selection.get("later_context_ids") or []
        if item in context_ids and item not in prior_context_ids
    ]
    if not target_ids:
        target_ids = [item["id"] for item in by_id.values() if item.get("recommended_role") == "target"][:1]
    selected_ids = [*target_ids, *context_ids]
    sections: list[str] = []
    for segment_id in selected_ids:
        segment = by_id[segment_id]
        role = (
            "TARGET"
            if segment_id in target_ids
            else "PRIOR CONTEXT"
            if segment_id in prior_context_ids
            else "LATER FOLLOW-UP CONTEXT"
            if segment_id in later_context_ids
            else "CONTEXT"
        )
        sender = segment.get("from") or "unknown sender"
        sections.append(f"[{role} MESSAGE: {sender}]\n{segment.get('text') or ''}".strip())
    selected_body = "\n\n".join(section for section in sections if section).strip()
    if selected_body:
        report["body_ai"] = selected_body
        report["body_extracted"] = selected_body
        report["body_for_ai"] = selected_body
        report["body_for_intent"] = selected_body
        report["body_context"] = "conversation_selection"
        report["body_source"] = "user-selected conversation messages"
    selected_text = "\n".join(str(by_id[item].get("text") or "") for item in selected_ids).casefold()
    kept_links = []
    excluded_count = 0
    for link in report.get("links") or []:
        candidates = [link.get("url"), link.get("display_text"), link.get("host")]
        if any(str(candidate).casefold() in selected_text for candidate in candidates if candidate):
            link["conversation_scope"] = "selected"
            kept_links.append(link)
        else:
            excluded_count += 1
    report["links"] = kept_links
    report["conversation_excluded_link_count"] = excluded_count
    manifest = {**public_conversation_manifest(manifest), "selection": {
        "target_ids": target_ids,
        "context_ids": context_ids,
        "prior_context_ids": prior_context_ids,
        "later_context_ids": later_context_ids,
        "excluded_ids": [item for item in by_id if item not in selected_ids],
    }}
    report["conversation_analysis"] = manifest
    has_outer_target = "outer" in target_ids
    has_embedded_target = any(item != "outer" for item in target_ids)
    target_authentication_scope = (
        "mixed_outer_and_embedded"
        if has_outer_target and has_embedded_target
        else "outer_delivery"
        if has_outer_target
        else "embedded_unavailable"
    )
    report["selected_target_authentication_scope"] = target_authentication_scope
    report["authentication_scope"] = target_authentication_scope
    report["container_analysis_scope"] = "complete_delivered_file"
    report["selected_message_headers"] = [
        {
            "id": item,
            "from": by_id[item].get("from") or "",
            "to": by_id[item].get("to") or "",
            "subject": by_id[item].get("subject") or "",
            "date": by_id[item].get("date") or "",
            "authentication_status": by_id[item].get("authentication_status") or "unavailable",
        }
        for item in target_ids
    ]
    if target_authentication_scope == "embedded_unavailable":
        report["outer_delivery_evidence"] = {
            key: report.get(key)
            for key in _OUTER_DELIVERY_EVIDENCE_KEYS
            if report.get(key) not in (None, "", [], {})
        }
        selected_targets = [by_id[item] for item in target_ids]
        if len(selected_targets) == 1:
            selected = selected_targets[0]
            report["from_"] = selected.get("from") or "Embedded sender unavailable"
            report["to"] = selected.get("to") or None
            report["subject"] = selected.get("subject") or report.get("subject")
            report["date"] = selected.get("date") or None
            report["from_registered_domain"] = selected.get("domain") or ""
        else:
            senders = list(dict.fromkeys(
                str(item.get("from") or "Unknown embedded sender")
                for item in selected_targets
            ))
            report["from_"] = "; ".join(senders)
            report["to"] = None
            report["date"] = None
            report["from_registered_domain"] = ""
        for key in (
            "authentication_results_raw", "arc_authentication_results", "received_spf_raw",
            "dkim_signature_raw", "delivered_to", "return_path", "reply_to", "errors_to",
            "injection_sender_ip", "x_received", "return_path_domain",
        ):
            report[key] = None
        for key in (
            "auth_results", "arc_auth_results", "effective_auth_results", "received_spf_results",
            "injection_server",
        ):
            report[key] = {}
        for key in ("authentication_checkpoints", "received_hops"):
            report[key] = []
        for key in (
            "dkim_signature_present", "return_path_domain_mismatch", "reply_to_mismatch",
            "reply_to_mismatch_legitimate",
        ):
            report[key] = False
        report["spf_sender_aligned"] = None
        report["injection_ip_spf_authorized"] = None
        report["display_name_spoofing"] = None
        report["forwarded_identity"] = None
    return report
