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
import ipaddress
import re
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
from .attachment      import analyze_attachment
from .body_context    import select_body_for_ai
from .html_utils      import (
    recover_mislabelled_utf7_html,
    sanitize_html_for_preview,
    strip_html,
    strip_html_for_intent,
)
from .link_extractor  import extract_links
from .lookalike       import check_lookalike_domains
from .received_parser import (
    merge_auth_results,
    parse_auth_results,
    parse_received_hop,
    parse_received_spf_results,
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


def _extract_domain(email_or_addr: str) -> str:
    """Returns the domain portion of an email address, lowercased."""
    m = re.search(r"@([\w.\-]+)", email_or_addr or "")
    return m.group(1).lower() if m else ""


def _registered_domain(domain: str) -> str:
    parts = (domain or "").lower().rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain or ""


def _same_registered_domain(left: str, right: str) -> bool:
    return bool(left and right and _registered_domain(left) == _registered_domain(right))


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
    if _same_registered_domain(from_domain, reply_domain):
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
                return recover_mislabelled_utf7_html(payload.decode(candidate, errors="strict"))
            except (LookupError, UnicodeDecodeError):
                continue
        return recover_mislabelled_utf7_html(payload.decode("utf-8", errors="replace"))

    raw_payload = part.get_payload(decode=False)
    if isinstance(raw_payload, str):
        return recover_mislabelled_utf7_html(raw_payload)
    return ""


def _looks_like_html(value: str) -> bool:
    if not value:
        return False
    return bool(re.search(
        r"(?is)<\s*(?:!doctype\s+html|html|body|table|div|span|p|br|a|img|style|head)\b",
        value,
    ))


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


def _iter_body_leaf_parts(part):
    """Yield body leaves without descending into attachments or attached emails."""
    disposition = str(part.get("Content-Disposition") or "").lower()
    if "attachment" in disposition or part.get_filename():
        return
    if part.get_content_type() == "message/rfc822":
        return
    if part.is_multipart():
        for child in part.iter_parts():
            yield from _iter_body_leaf_parts(child)
        return
    yield part


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

    def analyze(self, eml_path: str) -> dict:
        with open(eml_path, "rb") as f:
            raw_bytes = f.read()

        msg = email.message_from_bytes(raw_bytes, policy=policy.default)
        _validate_mime_structure(msg)
        report: dict = {}
        report["raw_eml_bytes"] = raw_bytes

        # ── 1. Campi envelope ──────────────────────────────────────────────
        report["delivered_to"] = self._header(msg, "Delivered-To")
        report["to"]           = self._header(msg, "To")
        report["from_"]        = self._header(msg, "From")
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
            and not _same_registered_domain(return_path_domain, from_domain)
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
        report["injection_sender_ip"]   = self._extract_spf_sender_ip(msg, hops)

        # ── 6. Received-SPF raw ───────────────────────────────────────────
        received_spf_headers = self._headers(msg, "Received-SPF")
        report["received_spf_raw"] = "\n".join(received_spf_headers)
        report["received_spf_results"] = parse_received_spf_results(received_spf_headers)

        # ── 7. Authentication-Results ─────────────────────────────────────
        auth_raw     = "\n".join(self._headers(msg, "Authentication-Results"))
        arc_auth_raw = "\n".join(self._headers(msg, "ARC-Authentication-Results"))
        report["authentication_results_raw"] = auth_raw
        report["auth_results"]     = parse_auth_results(auth_raw)
        report["arc_auth_results"] = parse_auth_results(arc_auth_raw)
        report["effective_auth_results"] = merge_auth_results(
            ("Authentication-Results", report["auth_results"]),
            ("ARC-Authentication-Results", report["arc_auth_results"]),
            ("Received-SPF", report["received_spf_results"]),
        )

        # ── 8. Firma DKIM ─────────────────────────────────────────────────
        dkim_headers = self._headers(msg, "DKIM-Signature")
        report["dkim_signature_present"] = bool(dkim_headers)
        report["dkim_signature_raw"]     = "\n".join(dkim_headers)

        # ── 9. Body e allegati ────────────────────────────────────────────
        body_parts       = []
        html_parts       = []
        attachments_info = []
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

        for part in _iter_body_leaf_parts(msg):
            ct = part.get_content_type()
            if ct == "text/plain":
                text = _decode_text_part(part)
                if text and text.strip():
                    decoded_text_chars += len(text)
                    if decoded_text_chars > MAX_DECODED_TEXT_CHARS:
                        raise EmailAnalysisLimitError(
                            "Decoded email text exceeds the supported analysis limit."
                        )
                    if _looks_like_html(text):
                        html_parts.append(text)
                    else:
                        text, removed_lines, removed_chars = _strip_plaintext_noise_blocks(text)
                        plain_noise_removed_lines += removed_lines
                        plain_noise_removed_chars += removed_chars
                        if text:
                            body_parts.append(text)
            elif ct == "text/html":
                text = _decode_text_part(part)
                if text and text.strip():
                    decoded_text_chars += len(text)
                    if decoded_text_chars > MAX_DECODED_TEXT_CHARS:
                        raise EmailAnalysisLimitError(
                            "Decoded email text exceeds the supported analysis limit."
                        )
                    html_parts.append(text)

        combined_html = "\n".join(html_parts)
        html_clean = strip_html(combined_html) if combined_html else ""
        plain_clean = re.sub(r"\n{3,}", "\n\n", "\n".join(body_parts)).strip() if body_parts else ""
        body_clean = plain_clean or html_clean

        report["body"] = body_clean
        report["body_html"] = combined_html.strip() if html_parts else None
        report["body_html_safe"] = sanitize_html_for_preview(combined_html) if html_parts else None
        report["body_html_clean"] = html_clean
        report["body_clean"] = body_clean

        report["body_source"] = "text/plain" if body_parts else ("text/html" if html_parts else "empty")
        report["html_strip_applied"] = bool(html_parts)
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
            body_plain=report["body"],
            body_html=report.get("body_html") or "",
        )
        report["lookalike_alerts"] = check_lookalike_domains(report["links"])

        # ── 11. Flag SOC ──────────────────────────────────────────────────
        report["flags"] = self._build_flags(report)

        return report

    # ── Helpers ────────────────────────────────────────────────────────────

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
    def _extract_spf_sender_ip(msg, hops: list) -> str | None:
        """
        Estrae l'IP corretto per la verifica SPF live.

        Priority:
          1. client-ip= in the LAST Received-SPF (closest to the sender)
          2. smtp.remote-ip= in Authentication-Results
          3. Primo IP pubblico nell'ultimo hop Received
          4. Fallback: sender_ip dall'hop [1]
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

        return (hops[1].get("sender_ip") if len(hops) > 1 else None)

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
            if spf_status != "pass":
                flag("MEDIUM", "SPF", f"SPF {spf_status.upper()} - sender authorization should be reviewed")
        else:
            flag("MEDIUM", "SPF", "No SPF result found in headers")

        # DKIM: missing/none is an absence of evidence, not a strong malicious signal.
        dkim = effective.get("DKIM") or report["auth_results"].get("DKIM") or report["arc_auth_results"].get("DKIM")
        dkim_status = (dkim.get("status") or "") .lower() if dkim else ""
        if dkim_status and dkim_status != "pass":
            flag("MEDIUM", "DKIM", f"DKIM {dkim_status.upper()} - signature validation should be reviewed")
        elif not report["dkim_signature_present"]:
            flag("MEDIUM", "DKIM", "DKIM signature missing from headers")

        # DMARC
        dmarc = effective.get("DMARC") or report["auth_results"].get("DMARC") or report["arc_auth_results"].get("DMARC")
        if dmarc and dmarc["status"] not in ("pass", "bestguesspass"):
            flag("MEDIUM", "DMARC", f"DMARC {dmarc['status'].upper()}")
        elif not dmarc:
            flag("MEDIUM", "DMARC", "No DMARC policy detected in headers")

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
            level = "LOW" if is_bulk_sender else "MEDIUM"
            bulk_note = (
                f"Bulk sender detected ({bulk_count} header signals), so this mismatch can be legitimate."
                if is_bulk_sender
                else f"Bulk sender not detected ({bulk_count} header signals), so this mismatch is more suspicious."
            )
            flag(
                level, "Return-Path",
                f"The Return-Path domain (`{report['return_path_domain']}`) differs from "
                f"the From domain (`{_from_domain}`). {bulk_note} Review with authentication "
                "and link evidence."
            )
        elif report.get("return_path") and not report.get("return_path_domain"):
            flag("LOW", "Return-Path", "Return-Path present but domain cannot be extracted")

        # HTML stripping applicato
        if report.get("html_strip_applied"):
            flag("INFO", "Body",
                 "Email body is pure HTML: tags removed before AI analysis. "
                 "Possible hidden text obfuscation in tags.")

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
            if att.get("magic_bytes_hex"):
                flag("INFO", "Attachment",
                     f"'{att['filename']}': magic bytes {att['magic_bytes_hex'][:8]}... "
                     f"-> detected format: {att['magic_detected_format'] or 'unknown'}")

        # Link anomalie: IP-direct e lookalike
        for lnk in report.get("links", []):
            if lnk.get("is_ip"):
                flag(
                    "HIGH", "Link",
                    "URL with bare IP detected: `" + lnk["url"] + "` - avoids DNS lookup, "
                    "typical of phishing or C2",
                )

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
            flag("HIGH", "Lookalike Domain", message)

        return flags
