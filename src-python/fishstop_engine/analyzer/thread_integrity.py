"""Detect messages presented as replies without belonging to a real thread.

Business email compromise often uses a "RE:" subject, and sometimes a
fabricated quoted history, to make a first contact look like the continuation
of an existing exchange. A genuine reply produced by a mail client carries
threading headers (In-Reply-To / References, or Thread-Index for Outlook).
Nothing here performs network access.
"""
from __future__ import annotations

import re

from fishstop_engine.domain_utils import mailbox_candidates, registered_domain

# Reply prefixes in common languages, optionally after list/ticket tags
# ("[EXT] RE:", "(External) R:") and with counters ("RE[2]:", "Re^3:").
_REPLY_PREFIX_RE = re.compile(
    r"^\s*(?:(?:\[[^\]]{1,40}\]|\([^)]{1,40}\)|\*{1,3}[^*]{1,30}\*{1,3})\s*)*"
    r"(?P<prefix>re|r|aw|sv|vs|antw|antwort|rif|res|odp|ynt|atb)"
    r"(?:\s*\[\d{1,3}\]|\s*\^\d{1,3}|\s*\(\d{1,3}\))?\s*:",
    re.IGNORECASE,
)
THREADING_HEADERS = ("In-Reply-To", "References", "Thread-Index")

NO_THREAD_MESSAGE = (
    "The subject presents the message as a reply, but it has no In-Reply-To, References or Thread-Index "
    "header linking it to a previous message. The previous exchange may not exist."
)
FABRICATED_THREAD_MESSAGE = (
    "The message presents itself as a reply and quotes a previous exchange, but no threading header links it "
    "to an earlier message. The quoted history may be fabricated."
)
FABRICATED_RECIPIENT_THREAD_MESSAGE = (
    "The message presents itself as a reply and quotes a previous message attributed to the recipient or to the "
    "recipient organisation, but no threading header links it to an earlier message. The quoted history may be "
    "fabricated to imitate an existing conversation."
)
BULK_MESSAGE = (
    "A bulk sender uses a reply prefix without threading headers. This misrepresents the message as part of an "
    "existing conversation."
)


def reply_prefix(subject: str) -> str:
    match = _REPLY_PREFIX_RE.match(str(subject or ""))
    return match.group("prefix") if match else ""


def threading_headers(message) -> dict:
    """Return the threading headers present on the delivered message."""
    present = {}
    for name in THREADING_HEADERS:
        values = [str(value).strip() for value in (message.get_all(name) or []) if str(value).strip()]
        if values:
            present[name] = values[0][:300]
    return present


def _recipient_identity(report: dict) -> tuple[set[str], set[str]]:
    from .lookalike import organization_domains
    addresses = {
        address.casefold()
        for key in ("to", "delivered_to")
        for _, address in mailbox_candidates(report.get(key) or "")[:20]
    }
    return addresses, set(organization_domains(report))


def assess_reply_threading(report: dict, headers: dict, segments: list[dict]) -> dict:
    """Grade a reply-looking message against its threading evidence.

    Levels: NONE (not a reply or properly threaded), LOW (bulk sender),
    MEDIUM (reply prefix without threading or with a quoted history from third
    parties), HIGH (fabricated quoted message attributed to the recipient or
    the recipient organisation).
    """
    prefix = reply_prefix(report.get("subject") or "")
    base = {"level": "NONE", "message": "", "reply_prefix": prefix, "threading_headers": sorted(headers),
            "quoted_messages": 0, "quoted_from_recipient": False}
    if not prefix or headers:
        return base
    if report.get("selected_target_authentication_scope") == "embedded_unavailable":
        return base
    quoted = [segment for segment in segments if segment.get("id") != "outer"
              and segment.get("kind") in {"quoted", "forwarded"}]
    addresses, organisation = _recipient_identity(report)
    sender_domains = {registered_domain(address.rsplit("@", 1)[-1])
                      for _, address in mailbox_candidates(report.get("from_") or "")}
    from_recipient = False
    for segment in quoted:
        address = str(segment.get("address") or "").casefold()
        domain = registered_domain(segment.get("domain") or (address.rsplit("@", 1)[-1] if address else ""))
        if address and (address in addresses or (domain and domain in organisation and domain not in sender_domains)):
            from_recipient = True
            break
    result = {**base, "quoted_messages": len(quoted), "quoted_from_recipient": from_recipient}
    if from_recipient:
        return {**result, "level": "HIGH", "message": FABRICATED_RECIPIENT_THREAD_MESSAGE}
    if quoted:
        return {**result, "level": "MEDIUM", "message": FABRICATED_THREAD_MESSAGE}
    if report.get("is_bulk_sender"):
        return {**result, "level": "LOW", "message": BULK_MESSAGE}
    return {**result, "level": "MEDIUM", "message": NO_THREAD_MESSAGE}
