"""Static inspection of iCalendar invitations (text/calendar, .ics).

Calendar invitations are increasingly used to deliver phishing links: the
email body can be empty while the event description or location carries the
lure and the destination. Nothing is fetched and no event is created.
"""
from __future__ import annotations

import re

from fishstop_engine.domain_utils import mailbox_candidates, registered_domain

MAX_CALENDAR_BYTES = 256 * 1024
MAX_EVENTS = 20
MAX_URLS = 25
_URL_RE = re.compile(r"https?://[^\s<>\"'\\]+", re.IGNORECASE)
_CALENDAR_EXTENSIONS = {"ics", "ical", "ifb", "icalendar", "vcs"}
_CALENDAR_TYPES = {"text/calendar", "application/ics", "text/x-vcalendar"}
# Services that send invitations on behalf of an organiser.
_CALENDAR_SERVICE_SENDERS = {
    "calendar-notification@google.com", "calendar-server.bounces.google.com",
}
_CALENDAR_SERVICE_DOMAINS = {"google.com", "calendar.google.com", "icloud.com", "me.com"}


def is_calendar_part(content_type: str, filename: str = "") -> bool:
    extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return content_type.split(";", 1)[0].strip().lower() in _CALENDAR_TYPES or extension in _CALENDAR_EXTENSIONS


def _unfold(text: str) -> list[str]:
    lines: list[str] = []
    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if raw[:1] in {" ", "\t"} and lines:
            lines[-1] += raw[1:]
        else:
            lines.append(raw)
    return lines


def _unescape(value: str) -> str:
    return (value.replace("\\n", "\n").replace("\\N", "\n").replace("\\,", ",")
            .replace("\\;", ";").replace("\\\\", "\\"))


def parse_calendar(payload: bytes) -> dict:
    complete = len(payload) <= MAX_CALENDAR_BYTES
    text = payload[:MAX_CALENDAR_BYTES].decode("utf-8", errors="replace")
    result = {"status": "complete" if complete else "partial", "analysis_complete": complete,
              "method": "", "events": [], "urls": [], "findings": [], "risk_level": "clean",
              "summary": ""}
    if "BEGIN:VCALENDAR" not in text.upper():
        return {**result, "status": "partial", "analysis_complete": False,
                "summary": "The calendar file could not be parsed."}
    event: dict | None = None
    binary_attachments = 0
    for line in _unfold(text):
        if ":" not in line:
            continue
        head, value = line.split(":", 1)
        name, *params = head.split(";")
        name = name.strip().upper()
        params_upper = ";".join(params).upper()
        if name == "METHOD":
            result["method"] = value.strip().upper()[:20]
        elif name == "BEGIN" and value.strip().upper() == "VEVENT":
            event = {"summary": "", "description": "", "location": "", "organizer": "", "attendees": 0, "urls": []}
        elif name == "END" and value.strip().upper() == "VEVENT" and event is not None:
            if len(result["events"]) < MAX_EVENTS:
                result["events"].append(event)
            event = None
        elif event is not None:
            value = _unescape(value)
            if name == "SUMMARY":
                event["summary"] = value[:200]
            elif name in {"DESCRIPTION", "X-ALT-DESC"}:
                event["description"] = (event["description"] + "\n" + re.sub(r"<[^>]+>", " ", value))[:4000]
            elif name == "LOCATION":
                event["location"] = value[:300]
            elif name == "ORGANIZER":
                event["organizer"] = re.sub(r"^mailto:", "", value.strip(), flags=re.I)[:200]
            elif name == "ATTENDEE":
                event["attendees"] += 1
            elif name == "ATTACH" and ("ENCODING=BASE64" in params_upper or "VALUE=BINARY" in params_upper):
                binary_attachments += 1
                continue
            if name in {"DESCRIPTION", "X-ALT-DESC", "LOCATION", "URL", "ATTACH", "CONFERENCE"}:
                for url in _URL_RE.findall(value):
                    url = url.rstrip(".,;)")
                    if url not in event["urls"]:
                        event["urls"].append(url[:500])
                    if url not in result["urls"] and len(result["urls"]) < MAX_URLS:
                        result["urls"].append(url[:500])
    if binary_attachments:
        result["findings"].append({"key": "calendar_binary_attachment", "severity": "medium",
                                   "label": "The invitation embeds a file inside the calendar data.",
                                   "evidence": str(binary_attachments)})
        result["risk_level"] = "medium"
    result["summary"] = (
        f"Calendar invitation ({result['method'] or 'no method'}): {len(result['events'])} event(s), "
        f"{len(result['urls'])} link(s)." + (" Calendar inspection size limit reached." if not complete else "")
    )
    return result


def assess_calendar_invites(report: dict, invites: list[dict]) -> list[dict]:
    """Report organiser/sender inconsistencies for invitations carrying links."""
    alerts: list[dict] = []
    senders = [address.casefold() for _, address in mailbox_candidates(report.get("from_") or "")]
    sender_domains = {registered_domain(address.rsplit("@", 1)[-1]) for address in senders}
    service_sender = any(address in _CALENDAR_SERVICE_SENDERS for address in senders) or bool(
        sender_domains & _CALENDAR_SERVICE_DOMAINS)
    for invite in invites:
        for event in invite.get("events") or []:
            organizer = str(event.get("organizer") or "").casefold()
            organizer_domain = registered_domain(organizer.rsplit("@", 1)[-1]) if "@" in organizer else ""
            mismatch = bool(organizer_domain and sender_domains and organizer_domain not in sender_domains
                            and not service_sender)
            if event.get("urls"):
                alerts.append({
                    "level": "MEDIUM" if mismatch else "INFO",
                    "message": (
                        f"The calendar invitation '{event.get('summary') or 'event'}' contains "
                        f"{len(event['urls'])} link(s)"
                        + (f" and its organiser ({organizer}) does not match the sender." if mismatch else ".")
                    ),
                })
            elif mismatch:
                alerts.append({"level": "LOW",
                               "message": f"The calendar organiser ({organizer}) does not match the sender."})
    return alerts[:10]
