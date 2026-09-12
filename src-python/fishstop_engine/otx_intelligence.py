"""Bounded, on-demand AlienVault OTX lookups for email indicators.

FishStop does not download or maintain a Pulse database. During an analysis it
queries OTX only for native indicators extracted from that email. Every Pulse
association must echo the exact same normalized indicator. Full URLs and file
hashes accept a small allowlist of explicit malicious tags; domains require the
exact ``phishing`` tag, while IP matches also require independent reputation
corroboration before they can affect the verdict. No parent-domain, URL-prefix,
redirect, or derived-indicator matching is performed.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from email.utils import getaddresses
from functools import lru_cache
import ipaddress
from pathlib import Path
import re
from typing import Callable
from urllib.parse import quote, urlsplit, urlunsplit

from fishstop_engine.domain_utils import is_public_suffix, normalize_hostname

try:
    import requests
except ImportError:  # Static analysis remains usable without online reputation.
    requests = None


OTX_BASE_URL = "https://otx.alienvault.com"
OTX_INDICATOR_DETAILS = f"{OTX_BASE_URL}/api/v1/indicators"
LOOKUP_WORKERS = 4
MAX_LOOKUP_WORKERS = 8
MAX_ON_DEMAND_INDICATORS = 32
MAX_PULSES_PER_INDICATOR = 5
REQUEST_TIMEOUT = (4, 12)
PUBLIC_EMAIL_PROVIDER_DOMAINS_PATH = (
    Path(__file__).with_name("data") / "public_email_provider_domains.txt"
)

_OTX_SLUGS = {
    "url": "url",
    "domain": "domain",
    "hostname": "hostname",
    "ipv4": "IPv4",
    "ipv6": "IPv6",
    "sha256": "file",
}

PHISHING_TAGS = {"phishing"}
HIGH_SPECIFICITY_MALICIOUS_TAGS = {
    "phishing",
    "malware",
    "ransomware",
    "scam",
    "credential theft",
    "credential-theft",
    "credential_theft",
    "credential phishing",
    "credential-phishing",
    "credential_phishing",
}


class OtxAuthenticationError(RuntimeError):
    """The configured OTX credential was rejected."""


@lru_cache(maxsize=1)
def _public_email_provider_domains() -> frozenset[str]:
    try:
        return frozenset(
            normalized
            for line in PUBLIC_EMAIL_PROVIDER_DOMAINS_PATH.read_text(encoding="utf-8").splitlines()
            if (normalized := normalize_hostname(line))
        )
    except OSError:
        return frozenset()


def _shared_sender_domain(value: str) -> bool:
    domain = normalize_hostname(value)
    return bool(
        domain
        and (domain in _public_email_provider_domains() or is_public_suffix(domain))
    )


def _normalize_url(value: str) -> str:
    value = str(value or "").strip()
    value = re.sub(r"^hxxps://", "https://", value, flags=re.IGNORECASE)
    value = re.sub(r"^hxxp://", "http://", value, flags=re.IGNORECASE)
    value = value.replace("[.]", ".")
    try:
        parsed = urlsplit(value)
    except ValueError:
        return ""
    scheme = parsed.scheme.lower()
    host = normalize_hostname(parsed.hostname or "")
    if scheme not in {"http", "https"} or not host:
        return ""
    try:
        port = parsed.port
    except ValueError:
        return ""
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    try:
        rendered_host = f"[{host}]" if ipaddress.ip_address(host).version == 6 else host
    except ValueError:
        rendered_host = host
    authority = rendered_host if port is None or default_port else f"{rendered_host}:{port}"
    return urlunsplit((scheme, authority, parsed.path or "/", parsed.query, ""))


def _normalize_indicator(kind: str, value: str) -> str:
    value = str(value or "").strip().replace("[.]", ".")
    if kind == "url":
        return _normalize_url(value)
    if kind in {"domain", "hostname"}:
        return normalize_hostname(value)
    if kind in {"ipv4", "ipv6"}:
        try:
            parsed = ipaddress.ip_address(value.strip("[]"))
        except ValueError:
            return ""
        if (kind == "ipv4" and parsed.version != 4) or (kind == "ipv6" and parsed.version != 6):
            return ""
        return str(parsed)
    if kind == "sha256":
        normalized = value.casefold()
        return normalized if re.fullmatch(r"[0-9a-f]{64}", normalized) else ""
    return ""


def _indicator_candidates(report: dict) -> list[tuple[str, str, str]]:
    """Return only native email indicators, ordered by investigative value."""
    candidates: list[tuple[str, str, str]] = []

    links = [
        link for link in (report.get("links") or [])
        if str(link.get("scheme") or "").lower() in {"http", "https"}
        and link.get("actionable") is not False
        and str(link.get("role") or "body_action").lower()
        not in {"signature", "unsubscribe", "navigation"}
    ]
    # When the message exposes one or more labelled call-to-action links, those
    # are the actual destinations the recipient is asked to open. Restrict the
    # lookup to them instead of querying every decorative or tracking anchor.
    labelled_calls_to_action = [
        link for link in links
        if link.get("html_call_to_action") and str(link.get("display_text") or "").strip()
    ]
    if labelled_calls_to_action:
        links = labelled_calls_to_action
    links.sort(key=lambda link: not bool(link.get("html_call_to_action")))
    for link in links:
        if value := _normalize_indicator("url", link.get("url") or ""):
            candidates.append(("url", value, "link"))

    for attachment in report.get("attachments") or []:
        if (
            attachment.get("actionable") is False
            or str(attachment.get("mime_role") or "").lower()
            in {"inline_resource", "signature"}
        ):
            continue
        if value := _normalize_indicator("sha256", attachment.get("hash_sha256") or ""):
            candidates.append(("sha256", value, "attachment"))

    for hop in report.get("received_hops") or []:
        values = hop.get("all_ips") or ([hop.get("sender_ip")] if hop.get("sender_ip") else [])
        for raw_ip in values:
            try:
                parsed = ipaddress.ip_address(str(raw_ip).strip("[]"))
            except ValueError:
                continue
            if parsed.is_global:
                kind = "ipv4" if parsed.version == 4 else "ipv6"
                candidates.append((kind, str(parsed), "email route"))

    # Sender domains are native header indicators. Do not query public mailbox
    # providers, and never derive a domain/hostname from a URL.
    for field in ("from_", "return_path", "reply_to"):
        for _display, address in getaddresses([str(report.get(field) or "")]):
            domain = normalize_hostname(address.rpartition("@")[2])
            if domain and not _shared_sender_domain(domain):
                candidates.append(("domain", domain, "sender identity"))

    unique: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for candidate in candidates:
        key = candidate[:2]
        if key in seen:
            continue
        seen.add(key)
        unique.append(candidate)
    return unique[:MAX_ON_DEMAND_INDICATORS]


def _indicator_pulses(payload: dict) -> list[dict]:
    pulse_info = payload.get("pulse_info") or {}
    pulses = pulse_info.get("pulses") or []
    if not isinstance(pulses, list):
        return []
    return [pulse for pulse in pulses if isinstance(pulse, dict)]


def _pulse_has_exact_tag(pulse: dict, accepted_tags: set[str]) -> bool:
    return any(
        str(tag).strip().casefold() in accepted_tags
        for tag in (pulse.get("tags") or [])
    )


def _malicious_pulses_for_indicator(kind: str, pulses: list[dict]) -> list[dict]:
    accepted_tags = (
        HIGH_SPECIFICITY_MALICIOUS_TAGS
        if kind in {"url", "sha256"}
        else PHISHING_TAGS
    )
    return [pulse for pulse in pulses if _pulse_has_exact_tag(pulse, accepted_tags)]


def _ip_is_independently_malicious(report: dict, value: str) -> bool:
    reputation = (report.get("hop_reputation") or {}).get(value) or {}
    status = str(reputation.get("status") or "").strip().casefold()
    try:
        abuse_score = int(reputation.get("abuseConfidenceScore") or 0)
    except (TypeError, ValueError):
        abuse_score = 0
    return status == "malicious" or abuse_score >= 50


def _pulse_summary(pulse: dict) -> dict:
    author = pulse.get("author") or {}
    author_name = (
        pulse.get("author_name")
        or (author.get("username") if isinstance(author, dict) else "")
        or "OTX community"
    )
    pulse_id = str(pulse.get("id") or "")[:64]
    return {
        "id": pulse_id,
        "name": str(pulse.get("name") or "Unnamed OTX Pulse")[:180],
        "author": str(author_name)[:100],
        "modified": str(pulse.get("modified") or pulse.get("created") or "")[:64],
        "tags": [str(tag)[:60] for tag in (pulse.get("tags") or [])[:12]],
        "tlp": str(pulse.get("TLP") or pulse.get("tlp") or "")[:20],
        "url": f"{OTX_BASE_URL}/pulse/{pulse_id}" if pulse_id else "",
    }


def _lookup_exact_indicator(session, kind: str, value: str) -> dict:
    slug = _OTX_SLUGS[kind]
    endpoint = f"{OTX_INDICATOR_DETAILS}/{slug}/{quote(value, safe='')}/general"
    response = session.get(endpoint, timeout=REQUEST_TIMEOUT)
    if response.status_code in {401, 403}:
        raise OtxAuthenticationError("The OTX API key is invalid or not authorized.")
    if response.status_code == 404:
        return {"matched": False, "pulses": []}
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise RuntimeError("OTX returned an invalid indicator response.")

    returned_kind = str(payload.get("type") or "").casefold()
    returned_value = _normalize_indicator(kind, payload.get("indicator") or "")
    expected_types = {
        "url": {"url", "uri"},
        "domain": {"domain"},
        "hostname": {"hostname"},
        "ipv4": {"ipv4"},
        "ipv6": {"ipv6"},
        "sha256": {"filehash-sha256", "sha256"},
    }[kind]
    # The endpoint alone is not enough: require the response to echo the same
    # native indicator and type before accepting any Pulse association.
    if returned_value != value or (returned_kind and returned_kind not in expected_types):
        return {"matched": False, "pulses": []}
    pulses = _indicator_pulses(payload)
    return {"matched": bool(pulses), "pulses": pulses}


def _worker_count() -> int:
    return max(1, min(MAX_LOOKUP_WORKERS, LOOKUP_WORKERS))


def apply_on_demand_otx_intelligence(
    report: dict,
    api_key: str | None = None,
    *,
    session_factory: Callable | None = None,
) -> dict:
    """Query OTX for this email's exact indicators and attach the result."""
    key = str(api_key or "").strip()
    if not key:
        report["otx_intelligence"] = {
            "status": "unavailable",
            "lookup_mode": "on_demand_exact",
            "checked_indicator_count": 0,
            "failed_indicator_count": 0,
            "matches": [],
            "message": "OTX is not configured: add the API key in Settings.",
        }
        return report
    if requests is None:
        report["otx_intelligence"] = {
            "status": "unavailable",
            "lookup_mode": "on_demand_exact",
            "checked_indicator_count": 0,
            "failed_indicator_count": 0,
            "matches": [],
            "message": "OTX on-demand lookup requires the requests package.",
        }
        return report

    candidates = _indicator_candidates(report)
    if not candidates:
        report["otx_intelligence"] = {
            "status": "no_match",
            "lookup_mode": "on_demand_exact",
            "checked_indicator_count": 0,
            "failed_indicator_count": 0,
            "matches": [],
            "message": "No supported OTX indicator was present in this email.",
        }
        return report

    make_session = session_factory or requests.Session
    matches: list[dict] = []
    failures = 0
    authentication_error = ""

    def lookup(candidate: tuple[str, str, str]) -> tuple[tuple[str, str, str], dict]:
        session = make_session()
        try:
            session.headers.update({
                "X-OTX-API-KEY": key,
                "Accept": "application/json",
                "User-Agent": "FishStop/0.2 OTX exact on-demand",
            })
            return candidate, _lookup_exact_indicator(session, candidate[0], candidate[1])
        finally:
            close = getattr(session, "close", None)
            if callable(close):
                close()

    with ThreadPoolExecutor(max_workers=_worker_count(), thread_name_prefix="otx-exact") as executor:
        futures = {executor.submit(lookup, candidate): candidate for candidate in candidates}
        for future in as_completed(futures):
            kind, value, source = futures[future]
            try:
                _candidate, result = future.result()
            except OtxAuthenticationError as error:
                authentication_error = str(error)
                failures += 1
                continue
            except Exception:
                failures += 1
                continue
            if not result.get("matched"):
                continue
            all_pulses = result.get("pulses") or []
            malicious_pulses = _malicious_pulses_for_indicator(kind, all_pulses)
            strong = bool(malicious_pulses) and (
                kind not in {"ipv4", "ipv6"}
                or _ip_is_independently_malicious(report, value)
            )
            supporting = bool(malicious_pulses) and not strong
            selected_pulses = malicious_pulses or all_pulses
            pulses = [_pulse_summary(pulse) for pulse in selected_pulses]
            matches.append({
                "indicator": value,
                "matched_indicator": value,
                "indicator_type": kind,
                "match_type": "exact",
                "source": source,
                "confidence": "strong" if strong else "supporting" if supporting else "informational",
                "classification": "malicious" if strong else "supporting" if supporting else "informational",
                "shared_infrastructure": kind in {"ipv4", "ipv6"},
                "pulse_count": len(selected_pulses),
                "pulses": pulses[:MAX_PULSES_PER_INDICATOR],
            })

    checked = len(candidates) - failures
    matches.sort(key=lambda item: (
        item.get("confidence") != "strong",
        item["source"],
        item["indicator_type"],
        item["indicator"],
    ))
    strong_matches = [match for match in matches if match.get("confidence") == "strong"]
    context_matches = [match for match in matches if match.get("confidence") != "strong"]
    if authentication_error and checked == 0:
        status = "unavailable"
        message = authentication_error
    elif checked == 0:
        status = "unavailable"
        message = "OTX could not check the email indicators. No result was treated as clean."
    elif strong_matches:
        status = "match"
        message = f"{len(strong_matches)} high-confidence exact OTX indicator match(es) found."
    elif context_matches:
        status = "context_only"
        message = (
            f"{len(context_matches)} exact OTX association(s) found, but none met the "
            "high-confidence malicious policy; they remain neutral context."
        )
    else:
        status = "no_match"
        message = (
            f"No exact match was found for {checked} indicator(s) checked on demand; "
            "this is neutral evidence, not proof of safety."
        )
    report["otx_intelligence"] = {
        "status": status,
        "lookup_mode": "on_demand_exact",
        "checked_indicator_count": checked,
        "failed_indicator_count": failures,
        "strong_match_count": len(strong_matches),
        "context_match_count": len(context_matches),
        "matches": matches[:20],
        "message": message,
    }
    if strong_matches:
        strongest = strong_matches[0]
        report.setdefault("flags", []).append({
            "level": "HIGH",
            "field": "OTX Threat Intelligence",
            "message": (
                f"Exact native {strongest['indicator_type'].upper()} indicator "
                f"'{strongest['indicator']}' appears in {strongest['pulse_count']} "
                "OTX Pulse(s) with an accepted exact malicious tag."
            ),
        })
    return report
