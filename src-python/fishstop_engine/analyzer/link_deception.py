"""Static deception checks on link presentation and domains.

Nothing here performs network access: decisions use only the parsed message.
"""
from __future__ import annotations

import base64
import json
import re
from functools import lru_cache
from pathlib import Path
from urllib.parse import unquote, urlsplit

from fishstop_engine.domain_utils import mailbox_candidates, normalize_hostname, registered_domain

from .lookalike import (
    check_lookalike_domains,
    check_sender_lookalikes,
    organization_domains,
    protected_brands,
)

# Click-tracking and link-protection services commonly used by legitimate
# senders. A visible URL that differs from one of these hosts is the normal
# shape of a tracked newsletter link, not by itself a masked destination.
CLICK_TRACKING_DOMAINS = frozenset({
    "list-manage.com", "mailchimp.com", "mcusercontent.com", "sendgrid.net", "mandrillapp.com",
    "mailgun.org", "mailgun.net", "exct.net", "exacttarget.com", "hubspotlinks.com", "hubspotemail.net",
    "hs-sites.com", "klclick.com", "klclick1.com", "klclick2.com", "klclick3.com", "rs6.net",
    "createsend.com", "createsend1.com", "cmail19.com", "cmail20.com", "sendibt2.com", "sendibt3.com",
    "sendibm1.com", "mjt.lu", "awstrack.me", "mktoweb.com", "mkt.com", "salesforce.com",
    "safelinks.protection.outlook.com", "urldefense.com", "urldefense.proofpoint.com",
    "cudasvc.com", "mimecast.com", "mimecastprotect.com", "emlnk.com", "ct.sendgrid.net",
    "acemlna.com", "acemlnb.com", "acemlnc.com", "acemlnd.com", "mailerlite.com", "mlsend.com",
})


LINK_HOSTING_PATH = Path(__file__).resolve().parents[1] / "data" / "link-hosting.json"


@lru_cache(maxsize=1)
def _link_hosting() -> dict:
    try:
        data = json.loads(LINK_HOSTING_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    return {key: frozenset(str(item).lower() for item in data.get(key) or [])
            for key in ("ipfs_gateways", "shorteners", "abused_hosting")}


def _host_in(host: str, domains: frozenset[str]) -> bool:
    return host in domains or any(host.endswith("." + domain) for domain in domains)


def _hosting_kind(host: str, url: str) -> str:
    data = _link_hosting()
    path = urlsplit(url).path.lower() if url else ""
    if _host_in(host, data["ipfs_gateways"]) or "/ipfs/" in path or "/ipns/" in path or ".ipfs." in host:
        return "ipfs"
    if _host_in(host, data["shorteners"]):
        return "shortener"
    if _host_in(host, data["abused_hosting"]):
        return "abused_hosting"
    return ""


def assess_link_hosting(report: dict) -> list[dict]:
    """Report IPFS gateways, URL shorteners and abused free hosting.

    IPFS links are MEDIUM: legitimate business mail practically never uses
    them. Shorteners and free hosting are MEDIUM when used as a clickable
    call to action, informational otherwise.
    """
    labels = {
        "ipfs": "an IPFS gateway, a hosting method frequently used for phishing pages",
        "shortener": "a URL shortener that hides the final destination",
        "abused_hosting": "a free hosting or form service frequently abused for phishing pages",
    }
    alerts: list[dict] = []
    for link in _web_actionable_links(report):
        host = normalize_hostname(link.get("host") or "")
        kind = _hosting_kind(host, str(link.get("url") or ""))
        if not kind:
            continue
        level = "MEDIUM" if kind == "ipfs" or link.get("html_call_to_action") else "INFO"
        alerts.append({"url": link.get("url"), "host": host, "kind": kind, "level": level,
                       "message": f"The link `{host}` uses {labels[kind]}."})
    return alerts[:10]


def _encodings_of(address: str) -> set[str]:
    raw = address.encode()
    variants = {address.casefold()}
    for encoder in (base64.b64encode, base64.urlsafe_b64encode):
        encoded = encoder(raw).decode()
        variants.update({encoded, encoded.rstrip("=")})
    return {variant for variant in variants if len(variant) >= 8}


def assess_recipient_in_links(report: dict) -> list[dict]:
    """Detect links personalised with the recipient address.

    Phishing kits pass the victim address to pre-fill a fake login page,
    usually in the URL fragment (never sent to server logs) or base64
    encoded. Plain addresses in the query are common in legitimate
    unsubscribe and preference links and are not reported.
    """
    addresses = {
        address.casefold()
        for key in ("to", "delivered_to")
        for _, address in mailbox_candidates(report.get(key) or "")[:10]
        if "@" in address
    }
    if not addresses:
        return []
    alerts: list[dict] = []
    for link in _web_actionable_links(report):
        url = str(link.get("url") or "")
        try:
            parts = urlsplit(url)
        except ValueError:
            continue
        fragment = unquote(unquote(parts.fragment))
        rest = unquote(unquote(parts.path + "?" + parts.query))
        for address in addresses:
            encoded = _encodings_of(address) - {address}
            in_fragment = address in fragment.casefold() or any(item in fragment for item in encoded)
            encoded_elsewhere = any(item in rest for item in encoded)
            if in_fragment or encoded_elsewhere:
                alerts.append({
                    "url": url, "host": link.get("host"), "level": "HIGH" if in_fragment else "MEDIUM",
                    "message": (
                        f"The link to `{link.get('host')}` carries the recipient address "
                        + ("in its fragment" if in_fragment else "encoded in its path or query")
                        + ", a technique used by phishing kits to pre-fill a fake login page."
                    ),
                })
                break
    return alerts[:10]


def _is_click_tracking(host: str) -> bool:
    host = normalize_hostname(host)
    registered = registered_domain(host)
    return host in CLICK_TRACKING_DOMAINS or registered in CLICK_TRACKING_DOMAINS or any(
        host.endswith("." + domain) for domain in CLICK_TRACKING_DOMAINS)


def _web_actionable_links(report: dict) -> list[dict]:
    return [
        link for link in report.get("links") or []
        if str(link.get("scheme") or "").lower() in {"http", "https"}
        and link.get("actionable") is not False
    ]


def lookalike_link_inputs(report: dict) -> list[dict]:
    """Actionable web links plus the final destinations of nested redirects."""
    inputs = []
    for link in _web_actionable_links(report):
        inputs.append(link)
        for target in (link.get("redirect_targets") or [])[:5]:
            for host in link.get("redirect_hosts") or []:
                if host and host in target:
                    inputs.append({"url": target, "host": host, "via_redirect": link.get("url")})
                    break
    return inputs


def assess_display_mismatches(report: dict) -> list[dict]:
    """Grade links whose visible text shows another domain than the target.

    HIGH: the visible text shows a protected brand or the recipient
    organisation, and the real target is an unrelated, non-tracking host.
    MEDIUM: the visible text shows another domain and the target is not a
    known click-tracking service, or a tracking host masks a protected brand.
    Ordinary tracked newsletter links are not reported.
    """
    brands = protected_brands(report)
    protected = {registered_domain(brand) for brand in brands}
    for brand in brands:
        from .lookalike import _brand_record
        protected.update(_brand_record(brand)["domains"])
    organisation = set(organization_domains(report))
    alerts: list[dict] = []
    for link in _web_actionable_links(report):
        if not link.get("display_mismatch"):
            continue
        display_domain = registered_domain(link.get("display_host") or "")
        target_host = normalize_hostname(link.get("host") or "")
        if not display_domain or not target_host:
            continue
        tracking = _is_click_tracking(target_host)
        shows_protected = display_domain in protected or display_domain in organisation
        if shows_protected and not tracking:
            level = "HIGH"
        elif shows_protected or not tracking:
            level = "MEDIUM"
        else:
            continue
        alerts.append({
            "url": link.get("url"),
            "host": target_host,
            "display_host": link.get("display_host"),
            "level": level,
            "message": (
                f"The link text shows `{link.get('display_host')}` but opens `{target_host}`."
                + (" The visible domain belongs to a protected brand or to the recipient organisation."
                   if shows_protected else "")
            ),
        })
    return alerts[:10]


def refresh_link_alerts(report: dict, unsafe_scheme_links: list[dict] | None = None) -> None:
    """Recompute static link/domain deception alerts on the selected content."""
    report["lookalike_alerts"] = check_lookalike_domains(
        lookalike_link_inputs(report), known_brands=protected_brands(report))
    report["sender_lookalike_alerts"] = check_sender_lookalikes(report)
    report["display_mismatch_alerts"] = assess_display_mismatches(report)
    report["link_hosting_alerts"] = assess_link_hosting(report)
    report["recipient_link_alerts"] = assess_recipient_in_links(report)
    if unsafe_scheme_links is not None:
        report["unsafe_scheme_links"] = unsafe_scheme_links
