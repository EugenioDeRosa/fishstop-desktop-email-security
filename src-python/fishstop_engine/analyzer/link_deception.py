"""Static deception checks on link presentation and domains.

Nothing here performs network access: decisions use only the parsed message.
"""
from __future__ import annotations

from fishstop_engine.domain_utils import normalize_hostname, registered_domain

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
    if unsafe_scheme_links is not None:
        report["unsafe_scheme_links"] = unsafe_scheme_links
