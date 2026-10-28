"""Registration age of the domains a message asks the recipient to visit.

Uses the cached, IANA-bootstrapped RDAP lookup already used for sender
identity. Only registrable domain names are sent to RDAP servers; the check
is skipped in Local only mode or when RDAP is disabled.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timezone

from fishstop_engine.domain_utils import icann_registered_domain, registered_domain

MAX_LOOKUPS = 5
TOTAL_BUDGET_SECONDS = 10.0
NEW_DOMAIN_DAYS = 7
RECENT_DOMAIN_DAYS = 30


def _excluded_domains(report: dict) -> set[str]:
    from .link_deception import CLICK_TRACKING_DOMAINS
    from .lookalike import SAAS_TENANT_DOMAINS, _brand_data
    excluded = set(CLICK_TRACKING_DOMAINS) | set(SAAS_TENANT_DOMAINS)
    for record in _brand_data()["brands"]:
        excluded.update(record["domains"])
    sender = report.get("from_registered_domain")
    if sender:
        excluded.add(sender)
    return excluded


def candidate_domains(report: dict) -> list[tuple[str, bool]]:
    """(domain, call_to_action) pairs, calls to action first, bounded."""
    excluded = _excluded_domains(report)
    candidates: dict[str, bool] = {}
    for link in report.get("links") or []:
        if str(link.get("scheme") or "").lower() not in {"http", "https"} or link.get("actionable") is False:
            continue
        hosts = [link.get("host") or ""] + list(link.get("redirect_hosts") or [])
        for host in hosts:
            # Tenants of private suffixes (evil.pages.dev) are not registry
            # domains: their RDAP record would describe the platform.
            if registered_domain(host) != icann_registered_domain(host):
                continue
            domain = icann_registered_domain(host)
            if not domain or domain in excluded or "." not in domain:
                continue
            candidates[domain] = candidates.get(domain, False) or bool(link.get("html_call_to_action"))
    ordered = sorted(candidates.items(), key=lambda item: not item[1])
    return ordered[:MAX_LOOKUPS]


def _registration_age_days(observation: dict, now: float) -> float | None:
    for event in observation.get("events") or []:
        if str(event.get("action") or "").lower() != "registration":
            continue
        try:
            moment = datetime.fromisoformat(str(event.get("date") or "").replace("Z", "+00:00"))
        except ValueError:
            continue
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return max(0.0, (now - moment.timestamp()) / 86400)
    return None


def assess_link_domain_age(report: dict, disabled_providers: set[str], lookup=None) -> list[dict]:
    if "local_only" in disabled_providers or "rdap" in disabled_providers:
        report["link_domain_age"] = {"status": "disabled", "domains": {}}
        return []
    if lookup is None:
        from fishstop_engine.domain_identity import rdap_observations as lookup
    candidates = candidate_domains(report)
    observations: dict[str, dict] = {}
    if candidates:
        with ThreadPoolExecutor(max_workers=len(candidates), thread_name_prefix="fishstop-rdap") as executor:
            jobs = {executor.submit(lookup, domain): domain for domain, _ in candidates}
            done, _ = wait(jobs, timeout=TOTAL_BUDGET_SECONDS)
            for job, domain in jobs.items():
                try:
                    observations[domain] = job.result() if job in done else {"status": "timeout"}
                except Exception:  # one failing lookup must not drop the report
                    observations[domain] = {"status": "error"}
    now = time.time()
    summary: dict[str, dict] = {}
    alerts: list[dict] = []
    for domain, call_to_action in candidates:
        observation = observations.get(domain) or {}
        age = _registration_age_days(observation, now) if observation.get("status") == "observed" else None
        summary[domain] = {"status": observation.get("status") or "unavailable",
                           "age_days": round(age, 1) if age is not None else None}
        if age is None or age >= RECENT_DOMAIN_DAYS:
            continue
        level = "HIGH" if age < NEW_DOMAIN_DAYS and not report.get("is_bulk_sender") else "MEDIUM"
        alerts.append({
            "domain": domain, "age_days": round(age, 1), "level": level, "call_to_action": call_to_action,
            "message": f"The linked domain `{domain}` was registered {int(age)} day(s) ago."
                       + (" Newly registered domains are a strong phishing indicator." if level == "HIGH" else ""),
        })
    report["link_domain_age"] = {"status": "checked" if candidates else "no_candidates", "domains": summary}
    return alerts


def apply_link_domain_age(report: dict, disabled_providers: set[str], lookup=None) -> None:
    alerts = assess_link_domain_age(report, disabled_providers, lookup)
    report["link_domain_age_alerts"] = alerts
    report.setdefault("flags", [])
    for alert in alerts:
        report["flags"].append({"level": alert["level"], "field": "Link domain age", "message": alert["message"]})
