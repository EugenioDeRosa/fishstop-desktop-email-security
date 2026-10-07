"""Deterministic identity evidence. Missing data never contributes suspicion."""
from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parseaddr
import re
from urllib.parse import urlparse

from fishstop_engine.domain_utils import registered_domain, normalize_hostname
from fishstop_engine.analyzer.lookalike import check_lookalike_domains

RULE_VERSION = 1
WEIGHTS = {"free_mail_claim": 25, "sender_domain_mismatch": 15,
           "sender_lookalike": 35, "display_domain_deception": 35,
           "sensitive_external_action": 20, "action_lookalike": 35,
           "external_reply": 10, "recent_registration": 8,
           "weak_dmarc_policy": 3, "documented_sender": -10,
           "authenticated_documented_sender": -25}
FREE_MAIL_DOMAINS = frozenset({"gmail.com", "googlemail.com", "outlook.com", "hotmail.com",
    "live.com", "yahoo.com", "yahoo.it", "aol.com", "icloud.com", "proton.me", "protonmail.com"})
SENSITIVE_ACTIONS = frozenset({"provide_credentials", "pay_or_transfer", "verify_account",
    "change_account_settings", "provide_information"})


def _brand_in_display(display: str, brand: str) -> bool:
    # An exact name, optionally followed by a role, avoids Apple Valley Dental.
    roles = r"(?:support|security|billing|payments|team|assistenza|sicurezza|service|customer\s+service)"
    return bool(brand and re.fullmatch(re.escape(brand) + r"(?:\s+" + roles + r")?", display.strip(), re.I))


def assess_impersonation(report: dict, claimed_entities: list[dict], semantic: dict | None = None,
                         coherence: list[dict] | None = None) -> dict:
    """Pure assessment of previously collected, attributable observations; no I/O."""
    semantic = semantic or {}
    coherence = coherence if coherence is not None else (report.get("identity_analysis") or {}).get("coherence", [])
    candidate = next((item for item in claimed_entities if item.get("verified_claim") is True), {})
    brand = str(candidate.get("name") or "")
    display, address = parseaddr(str(report.get("from_") or ""))
    sender_host = normalize_hostname(address.rsplit("@", 1)[-1]) if "@" in address else ""
    sender = registered_domain(sender_host)
    reference = next((item for item in coherence if str(item.get("brand") or "").casefold() == brand.casefold()), {})
    official = set(reference.get("official_domains") or [])
    documented_sender = any(item.get("source") == "From" and item.get("matches_official") for item in reference.get("contacts", []))
    claimed_role = str(semantic.get("claimed_role") or "unclear")
    display_claim = _brand_in_display(display, brand)
    represented = bool(brand and candidate and claimed_role not in {"mention", "third_party"}
                       and (display_claim or claimed_role == "representative"))
    signals: list[dict] = []
    missing: list[str] = []
    auth = report.get("domain_authentication") or {}
    authenticated = auth.get("status") == "verified" and sender in {
        registered_domain(domain) for domain in auth.get("verified_domains", [])}

    def add(identifier: str, family: str, evidence: str, source: str, strong: bool = False):
        weight = WEIGHTS[identifier]
        signals.append({"id": identifier, "family": family, "weight": weight,
                        "polarity": "suspicion" if weight > 0 else "support",
                        "strong": strong, "evidence": evidence, "source": source})

    if not brand:
        missing.append("claimed_identity_unavailable")
    elif not represented:
        missing.append("representative_claim_unconfirmed")
    if not official:
        missing.append("ambiguous_brand" if "ambiguous" in str(reference.get("message", "")).lower()
                       else "company_domain_reference_unavailable")
    if not sender:
        missing.append("sender_domain_unavailable")
    if not authenticated:
        missing.append("independent_authentication_unavailable")
    source = str(reference.get("resolution_source") or "unresolved")
    if represented and official:
        if documented_sender:
            add("documented_sender", "sender_identity", f"The sender domain {sender_host} matches a documented domain for {brand}.", source)
            if authenticated:
                add("authenticated_documented_sender", "sender_identity", "An aligned DKIM signature independently authenticates the documented sender domain.", "independent_dkim")
        elif sender:
            add("sender_domain_mismatch", "sender_identity", f"The sender {sender_host} differs from the public domains for {brand}; an external sending service may still be legitimate.", source)
            if sender in FREE_MAIL_DOMAINS:
                add("free_mail_claim", "sender_identity", f"The message represents {brand} using the personal mail provider {sender}.", "From")
            lookalikes = check_lookalike_domains([{"host": sender_host, "url": "https://" + sender_host}], known_brands=sorted(official))
            if any(item.get("level") in {"HIGH", "MEDIUM"} for item in lookalikes):
                add("sender_lookalike", "sender_identity", f"The sender {sender_host} resembles a documented domain for {brand}.", source + ":lookalike", True)
            displayed = {registered_domain(value) for value in re.findall(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\b", display, re.I)}
            if displayed & official:
                add("display_domain_deception", "sender_identity", f"The display name shows an official domain, while the actual sender is {sender_host}.", "From", True)

        sensitive = semantic.get("requested_action") in SENSITIVE_ACTIONS and bool(semantic.get("evidence_phrase") or semantic.get("intent_evidence"))
        action_links = [item for item in report.get("links", []) if item.get("actionable") is not False
                        and (item.get("html_call_to_action") or item.get("role") == "body_action")]
        if sensitive and not action_links:
            missing.append("action_destination_not_identified")
        from fishstop_engine.identity_store import action_authorized
        for link in action_links[:20] if sensitive else []:
            host = normalize_hostname(link.get("host") or urlparse(str(link.get("url") or "")).hostname or "")
            domain = registered_domain(host)
            if not domain or domain in official or any(action_authorized(link, relation, semantic.get("requested_action"))
                    for relation in reference.get("authorized_action_relations", [])):
                continue
            add("sensitive_external_action", "action_destination", f"The sensitive request leads to {host}, which is not a documented destination for {brand}.", "action_link")
            alerts = check_lookalike_domains([{"host": host, "url": str(link.get("url") or "")}], known_brands=sorted(official))
            if any(item.get("level") in {"HIGH", "MEDIUM"} for item in alerts):
                add("action_lookalike", "action_destination", f"The sensitive action targets {host}, a lookalike of a documented company domain.", source + ":action_link", True)
        if sensitive and reference.get("external_reply_domains"):
            add("external_reply", "action_destination", "The sensitive request includes an undocumented external reply destination: " + ", ".join(reference["external_reply_domains"]), "Reply-To")

    registration = reference.get("registration_observations") or {}
    if registration.get("status") != "observed":
        missing.append("rdap_unavailable")
    elif represented and official and not documented_sender:
        for event in registration.get("events", []):
            if event.get("action") != "registration":
                continue
            try:
                date = datetime.fromisoformat(str(event.get("date")).replace("Z", "+00:00"))
                age = (datetime.now(timezone.utc) - date).days
                if 0 <= age < 90:
                    add("recent_registration", "domain_context", f"The unrelated sender domain was registered {age} days ago; age is supporting context only.", str(registration.get("source") or "RDAP"))
            except (ValueError, TypeError):
                pass
            break
    dns = reference.get("dns_observations") or {}
    if dns.get("status") != "observed":
        missing.append("dns_unavailable")
    elif represented and official and not documented_sender and any(re.search(r"(?:^|;)\s*p\s*=\s*none(?:;|$)", value, re.I) for value in dns.get("dmarc", [])):
        add("weak_dmarc_policy", "domain_context", "The unrelated sender publishes a monitoring-only DMARC policy; this does not establish impersonation.", "DNS")

    # Correlated observations count once per family. Authentication support cannot
    # cancel contradictions in action destinations.
    family_scores = {}
    for signal in signals:
        family = signal["family"]
        family_scores.setdefault(family, []).append(signal["weight"])
    score = max(0, min(100, sum(max(values) if any(value > 0 for value in values) else min(values)
                              for values in family_scores.values())))
    strong = {item["family"] for item in signals if item["strong"]}
    identity_confidence = "high" if source in {"maintained_catalog", "administrator_confirmation", "signed_directory"} and official else "medium" if official else "low"
    confidence = "high" if represented and official and (authenticated or strong) else "medium" if represented and official else "low"
    escalation = bool(represented and official and (len(strong) >= 2 or "action_destination" in strong))
    status = "inconsistent" if strong else "consistent" if represented and documented_sender and authenticated else "insufficient_data"
    return {"claimed_identity": brand, "claimed_role": "representative" if represented else claimed_role,
            "claim_evidence": candidate.get("occurrences", []), "signals": signals, "score": score,
            "confidence": confidence, "identity_confidence": identity_confidence,
            "coverage": {"claim": represented, "company_reference": bool(official), "authentication": authenticated,
                         "registration": registration.get("status") == "observed", "dns": dns.get("status") == "observed"},
            "status": status, "decision": "phishing" if escalation else "review" if any(item["weight"] > 0 for item in signals) else "none",
            "missing": list(dict.fromkeys(missing)), "rule_version": RULE_VERSION}
