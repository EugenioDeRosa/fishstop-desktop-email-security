"""Resolve claimed organisations to public official websites and compare domains."""

from __future__ import annotations

from functools import lru_cache
import ipaddress
import re
import socket
from urllib.parse import urljoin, urlparse

import requests


WIKIDATA_API = "https://www.wikidata.org/w/api.php"
ENTITY_DATA_URL = "https://www.wikidata.org/wiki/Special:EntityData/{entity_id}.json"
WIKIDATA_HEADERS = {"User-Agent": "FishStopDesktop/0.1 (local email-security analysis)"}
_EMAIL_RE = re.compile(r"[A-Z0-9._%+\-]+@([A-Z0-9.\-]+\.[A-Z]{2,})", re.IGNORECASE)
_MULTI_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "com.au", "com.br", "co.jp"}
_POSTAL_ADDRESS_CONTEXT_RE = re.compile(
    r"\b(?:via|viale|piazza|corso|largo|strada|street|road|avenue|boulevard)\b.{0,140}\b\d{5}\b",
    re.IGNORECASE | re.DOTALL,
)
_MAX_ALIAS_REDIRECTS = 3


def _registered_domain(value: str) -> str:
    host = (value or "").lower().strip(". ")
    labels = [label for label in host.split(".") if label]
    if len(labels) < 2:
        return host
    suffix = ".".join(labels[-2:])
    if suffix in _MULTI_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return suffix


def _official_domain(url: str) -> str:
    try:
        return _registered_domain(urlparse(url).hostname or "")
    except ValueError:
        return ""


def _same_organisation_label(left: str, right: str) -> bool:
    """Limit alias probing to sibling domains such as example.it / example.com."""
    left_label = _registered_domain(left).split(".", 1)[0]
    right_label = _registered_domain(right).split(".", 1)[0]
    return len(left_label) >= 4 and left_label == right_label


def _resolves_only_to_public_addresses(host: str) -> bool:
    """Avoid following an email-controlled hostname to local/private network space."""
    try:
        addresses = {
            entry[4][0]
            for entry in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        }
    except (socket.gaierror, OSError):
        return False
    if not addresses:
        return False
    try:
        return all(ipaddress.ip_address(address).is_global for address in addresses)
    except ValueError:
        return False


@lru_cache(maxsize=128)
def _redirects_to_official_domain(candidate_domain: str, official_domain: str) -> bool:
    """Verify a same-label alternative domain by a short HTTPS redirect chain.

    The candidate comes from untrusted email metadata. Requests therefore use
    no ambient proxy configuration, accept HTTPS only, verify every redirect
    host resolves to global IP addresses, and never send credentials.
    """
    candidate = _registered_domain(candidate_domain)
    official = _registered_domain(official_domain)
    if not candidate or not official or candidate == official or not _same_organisation_label(candidate, official):
        return False

    session = requests.Session()
    session.trust_env = False
    current_url = f"https://{candidate}/"
    try:
        for _ in range(_MAX_ALIAS_REDIRECTS):
            parsed = urlparse(current_url)
            host = (parsed.hostname or "").lower().rstrip(".")
            if parsed.scheme != "https" or not host or not _resolves_only_to_public_addresses(host):
                return False
            response = session.get(
                current_url,
                allow_redirects=False,
                timeout=(2, 3),
                headers={"User-Agent": WIKIDATA_HEADERS["User-Agent"]},
            )
            location = response.headers.get("Location")
            if not location or response.status_code not in {301, 302, 303, 307, 308}:
                return False
            current_url = urljoin(current_url, location)
            target = urlparse(current_url)
            target_host = (target.hostname or "").lower().rstrip(".")
            if target.scheme != "https" or not target_host:
                return False
            if _registered_domain(target_host) == official:
                return _resolves_only_to_public_addresses(target_host)
    except requests.RequestException:
        return False
    finally:
        session.close()
    return False


def _normalized_evidence(value: object) -> str:
    return re.sub(r"\s+", "", str(value or "")).casefold()


def _is_selected_turn_link(report: dict, link: dict) -> bool:
    """Keep old quoted-thread links out of identity-action comparisons."""
    if str(report.get("body_context") or "") not in {"forwarded", "reply"}:
        return True
    selected = _normalized_evidence(report.get("body_for_ai") or report.get("body_clean"))
    if not selected:
        return True
    return any(
        (candidate := _normalized_evidence(value))
        and len(candidate) >= 4
        and candidate in selected
        for value in (link.get("url"), link.get("display_text"), link.get("host"))
    )


def _contact_domains(report: dict) -> list[dict]:
    values: list[dict] = []
    for source, raw in (
        ("From", report.get("from_")),
        ("Reply-To", report.get("reply_to")),
        ("Return-Path", report.get("return_path")),
    ):
        for domain in _EMAIL_RE.findall(str(raw or "")):
            item = {"source": source, "domain": _registered_domain(domain)}
            if item["domain"] and item not in values:
                values.append(item)
    for link in report.get("links") or []:
        scheme = str(link.get("scheme") or "").lower()
        # Mailto links in signatures and quoted history are not evidence of a
        # destination requested by the current sender. Reply-To is already
        # represented above as a first-class identity header.
        if (
            scheme in {"http", "https"}
            and link.get("actionable") is not False
            and str(link.get("role") or "body_action") not in {"signature", "unsubscribe", "navigation"}
            and _is_selected_turn_link(report, link)
        ):
            item = {"source": "Link action", "domain": _registered_domain(str(link.get("host") or ""))}
            if item["domain"] and item not in values:
                values.append(item)
    return values


def _entity_is_only_postal_address_context(entity: dict) -> bool:
    """Do not resolve a city in an address as a company brand claim."""
    occurrences = entity.get("occurrences") or []
    return bool(occurrences) and all(
        str(item.get("source") or "").lower() == "body"
        and _POSTAL_ADDRESS_CONTEXT_RE.search(str(item.get("evidence") or ""))
        for item in occurrences
    )


def _official_site(name: str) -> tuple[str, str]:
    """Return a Wikidata P856 URL. Only the extracted organisation name is sent."""
    search = requests.get(
        WIKIDATA_API,
        params={"action": "wbsearchentities", "search": name, "language": "en", "format": "json", "limit": 1},
        timeout=4,
        headers=WIKIDATA_HEADERS,
    ).json()
    result = (search.get("search") or [{}])[0]
    entity_id = str(result.get("id") or "")
    if not entity_id:
        return "", "No public organisation record was found."
    entity = requests.get(ENTITY_DATA_URL.format(entity_id=entity_id), timeout=4, headers=WIKIDATA_HEADERS).json()
    claims = ((entity.get("entities") or {}).get(entity_id) or {}).get("claims") or {}
    statements = claims.get("P856") or []
    for statement in statements:
        value = (((statement.get("mainsnak") or {}).get("datavalue") or {}).get("value"))
        if isinstance(value, str) and _official_domain(value):
            return value, "Official website resolved from Wikidata."
    return "", "The public organisation record has no official website field."


def assess_brand_coherence(report: dict, entities: list[dict]) -> list[dict]:
    """Return transparent domain comparisons; unknown data never becomes a detection."""
    contacts = _contact_domains(report)
    results: list[dict] = []
    for entity in entities[:4]:
        name = str(entity.get("name") or "").strip()
        if not name or _entity_is_only_postal_address_context(entity):
            continue
        try:
            website, message = _official_site(name)
        except (requests.RequestException, ValueError, KeyError, TypeError):
            website, message = "", "Official-domain lookup is currently unavailable."
        official = _official_domain(website)
        comparisons = []
        for contact in contacts:
            domain = contact["domain"]
            redirects_to_official = bool(
                official
                and _redirects_to_official_domain(domain, official)
            )
            comparisons.append({
                **contact,
                "matches_official": bool(official and (domain == official or redirects_to_official)),
                "redirects_to_official": redirects_to_official,
            })
        mismatches = [item for item in comparisons if official and not item["matches_official"]]
        results.append({
            "brand": name,
            "official_website": website,
            "official_domain": official,
            "contacts": comparisons,
            "mismatches": mismatches,
            "status": "mismatch" if mismatches else "aligned" if official and comparisons else "unverified",
            "message": message,
        })
    return results
