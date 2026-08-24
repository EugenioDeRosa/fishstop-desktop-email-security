"""Resolve claimed organisations to public official websites and compare domains."""

from __future__ import annotations

import re
from urllib.parse import urlparse

import requests


WIKIDATA_API = "https://www.wikidata.org/w/api.php"
ENTITY_DATA_URL = "https://www.wikidata.org/wiki/Special:EntityData/{entity_id}.json"
WIKIDATA_HEADERS = {"User-Agent": "FishStopDesktop/0.1 (local email-security analysis)"}
_EMAIL_RE = re.compile(r"[A-Z0-9._%+\-]+@([A-Z0-9.\-]+\.[A-Z]{2,})", re.IGNORECASE)
_MULTI_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "com.au", "com.br", "co.jp"}


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
        if scheme in {"http", "https"}:
            item = {"source": "Link action", "domain": _registered_domain(str(link.get("host") or ""))}
            if item["domain"] and item not in values:
                values.append(item)
        elif scheme == "mailto":
            for domain in _EMAIL_RE.findall(str(link.get("url") or "")):
                item = {"source": "Email action", "domain": _registered_domain(domain)}
                if item["domain"] and item not in values:
                    values.append(item)
    return values


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
        if not name:
            continue
        try:
            website, message = _official_site(name)
        except (requests.RequestException, ValueError, KeyError, TypeError):
            website, message = "", "Official-domain lookup is currently unavailable."
        official = _official_domain(website)
        comparisons = [
            {**contact, "matches_official": bool(official and contact["domain"] == official)}
            for contact in contacts
        ]
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
