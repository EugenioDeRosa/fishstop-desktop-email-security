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
_TRAVEL_CONTEXT_RE = re.compile(
    r"\b(?:train|treno|flight|volo|departure|partenza|arrival|arrivo|itinerary|itinerario)\b",
    re.IGNORECASE,
)
_MAX_ALIAS_REDIRECTS = 3
_MAX_DISCOVERY_BYTES = 512_000
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}


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
            if not location or response.status_code not in _REDIRECT_STATUSES:
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
    """Return identity-bearing email domains, not every newsletter link.

    Social, app-store and footer links are common in legitimate mail and do not
    establish the identity of the sender. Link risk is assessed separately by
    the link-analysis pipeline when the recipient is asked to use one.
    """
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
    return values


def _entity_is_only_postal_address_context(entity: dict) -> bool:
    """Do not resolve a city in an address as a company brand claim."""
    occurrences = entity.get("occurrences") or []
    return bool(occurrences) and all(
        str(item.get("source") or "").lower() == "body"
        and _POSTAL_ADDRESS_CONTEXT_RE.search(str(item.get("evidence") or ""))
        for item in occurrences
    )


def _entity_is_location_context(entity: dict) -> bool:
    """Recognise geographic candidates without maintaining a place-name list."""
    entity_types = {
        str(value or "").upper()
        for value in (entity.get("entity_types") or [entity.get("entity_type")])
    }
    if "LOC" in entity_types:
        return True
    name = re.escape(str(entity.get("name") or "").strip())
    occurrences = entity.get("occurrences") or []
    if not name or not occurrences:
        return False
    # A model can occasionally label a city as ORG. Only reject that fallback
    # when all evidence is body text and it has the generic structure of a
    # travel route, never by matching a list of city or brand names.
    route_pattern = re.compile(
        rf"\b(?:from|da)\s+{name}\b.{{0,64}}\b(?:to|a|verso)\s+[\wÀ-ÖØ-öø-ÿ]",
        re.IGNORECASE | re.DOTALL,
    )
    return all(
        str(item.get("source") or "").lower() == "body"
        and _TRAVEL_CONTEXT_RE.search(str(item.get("evidence") or ""))
        and route_pattern.search(str(item.get("evidence") or ""))
        for item in occurrences
    )


def _entity_is_brand_candidate(entity: dict) -> bool:
    """Allow only sender-anchored candidates to be linked to public domains."""
    entity_types = {
        str(value or "").upper()
        for value in (entity.get("entity_types") or [entity.get("entity_type")])
    }
    sources = {str(item.get("source") or "").lower() for item in (entity.get("occurrences") or [])}
    sender_anchored = "domain" in entity_types or bool(sources & {"sender", "sender domain"})
    return sender_anchored and bool(entity_types & {"ORG", "DOMAIN"}) and not (
        _entity_is_only_postal_address_context(entity) or _entity_is_location_context(entity)
    )


def _normalised_brand_label(value: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").casefold())


def _authenticated_sender_domain(report: dict) -> str:
    """Return From only when FishStop independently verified DMARC alignment."""
    authentication = report.get("cryptographic_authentication") or {}
    dmarc = authentication.get("dmarc") or {}
    if (
        str(authentication.get("status") or "").lower() != "pass"
        or str(dmarc.get("status") or "").lower() != "pass"
        or not (dmarc.get("dkim_aligned") or dmarc.get("spf_aligned"))
    ):
        return ""
    domains = _EMAIL_RE.findall(str(report.get("from_") or ""))
    return _registered_domain(domains[-1]) if domains else ""


def _read_limited_html(response: requests.Response) -> str:
    content_type = str(response.headers.get("Content-Type") or "").lower()
    if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
        return ""
    chunks: list[bytes] = []
    consumed = 0
    for chunk in response.iter_content(chunk_size=16_384):
        if not chunk:
            continue
        remaining = _MAX_DISCOVERY_BYTES - consumed
        if remaining <= 0:
            break
        chunks.append(chunk[:remaining])
        consumed += min(len(chunk), remaining)
    encoding = response.encoding or "utf-8"
    try:
        return b"".join(chunks).decode(encoding, errors="replace")
    except LookupError:
        return b"".join(chunks).decode("utf-8", errors="replace")


@lru_cache(maxsize=128)
def _discover_site_from_authenticated_domain(candidate_domain: str, brand_name: str) -> dict:
    """Discover a brand site from an authenticated, brand-matching domain.

    This fallback is intentionally unavailable to arbitrary sender display
    names. The brand must already match the authenticated domain label, which
    prevents a spoofed display name from bootstrapping trust by redirecting to
    the impersonated organisation's real website.
    """
    candidate = _registered_domain(candidate_domain)
    brand_label = _normalised_brand_label(brand_name)
    domain_label = _normalised_brand_label(candidate.split(".", 1)[0] if candidate else "")
    if len(brand_label) < 4 or brand_label != domain_label:
        return {}

    session = requests.Session()
    session.trust_env = False
    current_url = f"https://{candidate}/"
    associated_domains = {candidate}
    redirected = False
    try:
        for _ in range(_MAX_ALIAS_REDIRECTS + 1):
            parsed = urlparse(current_url)
            host = (parsed.hostname or "").lower().rstrip(".")
            if parsed.scheme != "https" or not host or not _resolves_only_to_public_addresses(host):
                return {}
            with session.get(
                current_url,
                allow_redirects=False,
                stream=True,
                timeout=(2, 4),
                headers={"User-Agent": WIKIDATA_HEADERS["User-Agent"]},
            ) as response:
                location = response.headers.get("Location")
                if location and response.status_code in _REDIRECT_STATUSES:
                    redirected = True
                    current_url = urljoin(current_url, location)
                    target = urlparse(current_url)
                    target_host = (target.hostname or "").lower().rstrip(".")
                    if target.scheme != "https" or not target_host:
                        return {}
                    associated_domains.add(_registered_domain(target_host))
                    continue
                if response.status_code < 200 or response.status_code >= 400:
                    return {}
                html = _read_limited_html(response)
            # The final page must identify itself with the extracted brand. A
            # redirect alone is association evidence, not proof of identity.
            if brand_label not in _normalised_brand_label(html):
                return {}
            final_domain = _official_domain(current_url)
            if not final_domain:
                return {}
            associated_domains.add(final_domain)
            return {
                "website": current_url,
                "official_domain": final_domain,
                "associated_domains": sorted(associated_domains),
                "resolution_source": "authenticated_sender_https_redirect" if redirected else "authenticated_sender_website",
                "message": (
                    "Official website discovered from the independently authenticated sender domain through a verified HTTPS redirect."
                    if redirected
                    else "Official website confirmed on the independently authenticated sender domain."
                ),
            }
    except requests.RequestException:
        return {}
    finally:
        session.close()
    return {}


def _authenticated_domain_site(report: dict, entity: dict) -> dict:
    entity_types = {
        str(value or "").upper()
        for value in (entity.get("entity_types") or [entity.get("entity_type")])
    }
    if "DOMAIN" not in entity_types:
        return {}
    sender_domain = _authenticated_sender_domain(report)
    if not sender_domain:
        return {}
    return _discover_site_from_authenticated_domain(
        sender_domain,
        str(entity.get("name") or "").strip(),
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
    for entity in entities[:8]:
        name = str(entity.get("name") or "").strip()
        if not name or not _entity_is_brand_candidate(entity):
            continue
        try:
            website, message = _official_site(name)
        except (requests.RequestException, ValueError, KeyError, TypeError):
            website, message = "", "Official-domain lookup is currently unavailable."
        resolution_source = "wikidata" if website else ""
        associated_domains: set[str] = set()
        official = _official_domain(website)
        if not official:
            discovered = _authenticated_domain_site(report, entity)
            if discovered:
                website = str(discovered.get("website") or "")
                official = str(discovered.get("official_domain") or "")
                associated_domains.update(discovered.get("associated_domains") or [])
                resolution_source = str(discovered.get("resolution_source") or "")
                message = str(discovered.get("message") or message)
        comparisons = []
        for contact in contacts:
            domain = contact["domain"]
            redirects_to_official = bool(
                official
                and _redirects_to_official_domain(domain, official)
            )
            comparisons.append({
                **contact,
                "matches_official": bool(
                    official
                    and (domain == official or domain in associated_domains or redirects_to_official)
                ),
                "redirects_to_official": bool(
                    redirects_to_official or (domain != official and domain in associated_domains)
                ),
            })
        mismatches = [item for item in comparisons if official and not item["matches_official"]]
        results.append({
            "brand": name,
            "entity_types": entity.get("entity_types") or [entity.get("entity_type")],
            "official_website": website,
            "official_domain": official,
            "associated_domains": sorted(associated_domains),
            "resolution_source": resolution_source,
            "contacts": comparisons,
            "mismatches": mismatches,
            "status": "mismatch" if mismatches else "aligned" if official and comparisons else "unverified",
            "message": message,
        })
    return results
