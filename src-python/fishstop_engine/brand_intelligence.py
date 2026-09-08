"""Resolve claimed organisations to public official websites and compare domains."""

from __future__ import annotations

from functools import lru_cache
from html.parser import HTMLParser
import ipaddress
import re
import socket
import unicodedata
from urllib.parse import urljoin, urlparse

import requests

from fishstop_engine.domain_utils import registered_domain, registrable_label


WIKIDATA_API = "https://www.wikidata.org/w/api.php"
ENTITY_DATA_URL = "https://www.wikidata.org/wiki/Special:EntityData/{entity_id}.json"
WIKIDATA_HEADERS = {"User-Agent": "FishStopDesktop/0.1 (local email-security analysis)"}
_EMAIL_RE = re.compile(r"[A-Z0-9._%+\-]+@([A-Z0-9.\-]+\.[A-Z]{2,})", re.IGNORECASE)
_POSTAL_ADDRESS_CONTEXT_RE = re.compile(
    r"\b(?:via|viale|piazza|corso|largo|strada|street|road|avenue|boulevard)\b.{0,140}\b\d{5}\b",
    re.IGNORECASE | re.DOTALL,
)
_TRAVEL_CONTEXT_RE = re.compile(
    r"\b(?:train|treno|flight|volo|departure|partenza|arrival|arrivo|itinerary|itinerario)\b",
    re.IGNORECASE,
)
_MAX_ALIAS_REDIRECTS = 3
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_MAX_OFFICIAL_PAGE_BYTES = 512 * 1024
_DMARC_PASS_STATUSES = {"pass", "bestguesspass"}
_LEGAL_ENTITY_SUFFIXES = {
    "ag", "corp", "corporation", "gmbh", "inc", "incorporated", "limited",
    "llc", "llp", "ltd", "plc", "sa", "spa", "srl",
}


class _LinkDomainParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.domains: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() not in {"a", "area"}:
            return
        href = next((value for key, value in attrs if key.lower() == "href"), None)
        if not href:
            return
        target = urlparse(urljoin(self.base_url, href))
        if target.scheme not in {"http", "https"} or not target.hostname:
            return
        domain = registered_domain(target.hostname)
        if domain:
            self.domains.add(domain)


def _official_domain(url: str) -> str:
    try:
        return registered_domain(urlparse(url).hostname or "")
    except ValueError:
        return ""


def _same_organisation_label(left: str, right: str) -> bool:
    """Limit alias probing to sibling domains such as example.it / example.com."""
    left_label = registrable_label(left)
    right_label = registrable_label(right)
    return len(left_label) >= 4 and left_label == right_label


def _normalised_brand_key(value: str) -> str:
    normalised = unicodedata.normalize("NFKD", str(value or "")).casefold()
    words = re.findall(r"[^\W_]+", normalised, flags=re.UNICODE)
    while words and words[-1] in _LEGAL_ENTITY_SUFFIXES:
        words.pop()
    return "".join(words)


def _domain_names_brand(domain: str, brand: str) -> bool:
    """Require the complete registrable label to name the claimed organisation."""
    return bool(
        (brand_key := _normalised_brand_key(brand))
        and len(brand_key) >= 4
        and _normalised_brand_key(registrable_label(domain)) == brand_key
    )


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
    candidate = registered_domain(candidate_domain)
    official = registered_domain(official_domain)
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
            if registered_domain(target_host) == official:
                return _resolves_only_to_public_addresses(target_host)
    except requests.RequestException:
        return False
    finally:
        session.close()
    return False


@lru_cache(maxsize=128)
def _linked_domains_from_official_site(website: str) -> frozenset[str]:
    """Return public domains linked by an official site, using a bounded fetch.

    This is used only to corroborate an already DMARC-aligned sender whose full
    registrable label names the organisation. A generic third-party link is
    therefore never enough to make an email domain trusted.
    """
    parsed = urlparse(website)
    host = (parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme != "https" or not host or not _resolves_only_to_public_addresses(host):
        return frozenset()

    session = requests.Session()
    session.trust_env = False
    current_url = website
    try:
        for _ in range(_MAX_ALIAS_REDIRECTS + 1):
            current = urlparse(current_url)
            current_host = (current.hostname or "").lower().rstrip(".")
            if current.scheme != "https" or not current_host or not _resolves_only_to_public_addresses(current_host):
                return frozenset()
            response = session.get(
                current_url,
                allow_redirects=False,
                stream=True,
                timeout=(2, 4),
                headers={"User-Agent": WIKIDATA_HEADERS["User-Agent"]},
            )
            if response.status_code in _REDIRECT_STATUSES:
                location = response.headers.get("Location")
                response.close()
                if not location:
                    return frozenset()
                current_url = urljoin(current_url, location)
                continue
            if response.status_code != 200:
                response.close()
                return frozenset()
            content_type = str(response.headers.get("Content-Type") or "").lower()
            if "html" not in content_type:
                response.close()
                return frozenset()
            chunks: list[bytes] = []
            size = 0
            for chunk in response.iter_content(16384):
                if not chunk:
                    continue
                size += len(chunk)
                if size > _MAX_OFFICIAL_PAGE_BYTES:
                    break
                chunks.append(chunk)
            response.close()
            parser = _LinkDomainParser(current_url)
            parser.feed(b"".join(chunks).decode(response.encoding or "utf-8", errors="replace"))
            return frozenset(parser.domains)
    except (requests.RequestException, UnicodeError, ValueError):
        return frozenset()
    finally:
        session.close()
    return frozenset()


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
            item = {"source": source, "domain": registered_domain(domain)}
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


def _official_sites(name: str) -> tuple[list[str], str]:
    """Return every current Wikidata P856 URL for the selected organisation."""
    search = requests.get(
        WIKIDATA_API,
        params={"action": "wbsearchentities", "search": name, "language": "en", "format": "json", "limit": 1},
        timeout=4,
        headers=WIKIDATA_HEADERS,
    ).json()
    result = (search.get("search") or [{}])[0]
    entity_id = str(result.get("id") or "")
    if not entity_id:
        return [], "No public organisation record was found."
    entity = requests.get(ENTITY_DATA_URL.format(entity_id=entity_id), timeout=4, headers=WIKIDATA_HEADERS).json()
    claims = ((entity.get("entities") or {}).get(entity_id) or {}).get("claims") or {}
    statements = sorted(
        claims.get("P856") or [],
        key=lambda item: {"preferred": 0, "normal": 1, "deprecated": 2}.get(
            str(item.get("rank") or "normal"), 1
        ),
    )
    websites: list[str] = []
    for statement in statements:
        if str(statement.get("rank") or "normal") == "deprecated":
            continue
        value = (((statement.get("mainsnak") or {}).get("datavalue") or {}).get("value"))
        if isinstance(value, str) and _official_domain(value) and value not in websites:
            websites.append(value)
    if websites:
        return websites, "Official website data resolved from Wikidata."
    return [], "The public organisation record has no official website field."


def _official_site(name: str) -> tuple[str, str]:
    """Backward-compatible single-site view for internal callers."""
    websites, message = _official_sites(name)
    return (websites[0] if websites else ""), message


def _auth_result(report: dict, name: str) -> dict:
    return (
        (report.get("effective_auth_results") or {}).get(name)
        or (report.get("auth_results") or {}).get(name)
        or (report.get("arc_auth_results") or {}).get(name)
        or {}
    )


def _identity_domain(value: object) -> str:
    raw = str(value or "").strip().strip("<>\"'")
    if "@" in raw:
        raw = raw.rsplit("@", 1)[-1]
    return registered_domain(raw)


def _dmarc_aligns_from(report: dict, from_domain: str) -> bool:
    result = _auth_result(report, "DMARC")
    if str(result.get("status") or "").lower() not in _DMARC_PASS_STATUSES:
        return False
    authenticated_domain = _identity_domain(result.get("identity"))
    return bool(authenticated_domain and authenticated_domain == registered_domain(from_domain))


def assess_brand_coherence(report: dict, entities: list[dict]) -> list[dict]:
    """Return transparent domain comparisons; unknown data never becomes a detection."""
    contacts = _contact_domains(report)
    results: list[dict] = []
    for entity in entities[:8]:
        name = str(entity.get("name") or "").strip()
        if not name or not _entity_is_brand_candidate(entity):
            continue
        try:
            websites, message = _official_sites(name)
        except (requests.RequestException, ValueError, KeyError, TypeError):
            websites, message = [], "Official-domain lookup is currently unavailable."
        resolution_source = "wikidata" if websites else ""
        official_domains = list(dict.fromkeys(filter(None, (_official_domain(site) for site in websites))))
        official = official_domains[0] if official_domains else ""
        associated_domains: set[str] = set()

        from_domain = next(
            (item["domain"] for item in contacts if item["source"] == "From"),
            "",
        )
        if (
            websites
            and from_domain
            and from_domain not in official_domains
            and _dmarc_aligns_from(report, from_domain)
            and _domain_names_brand(from_domain, name)
        ):
            linked_domains: set[str] = set()
            for site in websites:
                linked_domains.update(_linked_domains_from_official_site(site))
            if from_domain in linked_domains:
                associated_domains.add(from_domain)

        accepted_domains = set(official_domains) | associated_domains
        comparisons = []
        for contact in contacts:
            domain = contact["domain"]
            redirects_to_official = bool(
                official
                and _redirects_to_official_domain(domain, official)
            )
            is_reply_destination = contact["source"] == "Reply-To"
            comparisons.append({
                **contact,
                "role": "reply_destination" if is_reply_destination else "sender_identity",
                "is_external": bool(accepted_domains and domain not in accepted_domains),
                "mismatch_eligible": not is_reply_destination,
                "matches_official": bool(
                    official
                    and (domain in accepted_domains or redirects_to_official)
                ),
                "redirects_to_official": bool(
                    redirects_to_official or (domain != official and domain in associated_domains)
                ),
            })
        mismatches = [
            item for item in comparisons
            if official and item["mismatch_eligible"] and not item["matches_official"]
        ]
        external_reply_domains = sorted({
            item["domain"] for item in comparisons
            if item["role"] == "reply_destination" and item["is_external"]
        })
        results.append({
            "brand": name,
            "entity_types": entity.get("entity_types") or [entity.get("entity_type")],
            "official_website": websites[0] if websites else "",
            "official_websites": websites,
            "official_domain": official,
            "official_domains": official_domains,
            "associated_domains": sorted(associated_domains),
            "external_reply_domains": external_reply_domains,
            "resolution_source": resolution_source,
            "contacts": comparisons,
            "mismatches": mismatches,
            "status": "mismatch" if mismatches else "aligned" if official and comparisons else "unverified",
            "message": message,
        })
    return results
