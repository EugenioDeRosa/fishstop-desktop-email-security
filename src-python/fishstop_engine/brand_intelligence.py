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

from fishstop_engine.domain_utils import registered_domain, registrable_label, normalize_hostname
from fishstop_engine.identity_store import cached, put, resolve_partner, relationship_matches
from fishstop_engine.domain_identity import dns_observations, rdap_observations
import time


WIKIDATA_API = "https://www.wikidata.org/w/api.php"
ENTITY_DATA_URL = "https://www.wikidata.org/wiki/Special:EntityData/{entity_id}.json"
CRT_SH_URL = "https://crt.sh/"
WIKIDATA_HEADERS = {"User-Agent": "FishStopDesktop/0.1 (local email-security analysis)"}
IDENTITY_LOOKUP_BUDGET_SECONDS = 6
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
_MAX_CT_ENTRIES = 5000
_MAX_CT_CANDIDATES = 256
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


@lru_cache(maxsize=128)
def _crt_sh_candidate_domains(brand_label: str) -> frozenset[str]:
    """Generate untrusted same-label domain candidates from Certificate Transparency.

    Certificate presence proves neither ownership nor current control. This
    legacy discovery helper must never authorize a company or delegated domain.
    """
    label = _normalised_brand_key(brand_label)
    if len(label) < 4 or len(label) > 63 or not label.isascii() or not label.isalnum():
        return frozenset()
    try:
        response = requests.get(
            CRT_SH_URL,
            params={"q": f"%.{label}.%", "output": "json"},
            timeout=6,
            headers=WIKIDATA_HEADERS,
        )
        response.raise_for_status()
        entries = response.json()
    except (requests.RequestException, ValueError):
        return frozenset()
    if not isinstance(entries, list):
        return frozenset()

    candidates: set[str] = set()
    for entry in entries[:_MAX_CT_ENTRIES]:
        if not isinstance(entry, dict):
            continue
        for raw_name in str(entry.get("name_value") or "").splitlines():
            domain = registered_domain(raw_name.strip().lower().lstrip("*."))
            if domain:
                candidates.add(domain)
            if len(candidates) >= _MAX_CT_CANDIDATES:
                return frozenset(candidates)
    return frozenset(candidates)


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
            item = {"source": source, "domain": registered_domain(domain), "hostname": normalize_hostname(domain)}
            if item["domain"] and item not in values:
                values.append(item)
    return values


def _selected_action_domains(report: dict) -> set[str]:
    """Return actionable web domains from the message turn under analysis."""
    domains: set[str] = set()
    for link in report.get("links") or []:
        if link.get("actionable") is False or not _is_selected_turn_link(report, link):
            continue
        if str(link.get("scheme") or "").lower() not in {"http", "https"}:
            continue
        if str(link.get("role") or "body_action").lower() in {
            "signature", "unsubscribe", "navigation",
        }:
            continue
        domain = registered_domain(str(link.get("host") or ""))
        if domain:
            domains.add(domain)
    return domains


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
    """Allow sender identities or exact AI claims grounded in visible text."""
    entity_types = {
        str(value or "").upper()
        for value in (entity.get("entity_types") or [entity.get("entity_type")])
    }
    sources = {str(item.get("source") or "").lower() for item in (entity.get("occurrences") or [])}
    sender_anchored = "domain" in entity_types or bool(sources & {"sender", "sender domain"})
    grounded_claim = entity.get("verified_claim") is True and bool(
        sources & {"sender", "subject", "body"}
    )
    return (sender_anchored or grounded_claim) and bool(entity_types & {"ORG", "DOMAIN"}) and not (
        _entity_is_only_postal_address_context(entity) or _entity_is_location_context(entity)
    )


def _wikidata_json(url: str, params: dict | None = None, deadline: float | None = None) -> dict:
    """Fixed public endpoints only, bounded responses and no ambient credentials."""
    import json
    deadline = deadline or time.monotonic() + 5
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise requests.Timeout("Identity lookup deadline reached")
    session = requests.Session()
    session.trust_env = False
    try:
        with session.get(url, params=params, timeout=min(remaining, 2), headers=WIKIDATA_HEADERS,
                         stream=True, allow_redirects=False) as response:
            response.raise_for_status()
            raw = response.raw.read(512 * 1024 + 1, decode_content=True)
            if len(raw) > 512 * 1024:
                raise ValueError("Organisation response exceeds the size limit")
            return json.loads(raw)
    finally:
        session.close()


def _organisation_claims(claims: dict) -> bool:
    types = {((item.get("mainsnak", {}).get("datavalue") or {}).get("value") or {}).get("id")
             for item in claims.get("P31", []) if item.get("rank") != "deprecated"}
    organisation_types = {"Q43229", "Q4830453", "Q783794", "Q6881511", "Q891723", "Q22687",
                          "Q7278", "Q79913", "Q3918", "Q31855", "Q484652", "Q167037",
                          "Q6881511", "Q134161", "Q163740", "Q2659904", "Q161726"}
    # Legal form / headquarters can corroborate specialised company subclasses.
    # An arbitrary P856 (e.g. an artwork page) is never sufficient.
    return bool(types & organisation_types or claims.get("P1454") or claims.get("P159"))


def _official_sites(name: str, deadline: float | None = None) -> tuple[list[str], str]:
    """Disambiguate organisation types before selecting current P856 websites."""
    key = "wikidata-v2:" + _normalised_brand_key(name)
    previous = cached(key)
    if previous is not None:
        return previous["websites"], previous["message"]
    deadline = deadline or time.monotonic() + 5
    search = _wikidata_json(WIKIDATA_API, {"action": "wbsearchentities", "search": name,
        "language": "en", "format": "json", "limit": 5}, deadline)
    matches = [item for item in search.get("search", [])
        if _normalised_brand_key(item.get("label", "")) == _normalised_brand_key(name)
        or _normalised_brand_key((item.get("match") or {}).get("text", "")) == _normalised_brand_key(name)]
    ids = [item["id"] for item in matches if re.fullmatch(r"Q[0-9]+", str(item.get("id") or ""))][:5]
    data = _wikidata_json(WIKIDATA_API, {"action": "wbgetentities", "ids": "|".join(ids),
        "props": "claims", "format": "json"}, deadline).get("entities", {}) if ids else {}
    candidates = [(identifier, entity.get("claims") or {}) for identifier, entity in data.items()
                  if _organisation_claims(entity.get("claims") or {})]
    websites = []
    reference = ""
    if len(candidates) == 1:
        identifier, claims = candidates[0]
        statements = sorted(claims.get("P856", []), key=lambda item: {"preferred": 0, "normal": 1, "deprecated": 2}.get(item.get("rank", "normal"), 1))
        for item in statements:
            value = ((item.get("mainsnak", {}).get("datavalue") or {}).get("value"))
            if item.get("rank") != "deprecated" and isinstance(value, str) and _official_domain(value) and value not in websites:
                websites.append(value)
        reference = "https://www.wikidata.org/wiki/" + identifier
    message = ("Public organisation website resolved; sender authentication is checked separately." if websites
               else "Ambiguous company name: multiple plausible organisations were found." if len(candidates) > 1
               else "No independently resolved organisation website is available.")
    result = {"websites": websites, "message": message, "reference": reference, "observed_at": time.time()}
    put(key, result, 86400 if websites else 300)
    return websites, message


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
    """Resolve claims with explicit provenance, without promoting infrastructure."""
    contacts = _contact_domains(report)
    results: list[dict] = []
    sender = next((item["domain"] for item in contacts if item["source"] == "From"), "")
    auth = report.get("domain_authentication") or {}
    authenticated = auth.get("status") == "verified" and any(
        registered_domain(domain) == sender for domain in auth.get("verified_domains", []))
    from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout, CancelledError
    deadline = time.monotonic() + IDENTITY_LOOKUP_BUDGET_SECONDS
    pool = ThreadPoolExecutor(max_workers=4)
    candidates = [entity for entity in entities[:4] if entity.get("name") and _entity_is_brand_candidate(entity)]
    partners = {str(entity["name"]): resolve_partner(str(entity["name"])) for entity in candidates}
    futures = {str(entity["name"]): pool.submit(_official_sites, str(entity["name"]), deadline)
               for entity in candidates if not partners[str(entity["name"])]}
    dns_future = pool.submit(dns_observations, sender) if sender else None
    rdap_future = pool.submit(rdap_observations, sender) if sender and candidates else None
    def collected(future, default):
        if future is None:
            return default
        try:
            return future.result(timeout=max(0, deadline - time.monotonic()))
        except (FutureTimeout, CancelledError, requests.RequestException, ValueError, KeyError, TypeError):
            return default
    observation = collected(dns_future, {})
    registration = collected(rdap_future, {})
    pool.shutdown(wait=False, cancel_futures=True)
    for entity in candidates:
        name = str(entity.get("name") or "").strip()
        if not name or not _entity_is_brand_candidate(entity):
            continue
        partner = partners.get(name)
        relations = partner.get("relations", []) if partner else []
        if partner:
            official_domains = [item["domain"] for item in relations if item["role"] == "official"]
            websites = ["https://" + domain + "/" for domain in official_domains]
            source = partner["source"]
            reference = partner["reference"]
            verified_at, expires_at = partner["verified_at"], partner["expires_at"]
            message = "Company-to-domain relationships are recorded in an unexpired, scoped identity registry."
        else:
            try:
                websites, message = collected(futures.get(name), ([], "Public organisation lookup is currently unavailable."))
            except (requests.RequestException, ValueError, KeyError, TypeError):
                websites, message = [], "Public organisation lookup is currently unavailable."
            official_domains = list(dict.fromkeys(filter(None, (_official_domain(site) for site in websites))))
            source = "wikidata" if official_domains else "unresolved"
            public_evidence = cached("wikidata-v2:" + _normalised_brand_key(name)) or {}
            reference = public_evidence.get("reference", "https://www.wikidata.org/") if official_domains else ""
            verified_at = public_evidence.get("observed_at", time.time())
            expires_at = verified_at + 86400
        sender_domains = set(official_domains) if not partner else {
            item["domain"] for item in relations if "sender" in item["scopes"]}
        # An unknown website, redirect, CT certificate or shared provider can never add an accepted domain.
        associated = sorted(sender_domains - set(official_domains))
        comparisons = []
        for contact in contacts:
            domain = contact["domain"]
            is_sender = contact["source"] == "From"
            allowed = sender_domains if is_sender else {
                registered_domain(item["domain"]) for item in relations if "reply" in item["scopes"]}
            if not partner and not is_sender:
                allowed = set(official_domains)
            matches = any(relationship_matches(contact["hostname"], item) and ("sender" if is_sender else "reply") in item["scopes"] for item in relations) if partner else domain in allowed
            comparisons.append({**contact, "role": "sender_identity" if is_sender else "reply_destination" if contact["source"] == "Reply-To" else "transport",
                                "is_external": bool(official_domains and not matches),
                                "mismatch_eligible": is_sender, "matches_official": matches,
                                "redirects_to_official": False})
        mismatches = [item for item in comparisons if official_domains and item["mismatch_eligible"] and not item["matches_official"]]
        coherent = bool(sender and any(item["source"] == "From" and item["matches_official"] for item in comparisons))
        status = "mismatch" if mismatches else "aligned" if coherent and authenticated else "unverified"
        action_relations = [item for item in relations if any(scope != "sender" and scope != "reply" for scope in item["scopes"])]
        external_reply = sorted({item["domain"] for item in comparisons if item["role"] == "reply_destination" and item["is_external"]})
        # Only independently authenticated, registry-associated messages update a baseline.
        history_key = "baseline:" + (partner["id"] if partner else name.casefold()) + ":" + sender
        previous = cached(history_key) if partner and authenticated and coherent else None
        action_domains = sorted(_selected_action_domains(report))
        anomalies = []
        if previous and observation.get("status") == "observed":
            if previous.get("provider") != observation.get("provider") and previous.get("provider") != "unknown" and observation.get("provider") != "unknown":
                anomalies.append("The mail provider differs from the last independently authenticated observation.")
            if external_reply and set(external_reply) - set(previous.get("reply_domains", [])):
                anomalies.append("A new external reply destination was observed.")
            if set(action_domains) - set(previous.get("action_domains", [])):
                anomalies.append("A new action destination was observed for this confirmed sender.")
        if partner and authenticated and coherent and not previous:
            put(history_key, {"provider": observation.get("provider"), "reply_domains": external_reply,
                              "action_domains": action_domains}, 90 * 86400)
        results.append({"brand": name, "entity_types": entity.get("entity_types") or [entity.get("entity_type")],
                        "official_website": websites[0] if websites else "", "official_websites": websites,
                        "official_domain": official_domains[0] if official_domains else "", "official_domains": official_domains,
                        "associated_domains": associated, "trusted_action_domains": [],
                        "authorized_action_relations": action_relations if partner and authenticated and coherent else [],
                        "external_reply_domains": external_reply, "resolution_source": source,
                        "contacts": comparisons, "mismatches": mismatches, "status": status, "message": message,
                        "reference_status": partner["source"] if partner else "public_reference" if official_domains else "unresolved",
                        "sender_authentication": "verified" if authenticated else "unverified",
                        "evidence": [{"source": source, "reference": reference, "observed_at": verified_at, "expires_at": expires_at,
                                      "confidence": "high" if partner else "medium" if official_domains else "unknown"}] if official_domains else [],
                        "dns_observations": observation,
                        "registration_observations": registration,
                        "anomalies": anomalies})
    return results
