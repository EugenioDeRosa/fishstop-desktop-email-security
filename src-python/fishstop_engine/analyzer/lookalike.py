"""
analyzer/lookalike.py - Rilevamento domini lookalike anti-phishing.

Espone:
  - levenshtein(a, b)             : distanza di edit tra due stringhe
  - normalize_homoglyphs(domain)  : sostituisce omoglifi Unicode con ASCII
  - strip_public_suffix(domain)   : isolates the second-level domain
  - is_ip_url(host)               : True if host is a bare IP
  - check_lookalike_domains(...)  : analisi euristica completa (edit distance,
                                    omoglifi, typosquatting)
"""

import ipaddress
import json
import re
import unicodedata
from functools import lru_cache
from pathlib import Path

from .constants import KNOWN_BRANDS, HOMOGLYPH_MAP
from fishstop_engine.domain_utils import normalize_hostname, registered_domain, registrable_label


MIN_EDIT_DISTANCE_SLD_LEN = 4
# Shorter brand labels are only compared after visual-confusable normalization
# (paypa1, rnicrosoft). Generic edit distance on short labels matches ordinary
# words (like/live, email/gmail, posta/poste) and produced HIGH false positives.
MIN_TYPO_CLASS_SLD_LEN = 5
MIN_SUBSTITUTION_SLD_LEN = 6
MIN_ANY_EDIT_SLD_LEN = 8
MIN_CONCATENATED_TOKEN_LEN = 5
# Platforms where organisations get a tenant subdomain named after them
# (azienda.sharepoint.com, brand.zendesk.com). A protected name in the
# subdomain of these platforms is the expected tenant pattern.
SAAS_TENANT_DOMAINS = frozenset({
    "zendesk.com", "freshdesk.com", "helpscoutdocs.com", "atlassian.net", "service-now.com",
    "okta.com", "oktapreview.com", "my.salesforce.com", "force.com", "salesforce.com", "slack.com",
    "webex.com", "zoom.us", "box.com", "egnyte.com", "sharefile.com", "myshopify.com",
    "workday.com", "myworkdayjobs.com", "bamboohr.com", "teamviewer.com", "docebosaas.com",
})
BRAND_DATA_PATH = Path(__file__).resolve().parents[1] / "data" / "brand-lookalike.json"

# Visually confusable single characters (both directions are considered).
_CONFUSABLE_PAIRS = frozenset({
    frozenset(pair) for pair in (
        ("o", "0"), ("l", "1"), ("i", "1"), ("l", "i"), ("m", "n"), ("u", "v"),
        ("e", "3"), ("s", "5"), ("g", "q"), ("a", "4"), ("b", "8"),
    )
})
_MULTI_CHAR_CONFUSABLES = (("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "m"))


@lru_cache(maxsize=1)
def _brand_data() -> dict:
    try:
        data = json.loads(BRAND_DATA_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    brands = []
    for item in data.get("brands") or []:
        domains = frozenset(registered_domain(domain) for domain in item.get("domains") or [] if domain)
        tokens = frozenset(str(token).lower() for token in item.get("tokens") or [] if len(str(token)) >= 3)
        if domains and tokens:
            brands.append({"brand": str(item.get("brand") or ""), "domains": domains, "tokens": tokens})
    return {
        "lure_words": frozenset(str(word).lower() for word in data.get("lure_words") or []),
        "brands": tuple(brands),
    }


# Labels too generic to identify an organisation inside another domain.
_GENERIC_ORGANISATION_LABELS = frozenset({
    "example", "test", "mail", "email", "info", "admin", "office", "online", "group", "company",
    "service", "services", "web", "site", "home", "shop", "store", "studio", "network", "cloud",
    "global", "italia", "italy", "europe", "digital", "media", "news", "consulting", "solutions",
})
_RESERVED_TLDS = frozenset({"invalid", "example", "test", "local", "localhost", "internal", "lan", "corp", "home"})


def _brand_record(brand_domain: str) -> dict:
    """Return the catalog entry for a brand domain, or a single-domain record."""
    registered = registered_domain(brand_domain)
    for record in _brand_data()["brands"]:
        if registered in record["domains"]:
            return record
    label = registrable_label(registered)
    usable = len(label) >= 3 and label not in _GENERIC_ORGANISATION_LABELS
    return {"brand": registered, "domains": frozenset({registered}),
            "tokens": frozenset({label}) if usable else frozenset()}


def _confusable_skeletons(value: str) -> set[str]:
    """ASCII skeletons after replacing visually confusable characters."""
    base = value.replace("0", "o").replace("3", "e").replace("5", "s").replace("4", "a").replace("8", "b")
    variants = {base.replace("1", "l"), base.replace("1", "i")}
    result = set()
    for variant in variants:
        for source, target in _MULTI_CHAR_CONFUSABLES:
            variant = variant.replace(source, target)
        result.add(variant)
    return result


def _is_typo_class_edit(candidate: str, brand: str) -> bool:
    """True when one edit is a common typosquatting edit, not an arbitrary word.

    Accepted: confusable substitution, adjacent transposition, doubled or
    dropped repeated letter, inserted hyphen.
    """
    if candidate == brand:
        return False
    if len(candidate) == len(brand):
        diffs = [index for index, (left, right) in enumerate(zip(candidate, brand)) if left != right]
        if len(diffs) == 1:
            index = diffs[0]
            return frozenset((candidate[index], brand[index])) in _CONFUSABLE_PAIRS
        if len(diffs) == 2 and diffs[1] == diffs[0] + 1:
            first, second = diffs
            return candidate[first] == brand[second] and candidate[second] == brand[first]
        return False
    longer, shorter = (candidate, brand) if len(candidate) > len(brand) else (brand, candidate)
    if len(longer) - len(shorter) != 1:
        return False
    for index in range(len(longer)):
        if longer[:index] + longer[index + 1:] == shorter:
            removed = longer[index]
            if removed == "-":
                return True
            neighbours = longer[index - 1:index] + longer[index + 1:index + 2]
            if removed in neighbours:
                return True
    return False


def _split_lure_words(value: str, lure_words: frozenset[str]) -> bool:
    """True when value is empty, digits, or a concatenation of lure words."""
    value = re.sub(r"[0-9]+", "", value)
    if not value:
        return True
    reachable = [False] * (len(value) + 1)
    reachable[0] = True
    for end in range(1, len(value) + 1):
        for start in range(max(0, end - 16), end):
            if reachable[start] and value[start:end] in lure_words:
                reachable[end] = True
                break
    return reachable[-1]


def _combosquat_match(host_norm: str, record: dict) -> tuple[str, str] | None:
    """Detect a brand token inside an unrelated domain.

    Returns (technique, level) or None. Exact separated tokens are MEDIUM;
    tokens combined with lure words, or an official domain reused as a
    subdomain prefix, are HIGH.
    """
    lure_words = _brand_data()["lure_words"]
    registered = registered_domain(host_norm)
    if not registered or registered in record["domains"]:
        return None
    for official in record["domains"]:
        if host_norm.startswith(official + ".") or ("." + official + ".") in host_norm:
            return "brand_subdomain", "HIGH"
    suffix_free = host_norm[: -len(registered)].rstrip(".") if host_norm.endswith(registered) else ""
    registrable = registered.split(".", 1)[0]

    def match_in(labels: list[str]) -> str | None:
        parts = [part for label in labels for part in re.split(r"[-_]+", label) if part]
        if not parts:
            return None
        has_lure = any(part in lure_words for part in parts) or any(
            _split_lure_words(part, lure_words) for part in parts
            if not any(token in part for token in record["tokens"]))
        for token in record["tokens"]:
            skeleton_parts = [skeleton for part in parts for skeleton in _confusable_skeletons(part)]
            if token in parts or token in skeleton_parts:
                return "HIGH" if has_lure else "MEDIUM"
            if len(token) < MIN_CONCATENATED_TOKEN_LEN:
                continue
            for part in parts:
                for skeleton in {part} | _confusable_skeletons(part):
                    if skeleton == token:
                        continue
                    if skeleton.startswith(token) and _split_lure_words(skeleton[len(token):], lure_words):
                        return "HIGH"
                    if skeleton.endswith(token) and _split_lure_words(skeleton[: -len(token)], lure_words):
                        return "HIGH"
        return None

    # The brand label alone on another TLD (amazon.de) is not reported:
    # brands operate many ccTLDs that a static list cannot enumerate.
    if registrable not in record["tokens"] and not (_confusable_skeletons(registrable) & record["tokens"]):
        level = match_in([registrable])
        if level:
            return "combosquatting", level
    # A brand name only in the subdomain of another registrable domain is
    # common for SaaS tenants (brand.zendesk.com) and is capped at review;
    # tenants of known platforms and brand-operated domains are not reported.
    catalog_domains = {domain for item in _brand_data()["brands"] for domain in item["domains"]}
    if registered in SAAS_TENANT_DOMAINS or registered in catalog_domains:
        return None
    if suffix_free and match_in(suffix_free.split(".")):
        return "combosquatting", "MEDIUM"
    return None


def levenshtein(a: str, b: str) -> int:
    """Distanza di edit (Levenshtein) tra due stringhe, O(n·m) spazio O(n)."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(
                prev[j] + 1,
                curr[j - 1] + 1,
                prev[j - 1] + (ca != cb),
            ))
        prev = curr
    return prev[-1]


def normalize_homoglyphs(domain: str) -> str:
    """
    Normalizes a domain by replacing Unicode homoglyph characters with
    il loro equivalente ASCII. Gestisce anche la forma NFC/NFKC.
    """
    domain = unicodedata.normalize("NFKC", domain.lower())
    return "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in domain)


def decode_punycode_domain(host: str) -> str:
    """
    Decodifica le label IDNA/punycode (xn--) in Unicode.

    Se una label e' malformata, viene lasciata invariata per non interrompere
    l'analisi dell'email.
    """
    decoded, _ = _decode_punycode_domain(host)
    return decoded


def _decode_punycode_domain(host: str) -> tuple[str, bool]:
    """Return the decoded host and whether every punycode label was valid."""
    labels = []
    valid = True
    for label in (host or "").lower().rstrip(".").split("."):
        if label.startswith("xn--"):
            try:
                labels.append(label.encode("ascii").decode("idna"))
            except UnicodeError:
                labels.append(label)
                valid = False
        else:
            labels.append(label)
    return ".".join(labels), valid


def _has_punycode_label(host: str) -> bool:
    return any(label.lower().startswith("xn--") for label in (host or "").split("."))


def _has_homoglyph_chars(value: str) -> bool:
    normalized = unicodedata.normalize("NFKC", (value or "").lower())
    return any(ch in HOMOGLYPH_MAP for ch in normalized)


def _character_script(ch: str) -> str | None:
    """Return a coarse Unicode script for letters used in IDN labels."""
    if not ch.isalpha():
        return None
    name = unicodedata.name(ch, "")
    for script in (
        "LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "HEBREW", "ARABIC",
        "HIRAGANA", "KATAKANA", "HANGUL", "THAI", "DEVANAGARI",
        "BENGALI", "GEORGIAN",
    ):
        if script in name:
            return script
    if "CJK" in name or "IDEOGRAPH" in name:
        return "HAN"
    return "OTHER"


def _mixed_script_labels(domain: str) -> list[str]:
    mixed: list[str] = []
    for label in (domain or "").lower().rstrip(".").split("."):
        scripts = {
            script
            for ch in unicodedata.normalize("NFKC", label)
            if (script := _character_script(ch)) is not None
        }
        if len(scripts) > 1:
            mixed.append(label)
    return mixed


def is_risky_lookalike_alert(alert: dict) -> bool:
    """True for alerts that may influence the verdict.

    Reports produced before alert levels were introduced are treated as risky
    so that stored analyses keep their original, fail-closed behaviour.
    """
    return str(alert.get("level") or "HIGH").upper() in {"HIGH", "MEDIUM"}


def strip_public_suffix(domain: str) -> str:
    """
    Return the registrable label using the Public Suffix List.

    Esempio: mail.paypa1.com -> paypa1
    """
    return registrable_label(domain)



def is_ip_url(host: str) -> bool:
    """True if the host is an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address((host or "").strip("[]"))
        return True
    except ValueError:
        return False


def check_lookalike_domains(
    links: list[dict],
    known_brands: list[str] | None = None,
    edit_distance_threshold: int = 2,
) -> list[dict]:
    """
    For each link, checks whether the domain looks like a known brand
    usando tre tecniche combinate:

      1. Levenshtein distance sull'SLD (Second-Level Domain) ≤ threshold
      2. Omografia Unicode - caratteri visivamente identici ad ASCII
      3. Typosquatting patterns - inserimento/duplicazione consonanti,
         sostituzione 0↔o / 1↔l / rn↔m, aggiunta prefissi ingannevoli

    Returns only alerts (empty list = no suspicion found).

    Ogni alert:
      {
        "url"           : str
        "host"          : str
        "matched_brand" : str
        "technique"     : "edit_distance" | "homoglyph" | "typosquatting" | ...
        "detail"        : str
        "edit_distance" : int | None
        "level"         : "HIGH" | "MEDIUM" | "INFO"
      }
    """
    brands = known_brands if known_brands is not None else KNOWN_BRANDS
    alerts: list[dict] = []
    seen_pairs: set[tuple[str, str, str]] = set()

    def _alert(url: str, host: str, brand: str, technique: str,
                detail: str, dist: int | None = None,
                level: str = "HIGH") -> None:
        key = (host, brand, technique)
        if key in seen_pairs:
            return
        seen_pairs.add(key)
        alerts.append({
            "url":           url,
            "host":          host,
            "registered_domain": registered_domain(host),
            "matched_brand": brand,
            "technique":     technique,
            "detail":        detail,
            "edit_distance": dist,
            "level":         level,
        })

    for link in links:
        host = link["host"]
        url  = link["url"]

        if not host or is_ip_url(host):
            continue

        is_punycode = _has_punycode_label(host)
        decoded_host, valid_punycode = _decode_punycode_domain(host)
        comparison_host = decoded_host if is_punycode and valid_punycode else host
        host_norm = normalize_homoglyphs(comparison_host)
        host_sld = strip_public_suffix(host_norm)
        has_homoglyph_chars = _has_homoglyph_chars(comparison_host)
        mixed_labels = _mixed_script_labels(comparison_host)
        is_idn = is_punycode or any(ord(ch) > 127 for ch in host)
        suspicious_unicode = has_homoglyph_chars or bool(mixed_labels)
        brand_risk_found = False

        if is_punycode and not valid_punycode:
            _alert(
                url,
                host,
                "-",
                "punycode_invalid",
                f"The domain `{host}` contains an invalid IDNA label.",
                level="MEDIUM",
            )

        host_registered = registered_domain(host_norm)
        official_hosts = {registered_domain(normalize_homoglyphs(brand)) for brand in brands}
        if host_registered in official_hosts and not suspicious_unicode and not is_punycode:
            continue

        matched_records: set[str] = set()
        for brand in brands:
            brand_norm = normalize_homoglyphs(brand)
            brand_sld  = strip_public_suffix(brand_norm)
            record = _brand_record(brand_norm)
            record_key = record["brand"] or brand_norm
            if record_key in matched_records:
                continue

            # Skip exact brand matches only when the original host is already ASCII-equivalent.
            # If it becomes exact only after homoglyph normalization, it is suspicious.
            host_lower = host.lower()
            if host_lower == brand_norm or host_lower.endswith("." + brand_norm):
                break
            if host_registered in record["domains"] and not suspicious_unicode:
                continue

            # Tecnica 1: typosquatting on the registrable label. Confusable
            # characters first, then typo-class edits scaled by label length.
            if not is_idn and host_sld != brand_sld and len(brand_sld) >= MIN_EDIT_DISTANCE_SLD_LEN:
                if brand_sld in _confusable_skeletons(host_sld):
                    _alert(url, host, brand, "typosquatting",
                           f"Character substitution in `{host_sld}` reproduces `{brand_sld}` (brand: {brand})", 1)
                    brand_risk_found = True
                    matched_records.add(record_key)
                    continue
                dist = levenshtein(host_sld, brand_sld)
                typo_class = _is_typo_class_edit(host_sld, brand_sld)
                same_length_substitution = dist == 1 and len(host_sld) == len(brand_sld)
                if (
                    (typo_class and len(brand_sld) >= MIN_TYPO_CLASS_SLD_LEN)
                    or (same_length_substitution and len(brand_sld) >= MIN_SUBSTITUTION_SLD_LEN)
                    or (dist == 1 and len(brand_sld) >= MIN_ANY_EDIT_SLD_LEN)
                    or (dist == 2 and len(brand_sld) >= 10 and abs(len(host_sld) - len(brand_sld)) <= 2)
                ):
                    level = "HIGH" if typo_class or len(brand_sld) >= MIN_ANY_EDIT_SLD_LEN else "MEDIUM"
                    _alert(url, host, brand, "edit_distance",
                           f"SLD `{host_sld}` is {dist} edit(s) from `{brand_sld}` (brand: {brand})", dist, level)
                    brand_risk_found = True
                    matched_records.add(record_key)
                    continue

            # Tecnica 2: Omografia Unicode
            if suspicious_unicode and host_norm != host_lower:
                normalized_matches_brand = (
                    host_norm == brand_norm
                    or host_norm.endswith("." + brand_norm)
                    or host_sld == brand_sld
                    or levenshtein(host_sld, brand_sld) <= edit_distance_threshold
                )
                if normalized_matches_brand:
                    _alert(
                        url,
                        host,
                        brand,
                        "punycode_homograph" if is_punycode else "homoglyph",
                        (
                            f"Punycode domain `{host}` decoded as `{decoded_host}`; "
                            if is_punycode else f"The domain `{host}` "
                        )
                        + f"contains confusable or mixed-script characters and "
                          f"normalizes to a domain similar to `{brand}`.",
                    )
                    brand_risk_found = True
                    matched_records.add(record_key)
                    continue

            # Tecnica 3: combosquatting and brand used as a subdomain label.
            combo = _combosquat_match(host_norm, record)
            if combo:
                technique, level = combo
                detail = (
                    f"The official domain of {record['brand'] or brand} is used as a subdomain of `{host_registered}`"
                    if technique == "brand_subdomain"
                    else f"The domain `{host}` contains the brand name of {record['brand'] or brand} but is not one of its domains"
                )
                _alert(url, host, brand, technique, detail, None, level)
                brand_risk_found = True
                matched_records.add(record_key)
                continue

        if brand_risk_found:
            continue

        if mixed_labels:
            _alert(
                url,
                host,
                "-",
                "mixed_script_idn",
                f"The decoded domain `{comparison_host}` mixes Unicode scripts "
                f"inside label(s): {', '.join(mixed_labels)}.",
                level="MEDIUM",
            )
        elif has_homoglyph_chars:
            _alert(
                url,
                host,
                "-",
                "unicode_homoglyph",
                f"The decoded domain `{comparison_host}` contains Unicode "
                f"confusable characters; normalized form: `{host_norm}`.",
                level="MEDIUM",
            )
        elif is_punycode and valid_punycode and decoded_host != host.lower():
            _alert(
                url,
                host,
                "-",
                "punycode_idna",
                f"Valid internationalized domain `{host}`, decoded as "
                f"`{decoded_host}`; no homograph evidence was found.",
                level="INFO",
            )

    return alerts


def _public_email_provider(domain: str) -> bool:
    from fishstop_engine.otx_intelligence import _public_email_provider_domains
    registered = registered_domain(domain)
    return bool(registered) and (
        registered in _public_email_provider_domains()
        or normalize_hostname(domain) in _public_email_provider_domains()
    )


def organization_domains(report: dict) -> list[str]:
    """Recipient organisation domains (To / Delivered-To), excluding mailbox providers.

    Business email compromise frequently imitates the recipient's own company
    domain (azienda-spa.it to @azienda.it). These domains are therefore used
    as additional protected names by the static lookalike checks.
    """
    from fishstop_engine.domain_utils import mailbox_candidates
    domains: list[str] = []
    for key in ("delivered_to", "to"):
        for _, address in mailbox_candidates(report.get(key) or "")[:20]:
            domain = registered_domain(address.rsplit("@", 1)[-1])
            if not domain or domain in domains or _public_email_provider(domain):
                continue
            try:
                ipaddress.ip_address(domain)
                continue
            except ValueError:
                pass
            if "." not in domain or domain.rsplit(".", 1)[-1] in _RESERVED_TLDS:
                continue
            domains.append(domain)
    return domains[:5]


def protected_brands(report: dict) -> list[str]:
    """Known brands plus the recipient organisation domains."""
    brands = list(KNOWN_BRANDS)
    for record in _brand_data()["brands"]:
        for domain in sorted(record["domains"]):
            if domain not in brands:
                brands.append(domain)
                break
    for domain in organization_domains(report):
        if domain not in brands:
            brands.append(domain)
    return brands


def check_sender_lookalikes(report: dict) -> list[dict]:
    """Apply the lookalike checks to From, Reply-To and Return-Path domains.

    A sender address on a mailbox provider (gmail.com) cannot be a lookalike
    domain itself; brand claims on such addresses are handled by identity
    checks. The recipient organisation is protected against imitation, but
    mail from the organisation's own domain is not reported.
    """
    from fishstop_engine.domain_utils import mailbox_candidates
    brands = protected_brands(report)
    alerts: list[dict] = []
    seen: set[tuple[str, str]] = set()
    fields = (("From", "from_"), ("Reply-To", "reply_to"), ("Return-Path", "return_path"))
    if report.get("selected_target_authentication_scope") == "embedded_unavailable":
        fields = fields[:1]
    for field, key in fields:
        for _, address in mailbox_candidates(report.get(key) or "")[:5]:
            host = normalize_hostname(address.rsplit("@", 1)[-1])
            if not host or _public_email_provider(host):
                continue
            for alert in check_lookalike_domains([{"host": host, "url": f"mailto:{address}"}], known_brands=brands):
                if not is_risky_lookalike_alert(alert):
                    continue
                identity = (host, alert.get("matched_brand") or "")
                if identity in seen:
                    continue
                seen.add(identity)
                alerts.append({**alert, "field": field, "address": address,
                               "organization_domain": alert.get("matched_brand") in organization_domains(report)})
    return alerts
