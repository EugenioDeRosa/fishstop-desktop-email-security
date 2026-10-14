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
import unicodedata

from .constants import KNOWN_BRANDS, HOMOGLYPH_MAP
from fishstop_engine.domain_utils import registered_domain, registrable_label


MIN_EDIT_DISTANCE_SLD_LEN = 4


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

        for brand in brands:
            brand_norm = normalize_homoglyphs(brand)
            brand_sld  = strip_public_suffix(brand_norm)

            # Skip exact brand matches only when the original host is already ASCII-equivalent.
            # If it becomes exact only after homoglyph normalization, it is suspicious.
            host_lower = host.lower()
            if host_lower == brand_norm or host_lower.endswith("." + brand_norm):
                break

            # Tecnica 1: Levenshtein sull'SLD
            if (
                (not is_idn or suspicious_unicode)
                and
                len(host_sld) >= MIN_EDIT_DISTANCE_SLD_LEN
                and len(brand_sld) >= MIN_EDIT_DISTANCE_SLD_LEN
                and abs(len(host_sld) - len(brand_sld)) <= edit_distance_threshold
            ):
                dist = levenshtein(host_sld, brand_sld)
                if 0 < dist <= edit_distance_threshold:
                    _alert(url, host, brand, "edit_distance",
                           f"SLD `{host_sld}` dista {dist} edit da `{brand_sld}` "
                           f"(brand: {brand})", dist)
                    brand_risk_found = True
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
                    continue

            # Tecnica 4: Typosquatting - prefissi ingannatori
            for prefix in ("secure-", "login-", "verify-", "account-",
                           "update-", "signin-", "support-", "my-", "auth-"):
                candidate = host_norm.removeprefix("www.")
                if candidate.startswith(prefix):
                    inner = candidate[len(prefix):]
                    if levenshtein(strip_public_suffix(inner), brand_sld) <= 1:
                        _alert(url, host, brand, "typosquatting",
                               f"Deceptive prefix `{prefix}` before a domain "
                               f"simile a `{brand}`")
                        brand_risk_found = True
                        break

            # Typosquatting - sostituzione caratteri (0↔o, 1↔i/l, rn↔m)
            subst = (host_sld
                     .replace("0", "o").replace("1", "i").replace("1", "l")
                     .replace("rn", "m").replace("vv", "w"))
            if subst != host_sld and levenshtein(subst, brand_sld) == 0:
                _alert(url, host, brand, "typosquatting",
                       f"Sostituzione caratteri (`{host_sld}` -> `{subst}`) "
                       f"replica `{brand_sld}` (brand: {brand})")
                brand_risk_found = True

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
