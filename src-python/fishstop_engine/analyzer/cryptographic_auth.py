"""Independent DNS-backed email-authentication verification.

The regular parser preserves the receiver's Authentication-Results headers.
This module intentionally performs a separate verification against live DNS so
the UI can distinguish a claimed result from one FishStop could reproduce.
It is fail-safe: missing dependencies, incomplete exports and DNS failures are
reported as ``unavailable`` rather than authentication failures.
"""

from __future__ import annotations

import re
from email.utils import parseaddr
from typing import Any


DNS_TIMEOUT_SECONDS = 5.0
_DKIM_HEADER_RE = re.compile(
    rb"(?im)^DKIM-Signature:\s*(.*?)(?=\r?\n(?![ \t])|\Z)", re.DOTALL
)
_DKIM_DOMAIN_RE = re.compile(r"(?:^|;)\s*d\s*=\s*([^;\s]+)", re.IGNORECASE)


def _address_domain(value: str | None) -> str:
    address = parseaddr(str(value or ""))[1].strip().lower()
    return address.rsplit("@", 1)[-1].rstrip(".") if "@" in address else ""


def _dkim_domains(raw_email: bytes) -> list[str]:
    domains: list[str] = []
    for match in _DKIM_HEADER_RE.finditer(raw_email or b""):
        header = re.sub(rb"\r?\n[ \t]+", b" ", match.group(1))
        try:
            value = header.decode("utf-8", errors="replace")
        except Exception:
            continue
        domain = _DKIM_DOMAIN_RE.search(value)
        if domain:
            candidate = domain.group(1).lower().rstrip(".")
            if candidate:
                domains.append(candidate)
    return domains


def _org_domain(domain: str) -> str:
    """Use the public suffix list when available; otherwise retain the domain."""
    try:
        from publicsuffix2 import get_sld

        return str(get_sld(domain) or domain).lower().rstrip(".")
    except Exception:
        return domain.lower().rstrip(".")


def _aligned(authenticated_domain: str, from_domain: str, strict: bool) -> bool:
    candidate = authenticated_domain.lower().rstrip(".")
    visible = from_domain.lower().rstrip(".")
    if not candidate or not visible:
        return False
    return candidate == visible if strict else _org_domain(candidate) == _org_domain(visible)


def verify_dkim(raw_email: bytes) -> dict[str, Any]:
    domains = _dkim_domains(raw_email)
    base: dict[str, Any] = {
        "status": "unavailable",
        "signature_count": len(domains),
        "verified_domains": [],
        "message": "",
    }
    if not domains:
        return {**base, "message": "No DKIM-Signature header is available in this EML export."}
    try:
        import dkim
    except ImportError:
        return {**base, "message": "DKIM verification dependency is not installed."}

    verified: list[str] = []
    failures = 0
    unavailable = 0
    unavailable_reasons: list[str] = []
    for index, domain in enumerate(domains):
        try:
            verifier = dkim.DKIM(raw_email, timeout=DNS_TIMEOUT_SECONDS)
            if verifier.verify(idx=index):
                verified.append(domain)
            else:
                failures += 1
        except Exception as error:
            # DNS outages and malformed/unsupported signatures must not be
            # represented as proof of a failed signature.
            message = str(error).lower()
            if any(term in message for term in ("timeout", "dns", "temporary", "servfail", "nxdomain", "value is past", "signature has expired")):
                unavailable += 1
                unavailable_reasons.append(str(error))
            else:
                failures += 1

    if verified:
        return {
            **base,
            "status": "pass",
            "verified_domains": list(dict.fromkeys(verified)),
            "message": f"{len(verified)} of {len(domains)} DKIM signature(s) verified against DNS.",
        }
    if failures:
        return {
            **base,
            "status": "fail",
            "message": "DKIM signature verification failed against DNS.",
        }
    reason = unavailable_reasons[0] if unavailable_reasons else "DNS was unavailable."
    return {**base, "message": f"DKIM verification could not be completed: {reason}"}


def verify_spf(injection_ip: str | None, envelope_from: str | None, helo: str | None) -> dict[str, Any]:
    domain = _address_domain(envelope_from)
    base: dict[str, Any] = {
        "status": "unavailable",
        "identity": domain,
        "ip": injection_ip or "",
        "message": "",
    }
    if not injection_ip:
        return {**base, "message": "No public sender IP is available to evaluate SPF."}
    if not envelope_from or not domain:
        return {**base, "message": "No envelope MAIL FROM address is available to evaluate SPF."}
    if not helo:
        return {**base, "message": "No SMTP HELO hostname is available to evaluate SPF."}
    try:
        import spf
    except ImportError:
        return {**base, "message": "SPF verification dependency is not installed."}

    try:
        result, explanation = spf.check2(i=injection_ip, s=envelope_from, h=helo)
    except Exception as error:
        return {**base, "message": f"SPF verification could not be completed: {error}"}
    normalized = str(result or "unknown").lower()
    if normalized == "pass":
        status = "pass"
    elif normalized in {"fail", "softfail", "neutral"}:
        status = "fail"
    else:
        status = "unavailable"
    return {
        **base,
        "status": status,
        "spf_result": normalized,
        "message": str(explanation or f"SPF returned {normalized.upper()}.").strip(),
    }


def _dmarc_record(from_domain: str) -> tuple[str, str, str]:
    """Return record, policy domain and an availability reason when no record exists."""
    try:
        import dns.resolver
    except ImportError:
        return "", "", "DNS verification dependency is not installed."

    candidates = [from_domain]
    organizational = _org_domain(from_domain)
    if organizational and organizational not in candidates:
        candidates.append(organizational)
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = DNS_TIMEOUT_SECONDS
    resolver.lifetime = DNS_TIMEOUT_SECONDS
    for domain in candidates:
        try:
            answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except Exception as error:
            return "", "", f"DMARC DNS lookup could not be completed: {error}"
        for answer in answers:
            chunks = getattr(answer, "strings", ()) or ()
            value = b"".join(chunks).decode("utf-8", errors="replace")
            if re.search(r"(?:^|;)\s*v\s*=\s*DMARC1(?:\s*;|$)", value, re.IGNORECASE):
                return value, domain, ""
    return "", "", "No DMARC policy record was found for the visible sender domain."


def _dmarc_tag(record: str, name: str, default: str = "") -> str:
    match = re.search(rf"(?:^|;)\s*{re.escape(name)}\s*=\s*([^;\s]+)", record, re.IGNORECASE)
    return match.group(1).strip().lower() if match else default


def verify_dmarc(from_address: str | None, dkim: dict[str, Any], spf: dict[str, Any]) -> dict[str, Any]:
    from_domain = _address_domain(from_address)
    base: dict[str, Any] = {
        "status": "unavailable",
        "from_domain": from_domain,
        "policy": "",
        "policy_domain": "",
        "dkim_aligned": False,
        "spf_aligned": False,
        "message": "",
    }
    if not from_domain:
        return {**base, "message": "No visible From address is available to evaluate DMARC alignment."}
    record, policy_domain, error = _dmarc_record(from_domain)
    if not record:
        return {**base, "message": error}

    dkim_strict = _dmarc_tag(record, "adkim", "r") == "s"
    spf_strict = _dmarc_tag(record, "aspf", "r") == "s"
    dkim_aligned = any(
        _aligned(domain, from_domain, dkim_strict)
        for domain in (dkim.get("verified_domains") or [])
    )
    spf_aligned = (
        spf.get("status") == "pass"
        and _aligned(str(spf.get("identity") or ""), from_domain, spf_strict)
    )
    policy = _dmarc_tag(record, "p", "none")
    evaluated_statuses = {str(dkim.get("status") or ""), str(spf.get("status") or "")}
    enough_evidence_to_fail = evaluated_statuses <= {"pass", "fail"}
    status = "pass" if dkim_aligned or spf_aligned else "fail" if enough_evidence_to_fail else "unavailable"
    return {
        **base,
        "status": status,
        "policy": policy,
        "policy_domain": policy_domain,
        "dkim_aligned": dkim_aligned,
        "spf_aligned": spf_aligned,
        "alignment_mode": f"DKIM {'strict' if dkim_strict else 'relaxed'} · SPF {'strict' if spf_strict else 'relaxed'}",
        "message": (
            "At least one independently verified authentication domain aligns with From."
            if status == "pass"
            else "Neither independently verified SPF nor DKIM identity aligns with From."
            if status == "fail"
            else "DMARC policy was found, but the EML does not contain enough data to independently evaluate both SPF and DKIM alignment."
        ),
    }


def verify_cryptographic_authentication(
    raw_email: bytes,
    *,
    injection_ip: str | None,
    envelope_from: str | None,
    helo: str | None,
    from_address: str | None,
) -> dict[str, Any]:
    """Verify DKIM/SPF/DMARC independently while preserving header results."""
    dkim = verify_dkim(raw_email)
    spf = verify_spf(injection_ip, envelope_from, helo)
    dmarc = verify_dmarc(from_address, dkim, spf)
    statuses = [item["status"] for item in (dkim, spf, dmarc)]
    # DMARC alignment is the combined authentication result. Individual
    # mechanisms can legitimately be unavailable (for example an expired
    # archived DKIM signature) while a verified SPF identity aligns.
    # DMARC is the final identity-alignment outcome: it passes when either an
    # aligned, independently verified SPF or DKIM identity succeeds.  Keep an
    # isolated mechanism failure in its own result (and flag), but do not let
    # it override an aligned DMARC pass in the section-level status.
    overall = "pass" if dmarc.get("status") == "pass" else "fail" if "fail" in statuses else "unavailable"
    return {
        "status": overall,
        "provider": "local DNS-backed verification",
        "dkim": dkim,
        "spf": spf,
        "dmarc": dmarc,
    }
