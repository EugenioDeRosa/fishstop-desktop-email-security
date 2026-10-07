"""Independent message authentication and DNS observations; no brand inference."""
from __future__ import annotations

import re
import time
from email.parser import BytesParser
from email.policy import default
from email.utils import parseaddr, getaddresses

import dns.resolver

from fishstop_engine.domain_utils import registered_domain, normalize_hostname
from fishstop_engine.identity_store import cached, put


def rdap_observations(domain: str) -> dict:
    """Registration metadata is risk context, never a company identity proof."""
    from urllib.parse import urlparse, quote
    import requests
    result = {"domain": domain, "status": "unavailable", "identity_evidence": False}
    previous = cached("rdap:" + domain)
    if previous is not None:
        return previous
    bootstrap = cached("rdap-bootstrap")
    session = requests.Session()
    session.trust_env = False
    try:
        if bootstrap is None:
            response = session.get("https://data.iana.org/rdap/dns.json", timeout=2, stream=True, allow_redirects=False)
            response.raise_for_status()
            raw = response.raw.read(512 * 1024 + 1, decode_content=True)
            response.close()
            if len(raw) > 512 * 1024:
                return result
            import json
            bootstrap = json.loads(raw)
            put("rdap-bootstrap", bootstrap, 7 * 86400)
        suffix = domain.rsplit(".", 1)[-1]
        bases = [url for tlds, urls in bootstrap.get("services", []) if suffix in tlds for url in urls if url.startswith("https://")]
        if not bases:
            put("rdap:" + domain, result, 300)
            return result
        url = bases[0].rstrip("/") + "/domain/" + quote(domain, safe="")
        # IANA chooses the server. The email can supply only the query domain.
        if not urlparse(url).hostname:
            return result
        response = session.get(url, timeout=2, stream=True, allow_redirects=False)
        if response.status_code != 200:
            return result
        raw = response.raw.read(256 * 1024 + 1, decode_content=True)
        response.close()
        if len(raw) > 256 * 1024:
            return result
        import json
        data = json.loads(raw)
        result.update(status="observed", source=url, observed_at=time.time(),
                      events=[{"action": item.get("eventAction"), "date": item.get("eventDate")} for item in data.get("events", [])[:20]],
                      registration_status=data.get("status", [])[:20])
        # Do not collect registrant personal data or equate registrar/hosting with ownership.
    except (requests.RequestException, ValueError, KeyError, TypeError):
        pass
    finally:
        session.close()
    put("rdap:" + domain, result, 86400 if result["status"] == "observed" else 300)
    return result


def verify_message_domain(raw: bytes, report: dict) -> dict:
    base = {"status": "unverified", "method": "independent_dkim", "verified_domains": [],
            "message": "The sender domain has not been independently authenticated. Header assertions alone do not verify identity."}
    if report.get("selected_target_authentication_scope") in {"embedded_unavailable", "mixed_outer_and_embedded"}:
        return {**base, "message": "Original sender authentication is unavailable for the selected embedded message."}
    try:
        import dkim
    except ImportError:
        return {**base, "message": "Independent DKIM verification is unavailable in this engine."}
    message = BytesParser(policy=default).parsebytes(raw, headersonly=True)
    if len(message.get_all("From", [])) != 1:
        return base
    if len(getaddresses([str(message.get("From") or "")])) != 1:
        return base
    from_domain = normalize_hostname(parseaddr(str(message.get("From") or ""))[1].rsplit("@", 1)[-1])
    if from_domain != normalize_hostname(parseaddr(str(report.get("from_") or ""))[1].rsplit("@", 1)[-1]):
        return base
    deadline = time.monotonic() + 5

    def dns_key(name, timeout=2):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        try:
            answers = dns.resolver.resolve(name.decode("ascii").rstrip("."), "TXT", lifetime=min(remaining, 2))
            records = [b"".join(item.strings) for item in answers]
            return records[0] if len(records) == 1 else None
        except (dns.exception.DNSException, UnicodeError):
            return None

    verified = []
    for index, signature in enumerate(message.get_all("DKIM-Signature", [])[:3]):
        tags = dict(re.findall(r"(?:^|;)\s*([a-z]+)\s*=\s*([^;]+)", str(signature), re.IGNORECASE))
        domain = normalize_hostname(tags.get("d", ""))
        # Partial-body signatures do not cover the complete actionable message.
        if "l" in tags or registered_domain(domain) != registered_domain(from_domain):
            continue
        try:
            verifier = dkim.DKIM(raw)
            if verifier.verify(idx=index, dnsfunc=dns_key):
                verified.append(domain)
        except Exception:
            continue
        if time.monotonic() >= deadline:
            break
    if verified:
        return {**base, "status": "verified", "verified_domains": sorted(set(verified)),
                "from_domain": from_domain, "message": "An aligned DKIM signature was independently verified on the original message. This authenticates its domain, not its company claim or safety."}
    return base


def dns_observations(domain: str) -> dict:
    host = normalize_hostname(domain)
    value = cached("dns:" + host)
    if value is not None:
        return value
    result = {"domain": host, "observed_at": time.time(), "mx": [], "spf": [], "dmarc": [], "bimi_present": False,
              "provider": "unknown", "status": "unavailable",
              "identity_evidence": False}
    deadline = time.monotonic() + 3
    for name, kind, field in [(host, "MX", "mx"), (host, "TXT", "spf"),
                               ("_dmarc." + host, "TXT", "dmarc"), ("default._bimi." + host, "TXT", "bimi")]:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            answers = dns.resolver.resolve(name, kind, lifetime=min(remaining, 1))
            if kind == "MX":
                result["mx"] = sorted({str(item.exchange).rstrip(".").lower() for item in answers})[:20]
            else:
                prefix = {"spf": "v=spf1", "dmarc": "v=dmarc1", "bimi": "v=bimi1"}[field]
                values = [b"".join(item.strings).decode("utf-8", "replace")[:2048] for item in answers]
                matches = [value for value in values if value.lower().startswith(prefix)][:2]
                if field == "bimi":
                    result["bimi_present"] = bool(matches)
                else:
                    result[field] = matches
            result["status"] = "observed"
        except dns.exception.DNSException:
            continue
    if any(host == "smtp.google.com" or host.endswith(".google.com") or host.endswith(".googlemail.com") for host in result["mx"]):
        result["provider"] = "Google Workspace"
    elif any(host.endswith(".mail.protection.outlook.com") for host in result["mx"]):
        result["provider"] = "Microsoft 365"
    elif result["mx"]:
        result["provider"] = "Other mail provider"
    put("dns:" + host, result, 3600 if result["status"] == "observed" else 120)
    return result
