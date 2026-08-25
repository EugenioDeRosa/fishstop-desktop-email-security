"""External indicator reputation lookups used by the desktop engine."""

import base64
import ipaddress
import socket
import re
from urllib.parse import urlparse

try:
    import requests
except ImportError:  # Static parsing must remain usable without optional lookups.
    requests = None

VT = "https://www.virustotal.com/api/v3"
ABUSE = "https://api.abuseipdb.com/api/v2/check"
RDAP = "https://rdap.org/domain"


def _vt_status(data: dict, base: dict) -> dict:
    stats = (data.get("data") or {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious, suspicious = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
    harmless, undetected, timeout = (int(stats.get(key, 0)) for key in ("harmless", "undetected", "timeout"))
    total = malicious + suspicious + harmless + undetected + timeout
    attrs = (data.get("data") or {}).get("attributes", {})
    raw_context = attrs.get("crowdsourced_context") or attrs.get("crowdsourced_contexts") or []
    context = raw_context if isinstance(raw_context, list) else [raw_context]
    context_titles = [str((item.get("attributes") if isinstance(item, dict) and isinstance(item.get("attributes"), dict) else item).get("title") or "Crowdsourced context") for item in context if isinstance(item, dict)][:3]
    return {**base, "status": "malicious" if malicious else "suspicious" if suspicious else "clean" if total else "unknown", "malicious": malicious, "suspicious": suspicious, "harmless": harmless, "undetected": undetected, "timeout": timeout, "total_engines": total, "detection_ratio": f"{malicious + suspicious} / {total}" if total else "0 / 0", "last_analysis": attrs.get("last_analysis_date") or "", "reputation": attrs.get("reputation", 0), "title": attrs.get("title", ""), "crowdsourced_context": context, "crowdsourced_context_summary": " · ".join(context_titles)}


def check_url(api_key: str, url: str) -> dict:
    base = {"url": url, "status": "skipped", "malicious": 0, "suspicious": 0, "total_engines": 0, "detection_ratio": "-"}
    if not api_key:
        return {**base, "message": "VirusTotal is not configured: add the API key in Settings."}
    if requests is None: return {**base, "message": "Reputation check unavailable: install requests."}
    identifier = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    try:
        response = requests.get(f"{VT}/urls/{identifier}", headers={"x-apikey": api_key}, timeout=10)
        if response.status_code == 404: return {**base, "status": "not_found", "message": "URL not found on VirusTotal"}
        if response.status_code == 401: return {**base, "status": "error", "message": "Invalid VirusTotal API key"}
        if response.status_code == 429: return {**base, "status": "error", "message": "VirusTotal rate limit exceeded"}
        response.raise_for_status()
        payload = response.json()
        result = _vt_status(payload, base)
        object_id = str((payload.get("data") or {}).get("id") or "")
        return {**result, "permalink": f"https://www.virustotal.com/gui/url/{object_id}" if object_id else "https://www.virustotal.com/gui/home/url"}
    except requests.RequestException as error:
        return {**base, "status": "error", "message": f"VirusTotal unavailable: {error}"}


def check_file(api_key: str, sha256: str) -> dict:
    base = {"sha256": sha256, "status": "skipped", "malicious": 0, "suspicious": 0, "total_engines": 0, "detection_ratio": "-"}
    if not api_key: return {**base, "message": "VirusTotal is not configured: add the API key in Settings."}
    if requests is None: return {**base, "message": "Reputation check unavailable: install requests."}
    try:
        response = requests.get(f"{VT}/files/{sha256}", headers={"x-apikey": api_key}, timeout=10)
        if response.status_code == 404: return {**base, "status": "not_found", "message": "Hash not found on VirusTotal"}
        if response.status_code == 401: return {**base, "status": "error", "message": "Invalid VirusTotal API key"}
        if response.status_code == 429: return {**base, "status": "error", "message": "VirusTotal rate limit exceeded"}
        response.raise_for_status(); result = _vt_status(response.json(), base)
        attrs = (response.json().get("data") or {}).get("attributes", {}); ptc = attrs.get("popular_threat_classification") or {}
        return {**result, "threat_label": ptc.get("suggested_threat_label", ""), "file_type": attrs.get("type_description", ""), "file_name": (attrs.get("names") or [""])[0], "permalink": f"https://www.virustotal.com/gui/file/{sha256}"}
    except requests.RequestException as error:
        return {**base, "status": "error", "message": f"VirusTotal unavailable: {error}"}


def check_vt_domain(api_key: str, domain: str) -> dict:
    domain = (domain or "").lower().strip().strip(".")
    base = {"domain": domain, "domain_queried": domain, "status": "skipped", "malicious": 0, "suspicious": 0, "detection_ratio": "-"}
    if not api_key: return {**base, "message": "VirusTotal is not configured: add the API key in Settings."}
    if requests is None: return {**base, "message": "Reputation check unavailable: install requests."}
    try:
        response = requests.get(f"{VT}/domains/{domain}", headers={"x-apikey": api_key}, timeout=10)
        if response.status_code == 404:
            parent = _parent_domain_for_reputation(domain)
            if parent != domain:
                fallback = check_vt_domain(api_key, parent)
                return {
                    **fallback,
                    "domain_queried": domain,
                    "used_parent_fallback": parent,
                    "message": f"Exact subdomain not found on VirusTotal; analysed parent domain {parent}.",
                }
            return {**base, "status": "not_found", "message": "Domain not found on VirusTotal"}
        if response.status_code == 401: return {**base, "status": "error", "message": "Invalid VirusTotal API key"}
        if response.status_code == 429: return {**base, "status": "error", "message": "VirusTotal rate limit exceeded"}
        response.raise_for_status()
        payload = response.json(); result = _vt_status(payload, base)
        attrs = (payload.get("data") or {}).get("attributes", {})
        return {**result, "registrar": attrs.get("registrar", ""), "creation_date": attrs.get("creation_date", ""), "last_update_date": attrs.get("last_update_date", ""), "permalink": f"https://www.virustotal.com/gui/domain/{domain}"}
    except requests.RequestException as error:
        return {**base, "status": "error", "message": f"VirusTotal unavailable: {error}"}


def check_rdap_domain(domain: str) -> dict:
    base = {"domain": domain, "status": "skipped"}
    if requests is None: return {**base, "message": "RDAP lookup unavailable: install requests."}
    try:
        response = requests.get(f"{RDAP}/{domain}", headers={"Accept": "application/rdap+json", "User-Agent": "FishStop/1.0"}, timeout=8)
        if response.status_code == 404: return {**base, "status": "not_found", "message": "Domain is not available in RDAP."}
        response.raise_for_status(); payload = response.json()
        events = {str(item.get("eventAction") or "").lower(): item.get("eventDate") or "" for item in (payload.get("events") or []) if isinstance(item, dict)}
        registrar = ""
        for entity in payload.get("entities") or []:
            if "registrar" not in [str(role).lower() for role in (entity.get("roles") or [])]: continue
            vcard = entity.get("vcardArray") or []
            if len(vcard) > 1:
                for field in vcard[1]:
                    if field and field[0] == "fn": registrar = str(field[3] or ""); break
        return {**base, "status": "ok", "registration_date": events.get("registration", ""), "last_changed_date": events.get("last changed", ""), "registrar": registrar, "handle": payload.get("handle", ""), "url": f"https://rdap.org/domain/{domain}"}
    except requests.RequestException as error:
        return {**base, "status": "error", "message": f"RDAP unavailable: {error}"}


def check_ip(api_key: str, ip: str) -> dict:
    base = {"ip": ip, "status": "skipped", "abuseConfidenceScore": 0, "totalReports": 0}
    try:
        if not ipaddress.ip_address(ip.strip("[]")).is_global: return {**base, "message": "Non-public IP: check skipped"}
    except ValueError: return {**base, "message": "Invalid IP address"}
    if not api_key: return {**base, "message": "AbuseIPDB is not configured: add the API key in Settings."}
    if requests is None: return {**base, "message": "Reputation check unavailable: install requests."}
    try:
        response = requests.get(ABUSE, params={"ipAddress": ip, "maxAgeInDays": "90"}, headers={"Key": api_key, "Accept": "application/json"}, timeout=6)
        if response.status_code == 401: return {**base, "status": "error", "message": "Invalid AbuseIPDB API key"}
        if response.status_code == 429: return {**base, "status": "error", "message": "AbuseIPDB rate limit exceeded"}
        response.raise_for_status(); data = response.json().get("data", {})
        return {**base, "status": "ok", "abuseConfidenceScore": int(data.get("abuseConfidenceScore") or 0), "totalReports": int(data.get("totalReports") or 0), "countryCode": data.get("countryCode") or "", "isp": data.get("isp") or "", "url": f"https://www.abuseipdb.com/check/{ip}"}
    except requests.RequestException as error:
        return {**base, "status": "error", "message": f"AbuseIPDB unavailable: {error}"}


def _parent_domain_for_reputation(domain: str) -> str:
    """Return the registrable-looking parent used by the Streamlit fallback."""
    labels = [label for label in domain.lower().strip(".").split(".") if label]
    if len(labels) <= 2:
        return domain
    # Preserve the commonly used three-label country suffixes handled by the
    # Streamlit implementation, otherwise inspect the final two labels.
    if len(labels[-2]) <= 3 and labels[-1] in {"uk", "it", "au", "br", "za", "jp"}:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def check_domain(api_key: str, domain: str) -> dict:
    """Resolve a sender domain and check the resulting IP on AbuseIPDB.

    Campaigns commonly use a non-existent random subdomain under a real parent
    domain. As in the Streamlit application, a DNS-negative result therefore
    receives one explicit parent-domain fallback; the response always preserves
    the original queried domain so the UI cannot imply that it resolved.
    """
    domain = (domain or "").lower().strip().strip(".")
    base = {"domain_queried": domain, "resolved_ip": "", "status": "skipped"}
    if not domain:
        return {**base, "message": "No domain to resolve."}
    if not api_key:
        return {**base, "message": "AbuseIPDB is not configured: add the API key in Settings."}

    resolved_domain = domain
    used_parent_fallback = ""
    try:
        ip = socket.gethostbyname(resolved_domain)
    except OSError as original_error:
        parent = _parent_domain_for_reputation(domain)
        if parent == domain:
            return {**base, "message": f"Domain resolution failed: {original_error}"}
        try:
            ip = socket.gethostbyname(parent)
        except OSError:
            return {**base, "message": f"Domain resolution failed: {original_error}"}
        resolved_domain = parent
        used_parent_fallback = parent

    result = {
        **check_ip(api_key, ip),
        "domain_queried": domain,
        "resolved_ip": ip,
        "resolved_domain": resolved_domain,
        "lookup_method": "system-socket-parent-fallback" if used_parent_fallback else "system-socket",
    }
    if used_parent_fallback:
        result.update({
            "used_parent_fallback": used_parent_fallback,
            "message": (
                f"The subdomain could not be resolved; reputation was calculated for parent domain "
                f"{used_parent_fallback}."
            ),
        })
    return result


def geolocate(ip: str) -> dict:
    base = {"ip": ip, "status": "skipped", "provider": "ipwho.is"}
    try:
        if not ipaddress.ip_address(ip.strip("[]")).is_global: return {**base, "message": "Non-public IP address"}
    except ValueError: return {**base, "message": "Invalid IP address"}
    if requests is None: return {**base, "message": "Geolocation unavailable: install requests."}
    try:
        data = requests.get(f"https://ipwho.is/{ip}", timeout=5).json()
        if not data.get("success", False): return {**base, "message": str(data.get("message") or "Invalid response")}
        connection = data.get("connection") or {}
        security = data.get("security") or {}
        return {
            **base,
            "status": "ok",
            "country": data.get("country", ""),
            "country_code": data.get("country_code", ""),
            "region": data.get("region", ""),
            "city": data.get("city", ""),
            "lat": data.get("latitude"),
            "lon": data.get("longitude"),
            "timezone": (data.get("timezone") or {}).get("id", ""),
            "isp": connection.get("isp", ""),
            "org": connection.get("org", ""),
            "asn": connection.get("asn", ""),
            "is_proxy": bool(security.get("proxy")),
            "is_hosting": bool(security.get("hosting")),
        }
    except requests.RequestException as error: return {**base, "status": "error", "message": f"ipwho.is unavailable: {error}"}


def enrich(report: dict, vt_key: str, abuse_key: str) -> dict:
    # Reputation services receive web indicators only. A mailto link is an
    # email address, not a URL destination, and must not be sent to VirusTotal.
    urls = dict.fromkeys(
        str(link.get("url") or "").strip()
        for link in report.get("links") or []
        if str(link.get("scheme") or "").lower() in {"http", "https"}
        and link.get("actionable") is not False
    )
    report["link_reputation"] = {url: check_url(vt_key, url) for url in urls if url}
    ips = dict.fromkeys(ip for hop in report.get("received_hops") or [] for ip in (hop.get("all_ips") or ([hop.get("sender_ip")] if hop.get("sender_ip") else [])))
    if report.get("injection_sender_ip"): ips[report["injection_sender_ip"]] = None
    report["hop_reputation"] = {ip: check_ip(abuse_key, ip) for ip in ips}
    report["geolocation_results"] = {ip: geolocate(ip) for ip in ips}
    def domain(value: str) -> str:
        match = re.search(r"@([\w.-]+)", value or ""); return match.group(1).lower() if match else ""
    domains = dict.fromkeys(filter(None, (domain(report.get(key) or "") for key in ("from_", "return_path", "reply_to"))))
    # Sender-domain reputation is evaluated as a domain indicator on
    # VirusTotal. Do not infer domain risk from an AbuseIPDB score belonging to
    # a shared hosting/CDN IP, which can create false positives for services
    # such as Google, Microsoft or Spotify.
    report["domain_reputation"] = {
        item: {
            "virustotal": check_vt_domain(vt_key, item),
            "rdap": check_rdap_domain(item),
        }
        for item in domains
    }
    for attachment in report.get("attachments") or []:
        if attachment.get("hash_sha256"):
            attachment["file_reputation"] = check_file(vt_key, attachment["hash_sha256"])
    return report
