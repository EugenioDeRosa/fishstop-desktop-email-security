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
        return {**base, "message": "VirusTotal non configurato: inserisci il token nelle Impostazioni."}
    if requests is None: return {**base, "message": "Verifica reputazione non disponibile: installa requests."}
    identifier = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    try:
        response = requests.get(f"{VT}/urls/{identifier}", headers={"x-apikey": api_key}, timeout=10)
        if response.status_code == 404: return {**base, "status": "not_found", "message": "URL non trovato su VirusTotal"}
        if response.status_code == 401: return {**base, "status": "error", "message": "Token VirusTotal non valido"}
        if response.status_code == 429: return {**base, "status": "error", "message": "Rate limit VirusTotal superato"}
        response.raise_for_status()
        payload = response.json()
        result = _vt_status(payload, base)
        object_id = str((payload.get("data") or {}).get("id") or "")
        return {**result, "permalink": f"https://www.virustotal.com/gui/url/{object_id}" if object_id else "https://www.virustotal.com/gui/home/url"}
    except requests.RequestException as error:
        return {**base, "status": "error", "message": f"VirusTotal non disponibile: {error}"}


def check_file(api_key: str, sha256: str) -> dict:
    base = {"sha256": sha256, "status": "skipped", "malicious": 0, "suspicious": 0, "total_engines": 0, "detection_ratio": "-"}
    if not api_key: return {**base, "message": "VirusTotal non configurato: inserisci il token nelle Impostazioni."}
    if requests is None: return {**base, "message": "Verifica reputazione non disponibile: installa requests."}
    try:
        response = requests.get(f"{VT}/files/{sha256}", headers={"x-apikey": api_key}, timeout=10)
        if response.status_code == 404: return {**base, "status": "not_found", "message": "Hash non trovato su VirusTotal"}
        if response.status_code == 401: return {**base, "status": "error", "message": "Token VirusTotal non valido"}
        if response.status_code == 429: return {**base, "status": "error", "message": "Rate limit VirusTotal superato"}
        response.raise_for_status(); result = _vt_status(response.json(), base)
        attrs = (response.json().get("data") or {}).get("attributes", {}); ptc = attrs.get("popular_threat_classification") or {}
        return {**result, "threat_label": ptc.get("suggested_threat_label", ""), "file_type": attrs.get("type_description", ""), "file_name": (attrs.get("names") or [""])[0], "permalink": f"https://www.virustotal.com/gui/file/{sha256}"}
    except requests.RequestException as error:
        return {**base, "status": "error", "message": f"VirusTotal non disponibile: {error}"}


def check_ip(api_key: str, ip: str) -> dict:
    base = {"ip": ip, "status": "skipped", "abuseConfidenceScore": 0, "totalReports": 0}
    try:
        if not ipaddress.ip_address(ip.strip("[]")).is_global: return {**base, "message": "IP non pubblico: controllo saltato"}
    except ValueError: return {**base, "message": "IP non valido"}
    if not api_key: return {**base, "message": "AbuseIPDB non configurato: inserisci il token nelle Impostazioni."}
    if requests is None: return {**base, "message": "Verifica reputazione non disponibile: installa requests."}
    try:
        response = requests.get(ABUSE, params={"ipAddress": ip, "maxAgeInDays": "90"}, headers={"Key": api_key, "Accept": "application/json"}, timeout=6)
        if response.status_code == 401: return {**base, "status": "error", "message": "Token AbuseIPDB non valido"}
        if response.status_code == 429: return {**base, "status": "error", "message": "Rate limit AbuseIPDB superato"}
        response.raise_for_status(); data = response.json().get("data", {})
        return {**base, "status": "ok", "abuseConfidenceScore": int(data.get("abuseConfidenceScore") or 0), "totalReports": int(data.get("totalReports") or 0), "countryCode": data.get("countryCode") or "", "isp": data.get("isp") or "", "url": f"https://www.abuseipdb.com/check/{ip}"}
    except requests.RequestException as error:
        return {**base, "status": "error", "message": f"AbuseIPDB non disponibile: {error}"}


def check_domain(api_key: str, domain: str) -> dict:
    base = {"domain_queried": domain, "resolved_ip": "", "status": "skipped"}
    if not api_key: return {**base, "message": "AbuseIPDB non configurato: inserisci il token nelle Impostazioni."}
    try: ip = socket.gethostbyname(domain)
    except OSError as error: return {**base, "message": f"Risoluzione dominio non riuscita: {error}"}
    return {**check_ip(api_key, ip), "domain_queried": domain, "resolved_ip": ip, "lookup_method": "system-socket"}


def geolocate(ip: str) -> dict:
    base = {"ip": ip, "status": "skipped", "provider": "ipwho.is"}
    try:
        if not ipaddress.ip_address(ip.strip("[]")).is_global: return {**base, "message": "IP non pubblico"}
    except ValueError: return {**base, "message": "IP non valido"}
    if requests is None: return {**base, "message": "Geolocalizzazione non disponibile: installa requests."}
    try:
        data = requests.get(f"https://ipwho.is/{ip}", timeout=5).json()
        if not data.get("success", False): return {**base, "message": str(data.get("message") or "Risposta non valida")}
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
    except requests.RequestException as error: return {**base, "status": "error", "message": f"ipwho.is non disponibile: {error}"}


def enrich(report: dict, vt_key: str, abuse_key: str) -> dict:
    urls = dict.fromkeys(str(link.get("url") or "").strip() for link in report.get("links") or [])
    report["link_reputation"] = {url: check_url(vt_key, url) for url in urls if url}
    ips = dict.fromkeys(ip for hop in report.get("received_hops") or [] for ip in (hop.get("all_ips") or ([hop.get("sender_ip")] if hop.get("sender_ip") else [])))
    if report.get("injection_sender_ip"): ips[report["injection_sender_ip"]] = None
    report["hop_reputation"] = {ip: check_ip(abuse_key, ip) for ip in ips}
    report["geolocation_results"] = {ip: geolocate(ip) for ip in ips}
    def domain(value: str) -> str:
        match = re.search(r"@([\w.-]+)", value or ""); return match.group(1).lower() if match else ""
    domains = dict.fromkeys(filter(None, (domain(report.get(key) or "") for key in ("from_", "return_path", "reply_to"))))
    report["domain_reputation"] = {item: check_domain(abuse_key, item) for item in domains}
    for attachment in report.get("attachments") or []:
        if attachment.get("hash_sha256"):
            attachment["file_reputation"] = check_file(vt_key, attachment["hash_sha256"])
    return report
