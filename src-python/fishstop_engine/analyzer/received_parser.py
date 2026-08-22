"""
analyzer/received_parser.py - Parsing degli header di routing email (Enterprise Level).

Espone:
  - parse_received_hop(raw)    : dizionario strutturato per un singolo hop Received
  - parse_auth_results(raw)    : dizionario SPF/DKIM/DMARC da Authentication-Results
"""

import ipaddress
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Optional

# ── Regex Enterprise-Grade ──────────────────────────────────────────────────

# Estrae potenziali candidati IP (stringhe di caratteri esadecimali, due punti e punti)
# La validazione formale ed enterprise viene delegata al modulo 'ipaddress'
_IP_CANDIDATE_RE = re.compile(r"\[?([0-9a-fA-F:.]+)\]?")

_BY_RE = re.compile(r"\bby\s+(\[[^\]]+\]|[^\s;()]+)", re.IGNORECASE)
_FROM_RE = re.compile(r"\bfrom\s+(\[[^\]]+\]|[^\s;()]+)\s*(?:\(([^)]*)\))?", re.IGNORECASE)
_FOR_RE = re.compile(r"\bfor\s+<([^>]+)>", re.IGNORECASE)

# More tolerant TLS regex for modern standards (including TLSv1.3 and extended formats)
_TLS_RE = re.compile(
    r"(?:version=)?(TLSv?[\d.]+)\s+(?:cipher|version)=([\w\-]+)", re.IGNORECASE
)

# Authentication-Results standard RFC 8601
_AUTH_FIELD_RE = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z0-9_-]+)",
    re.IGNORECASE,
)

_AUTH_IDENTITY_RE = re.compile(
    r"\b(?:header|smtp)\.[a-zA-Z0-9_-]+\s*=\s*([^\s;]+)",
    re.IGNORECASE,
)

# Authentication results are not boolean: a message can contain multiple
# results for the same protocol, possibly produced at different hops.  When a
# compact status is required, retain the most adverse result instead of the
# last one encountered in the header text.
_AUTH_STATUS_PRIORITY = {
    "fail": 100,
    "permerror": 95,
    "temperror": 90,
    "softfail": 85,
    "policy": 80,
    "neutral": 70,
    "none": 60,
    "unknown": 50,
    "bestguesspass": 10,
    "pass": 0,
}


def _auth_priority(result: Dict[str, Any]) -> int:
    return _AUTH_STATUS_PRIORITY.get(str(result.get("status") or "unknown").lower(), 50)


def _select_worst_auth_result(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    selected = dict(max(items, key=_auth_priority))
    selected["all_results"] = [dict(item) for item in items]
    return selected


# ── Funzioni di Utility Internizzate ─────────────────────────────────────────


def _extract_valid_ips(text: str) -> List[str]:
    """
    Finds all IP candidates in the text and returns only those that pass
    la validazione rigorosa del modulo ipaddress di Python, rimuovendo i duplicati.
    """
    valid_ips: Dict[str, bool] = {}
    # Pulizia preliminare per evitare falsi positivi con caratteri di punteggiatura attigui
    cleaned_text = text.replace("(", " ").replace(")", " ").replace(";", " ")

    for match in _IP_CANDIDATE_RE.finditer(cleaned_text):
        candidate = match.group(1).strip(".")
        # Rimuove eventuali prefissi comuni negli header email (es. "IPv6:")
        if candidate.lower().startswith("ipv6:"):
            candidate = candidate[5:]

        try:
            # Sfrutta il parsing nativo C-level di Python (valida sia IPv4 che IPv6)
            ip_obj = ipaddress.ip_address(candidate)
            valid_ips[str(ip_obj)] = True
        except ValueError:
            continue

    return list(valid_ips.keys())


def _is_global_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip.strip("[]")).is_global
    except ValueError:
        return False


def _preferred_sender_ip(*ip_groups: List[str]) -> Optional[str]:
    ips = [ip for group in ip_groups for ip in group]
    for ip in ips:
        if _is_global_ip(ip):
            return ip
    return ips[0] if ips else None


def _clean_host_token(value: str | None) -> Optional[str]:
    if not value:
        return None
    value = value.strip().strip("[]")
    if "%" in value:
        value = value.split("%", 1)[0]
    return value.rstrip(".,;") or None


def _received_timestamp(raw: str) -> Optional[str]:
    """Extract and normalize the RFC date after the final Received semicolon."""
    if ";" not in (raw or ""):
        return None
    raw_date = raw.rsplit(";", 1)[-1].strip()
    if not raw_date:
        return None
    try:
        parsed = parsedate_to_datetime(raw_date)
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def order_received_hops(hops: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return sender-to-recipient hops, preferring timestamps when all are valid."""
    current_route_order = list(reversed(hops or []))
    if len(current_route_order) < 2:
        return current_route_order

    timestamps: List[float] = []
    for hop in current_route_order:
        value = hop.get("received_at")
        if not value:
            return current_route_order
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            timestamps.append(parsed.astimezone(timezone.utc).timestamp())
        except (TypeError, ValueError, OverflowError):
            return current_route_order

    return [
        hop
        for _, hop in sorted(
            zip(timestamps, current_route_order),
            key=lambda item: item[0],
        )
    ]


# ── Funzioni Principali Esposte ──────────────────────────────────────────────


def parse_received_hop(raw: str) -> Dict[str, Any]:
    """
    Parsa un singolo header Received in modo sicuro ed enterprise.
    Garantisce l'assenza di crash anche su stringhe RFC-non-compliant.
    """
    if not raw:
        return {
            "raw": "",
            "from_host": None,
            "sender_ip": None,
            "sender_domain": None,
            "by_host": None,
            "for_address": None,
            "tls_version": None,
            "tls_cipher": None,
            "all_ips": [],
            "received_at": None,
        }

    hop: Dict[str, Any] = {
        "raw": raw.strip(),
        "received_at": _received_timestamp(raw),
    }
    clean_raw = " ".join(raw.split())

    # Estrazione di tutti gli IP validi presenti nell'header
    all_ips = _extract_valid_ips(clean_raw)
    hop["all_ips"] = all_ips

    # Parsing della sezione 'FROM'
    m_from = _FROM_RE.search(clean_raw)
    if m_from:
        hop["from_host"] = _clean_host_token(m_from.group(1))
        parenthetical = m_from.group(2) or ""

        # Cerca prima l'IP dentro la parentesi (comportamento standard MTA)
        parenthesis_ips = _extract_valid_ips(parenthetical)
        hop["sender_ip"] = _preferred_sender_ip(parenthesis_ips, all_ips)

        # Identificazione del sender_domain dichiarato (eshewing IP/helo-name)
        parts = [p.strip("()[]:,") for p in parenthetical.split() if p.strip("()[]:,")]
        if parts:
            first_part = parts[0]
            # If the first part is not a valid IP, treat it as the declared domain
            try:
                ipaddress.ip_address(first_part.lower().replace("ipv6:", ""))
                hop["sender_domain"] = None
            except ValueError:
                hop["sender_domain"] = first_part
        else:
            hop["sender_domain"] = None
    else:
        hop["from_host"] = None
        hop["sender_ip"] = _preferred_sender_ip(all_ips)
        hop["sender_domain"] = None

    # Parsing della sezione 'BY'
    m_by = _BY_RE.search(clean_raw)
    hop["by_host"] = _clean_host_token(m_by.group(1)) if m_by else None

    # Parsing della sezione 'FOR'
    m_for = _FOR_RE.search(clean_raw)
    hop["for_address"] = m_for.group(1) if m_for else None

    # Parsing dei dati TLS
    m_tls = _TLS_RE.search(clean_raw)
    if m_tls:
        hop["tls_version"] = m_tls.group(1)
        hop["tls_cipher"] = m_tls.group(2)
    else:
        hop["tls_version"] = None
        hop["tls_cipher"] = None

    return hop


def parse_auth_results(raw: str) -> Dict[str, Dict[str, Any]]:
    """
    Parsa l'header Authentication-Results normalizzando i risultati
    secondo lo standard RFC 8601.
    """
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    if not raw:
        return {}

    matches = list(_AUTH_FIELD_RE.finditer(raw))
    for index, m in enumerate(matches):
        proto = m.group(1).upper()
        status = m.group(2).lower()
        next_start = matches[index + 1].start() if index + 1 < len(matches) else len(raw)
        segment = raw[m.start():next_start].strip(" ;\n\t")
        identity_match = _AUTH_IDENTITY_RE.search(segment)
        identity = identity_match.group(1) if identity_match else ""

        grouped.setdefault(proto, []).append({
            "status": status,
            "identity": identity.strip("<>\"'"),
            "raw": segment,
        })
    return {
        proto: _select_worst_auth_result(items)
        for proto, items in grouped.items()
    }


def parse_received_spf_results(headers: List[str]) -> Dict[str, Dict[str, Any]]:
    """Parse every Received-SPF header and retain the most adverse result."""
    items: List[Dict[str, Any]] = []
    for raw in headers or []:
        match = re.match(r"\s*([a-zA-Z0-9_-]+)", str(raw))
        if not match:
            continue
        items.append({
            "status": match.group(1).lower(),
            "identity": "",
            "raw": str(raw).strip(),
        })
    return {"SPF": _select_worst_auth_result(items)} if items else {}


def merge_auth_results(
    *sources: tuple[str, Dict[str, Dict[str, Any]]],
) -> Dict[str, Dict[str, Any]]:
    """Merge parsed auth sources, selecting the most adverse result per protocol."""
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for source_name, parsed in sources:
        for proto, result in (parsed or {}).items():
            result_items = result.get("all_results") or [result]
            for item in result_items:
                enriched = {key: value for key, value in item.items() if key != "all_results"}
                enriched["source"] = source_name
                grouped.setdefault(proto.upper(), []).append(enriched)
    return {
        proto: _select_worst_auth_result(items)
        for proto, items in grouped.items()
    }
