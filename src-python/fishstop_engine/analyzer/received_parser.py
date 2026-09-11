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

_AUTH_PROPERTY_RE = re.compile(
    r"\b((?:header|smtp|policy)\.[a-zA-Z0-9_-]+|client-ip|envelope-from|helo)"
    r"\s*=\s*([^\s;]+)",
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


def _auth_identity_domain(value: str) -> str:
    """Normalize an SPF identity so the same envelope domain can be compared."""
    identity = str(value or "").strip().strip("<>\"'").lower().rstrip(".")
    if "@" in identity:
        identity = identity.rsplit("@", 1)[-1]
    return identity


def _authserv_id(raw: str, *, arc: bool = False) -> str:
    """Extract the RFC 8601 authentication service identifier."""
    parts = [part.strip() for part in str(raw or "").split(";")]
    position = 1 if arc and parts and re.fullmatch(r"i\s*=\s*\d+", parts[0], re.I) else 0
    if position >= len(parts):
        return ""
    candidate = re.sub(r"\([^)]*\)", "", parts[position]).strip()
    token = candidate.split()[0].strip("<>\"'") if candidate else ""
    return token if token and "=" not in token else ""


def _arc_instance(raw: str) -> int:
    match = re.search(r"(?:^|;)\s*i\s*=\s*(\d+)\b", str(raw), re.IGNORECASE)
    return int(match.group(1)) if match else 0


def _auth_result_items(raw: str) -> List[Dict[str, Any]]:
    """Return every authentication method result without flattening headers."""
    items: List[Dict[str, Any]] = []
    matches = list(_AUTH_FIELD_RE.finditer(str(raw or "")))
    for index, match in enumerate(matches):
        next_start = matches[index + 1].start() if index + 1 < len(matches) else len(raw)
        segment = str(raw)[match.start():next_start].strip(" ;\n\t")
        properties = {
            property_match.group(1).lower(): property_match.group(2).strip("<>\"'")
            for property_match in _AUTH_PROPERTY_RE.finditer(segment)
        }
        protocol = match.group(1).upper()
        identity_keys = {
            "SPF": ("smtp.mailfrom", "smtp.helo", "envelope-from", "helo"),
            "DKIM": ("header.d", "header.i"),
            "DMARC": ("header.from",),
        }.get(protocol, ())
        identity = next((properties[key] for key in identity_keys if properties.get(key)), "")
        client_ip = (
            properties.get("client-ip")
            or properties.get("smtp.remote-ip")
            or properties.get("policy.iprev")
            or ""
        )
        try:
            client_ip = str(ipaddress.ip_address(client_ip.strip("[]"))) if client_ip else ""
        except ValueError:
            client_ip = ""
        items.append({
            "protocol": protocol,
            "status": match.group(2).lower(),
            "identity": identity,
            "client_ip": client_ip,
            "properties": properties,
            "raw": segment,
        })
    return items


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

    for parsed in _auth_result_items(raw):
        proto = str(parsed.pop("protocol"))
        grouped.setdefault(proto, []).append(parsed)
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
        properties = {
            property_match.group(1).lower(): property_match.group(2).strip("<>\"'")
            for property_match in _AUTH_PROPERTY_RE.finditer(str(raw))
        }
        client_ip = properties.get("client-ip", "")
        try:
            client_ip = str(ipaddress.ip_address(client_ip.strip("[]"))) if client_ip else ""
        except ValueError:
            client_ip = ""
        items.append({
            "status": match.group(1).lower(),
            "identity": properties.get("envelope-from", ""),
            "client_ip": client_ip,
            "properties": properties,
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


def select_effective_auth_results(
    authentication_headers: List[str],
    arc_authentication_headers: List[str],
    received_spf_headers: List[str],
) -> Dict[str, Dict[str, Any]]:
    """Select authentication results without losing the original SPF check.

    Header order is significant: a receiving service prepends its own
    ``Authentication-Results`` field, while ARC instances describe earlier
    stages of the route.  Combining every stage and choosing the most adverse
    status turns an historical ``none`` into a false failure. DKIM and DMARC
    therefore retain the final receiver's result. SPF is different because it
    authenticates the client IP at each SMTP hop: when a valid-looking ARC
    chain is available, the earliest ARC assessment is the primary SPF result
    and the final receiver's relay result is retained as delivery metadata.

    This establishes precedence, not cryptographic trust in arbitrary header
    text; the UI continues to present the raw evidence for inspection.
    """
    selected: Dict[str, Dict[str, Any]] = {}

    def add_missing(parsed: Dict[str, Dict[str, Any]], source: str) -> None:
        for proto, result in (parsed or {}).items():
            key = proto.upper()
            if key in selected:
                continue
            enriched = dict(result)
            enriched["source"] = source
            selected[key] = enriched

    # RFC 5322 preserves field order. The first direct Authentication-Results
    # header is the one closest to the recipient represented by this export.
    for raw in authentication_headers or []:
        add_missing(parse_auth_results(str(raw)), "Authentication-Results")

    # ARC sets grow monotonically; the highest instance is the newest sealed
    # account of the preceding route and is only a fallback for missing direct
    # receiver results.
    ordered_arc_headers = sorted(
        (str(value) for value in (arc_authentication_headers or [])),
        key=_arc_instance,
        reverse=True,
    )
    for raw in ordered_arc_headers:
        add_missing(parse_auth_results(raw), "ARC-Authentication-Results")

    add_missing(parse_received_spf_results(received_spf_headers), "Received-SPF")

    # SPF is evaluated independently at every SMTP boundary. A forwarder can
    # therefore pass SPF at the final receiver even though the original source
    # failed it. If the newest ARC custodian reports a passing ARC chain, make
    # the earliest preserved result primary and retain the delivery result.
    delivery_spf = selected.get("SPF")
    newest_arc = ordered_arc_headers[0] if ordered_arc_headers else ""
    arc_chain_passed = bool(re.search(r"\barc\s*=\s*pass\b", newest_arc, re.IGNORECASE))
    if arc_chain_passed:
        origin_spf = None
        origin_instance = 0
        for raw in sorted(ordered_arc_headers, key=_arc_instance):
            if _arc_instance(raw) <= 0:
                continue
            candidate = (parse_auth_results(raw) or {}).get("SPF")
            if candidate:
                origin_spf = candidate
                origin_instance = _arc_instance(raw)
                break

        if origin_spf:
            origin = {
                key: value for key, value in origin_spf.items()
                if key != "all_results"
            }
            origin_status = str(origin.get("status") or "unknown").lower()
            result = {
                **origin,
                "status": origin_status,
                "source": f"ARC-Authentication-Results i={origin_instance} (sender boundary)",
                "origin_status": origin_status,
                "origin_identity": origin.get("identity") or "",
                "origin_source": f"ARC-Authentication-Results i={origin_instance}",
                "origin_raw": origin.get("raw") or "",
                "sender_boundary_selected": True,
            }
            if delivery_spf:
                delivery = {
                    key: value for key, value in delivery_spf.items()
                    if key != "all_results"
                }
                delivery_status = str(delivery.get("status") or "unknown").lower()
                result.update({
                    "raw": (
                        f"Sender boundary i={origin_instance} ({origin_status}): "
                        f"{origin.get('raw') or ''}\n"
                        f"Final receiver ({delivery_status}): {delivery.get('raw') or ''}"
                    ).strip(),
                    "delivery_status": delivery_status,
                    "delivery_identity": delivery.get("identity") or "",
                    "delivery_source": delivery.get("source") or "Authentication-Results",
                    "path_conflict": delivery_status != origin_status,
                    "same_envelope_domain": (
                        bool(_auth_identity_domain(origin.get("identity") or ""))
                        and _auth_identity_domain(origin.get("identity") or "")
                        == _auth_identity_domain(delivery.get("identity") or "")
                    ),
                    "all_results": [origin, delivery],
                })
            else:
                result["all_results"] = [origin]
            selected["SPF"] = result
    return selected


def build_authentication_checkpoints(
    authentication_headers: List[str],
    arc_authentication_headers: List[str],
    received_spf_headers: List[str],
    received_hops: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Preserve authentication observations and link only exact hop evidence.

    A checkpoint says where a result was *reported*. It does not claim that
    the geographic location caused the result. SPF can be linked by its
    explicit client IP; DKIM and DMARC require an exact authserv-id/by-host
    match. Ambiguous observations remain intentionally unlinked.
    """
    route_hops = order_received_hops(received_hops)

    def matching_hop_indices(*, client_ip: str = "", authserv_id: str = "") -> tuple[List[int], str]:
        normalized_authserv = _clean_host_token(authserv_id)
        if client_ip:
            ip_matches = [
                index for index, hop in enumerate(route_hops)
                if client_ip == (
                    hop.get("sender_ip")
                    or ((hop.get("all_ips") or [""])[0] if len(hop.get("all_ips") or []) == 1 else "")
                )
            ]
            if len(ip_matches) == 1:
                return ip_matches, "client-ip"
        if normalized_authserv:
            host_matches = [
                index for index, hop in enumerate(route_hops)
                if (_clean_host_token(hop.get("by_host")) or "").casefold()
                == normalized_authserv.casefold()
            ]
            if len(host_matches) == 1:
                return host_matches, "authserv-id"
        return [], ""

    checkpoints: List[Dict[str, Any]] = []

    def add_header(raw: str, source: str, source_index: int, *, arc: bool = False) -> None:
        authserv_id = _authserv_id(raw, arc=arc)
        arc_instance = _arc_instance(raw) if arc else 0
        for result_index, result in enumerate(_auth_result_items(raw)):
            protocol = str(result.get("protocol") or "").upper()
            client_ip = str(result.get("client_ip") or "")
            indices, basis = matching_hop_indices(
                client_ip=client_ip if protocol == "SPF" else "",
                authserv_id=authserv_id,
            )
            checkpoints.append({
                "id": f"{source.lower().replace('-', '_')}:{source_index}:{result_index}",
                "protocol": protocol,
                "status": result.get("status") or "unknown",
                "identity": result.get("identity") or "",
                "client_ip": client_ip,
                "authserv_id": authserv_id,
                "source": source,
                "source_index": source_index,
                "arc_instance": arc_instance or None,
                "trust": "receiver_reported" if source == "Authentication-Results" and source_index == 0 else "reported",
                "linked_hop_index": indices[0] if len(indices) == 1 else None,
                "association": "exact" if len(indices) == 1 else "unmapped",
                "link_basis": basis,
                "raw": result.get("raw") or str(raw).strip(),
            })

    for index, raw in enumerate(authentication_headers or []):
        add_header(str(raw), "Authentication-Results", index)
    for index, raw in enumerate(arc_authentication_headers or []):
        add_header(str(raw), "ARC-Authentication-Results", index, arc=True)
    for index, raw in enumerate(received_spf_headers or []):
        text = str(raw)
        match = re.match(r"\s*([a-zA-Z0-9_-]+)", text)
        if not match:
            continue
        properties = {
            property_match.group(1).lower(): property_match.group(2).strip("<>\"'")
            for property_match in _AUTH_PROPERTY_RE.finditer(text)
        }
        client_ip = properties.get("client-ip", "")
        try:
            client_ip = str(ipaddress.ip_address(client_ip.strip("[]"))) if client_ip else ""
        except ValueError:
            client_ip = ""
        indices, basis = matching_hop_indices(client_ip=client_ip)
        checkpoints.append({
            "id": f"received_spf:{index}:0",
            "protocol": "SPF",
            "status": match.group(1).lower(),
            "identity": properties.get("envelope-from", ""),
            "client_ip": client_ip,
            "authserv_id": "",
            "source": "Received-SPF",
            "source_index": index,
            "arc_instance": None,
            "trust": "reported",
            "linked_hop_index": indices[0] if len(indices) == 1 else None,
            "association": "exact" if len(indices) == 1 else "unmapped",
            "link_basis": basis,
            "raw": text.strip(),
        })
    return checkpoints
