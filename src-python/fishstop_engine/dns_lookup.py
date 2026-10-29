"""Bounded DNS transport with an HTTPS fallback for unreachable resolvers."""
import os
import time

import dns.exception
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
from dns.rdtypes.ANY.TXT import TXT
import requests

from fishstop_engine.domain_utils import normalize_hostname, public_suffix


def resolve_records(name: str, kind: str, *, lifetime: float = 2):
    deadline = time.monotonic() + lifetime
    try:
        return list(dns.resolver.resolve(name, kind, lifetime=min(.7, lifetime)))
    except (dns.exception.Timeout, dns.resolver.NoNameservers):
        disabled = set(os.getenv("FISHSTOP_DISABLED_PROVIDERS", "").split(","))
        host = normalize_hostname(name)
        suffix = public_suffix(host)
        if ("local_only" in disabled or os.getenv("FISHSTOP_DNS_HTTPS_FALLBACK", "1") == "0"
                or not suffix or suffix == host):
            raise
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise dns.exception.Timeout
    with requests.Session() as session:
        session.trust_env = False
        with session.get("https://dns.google/resolve", params={"name": name, "type": kind},
                         timeout=remaining, stream=True, allow_redirects=False) as response:
            response.raise_for_status()
            raw = response.raw.read(65537, decode_content=True)
            if len(raw) > 65536:
                raise ValueError("DNS response exceeds the size limit")
            import json
            payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("Invalid DNS response")
    if payload.get("Status") != 0 or payload.get("TC"):
        raise dns.resolver.NoAnswer
    answers = payload.get("Answer") or []
    if not isinstance(answers, list) or any(not isinstance(item, dict) or not isinstance(item.get("data"), str) for item in answers):
        raise ValueError("Invalid DNS answer")
    allowed = {name.rstrip(".").lower()}
    for _ in range(4):
        allowed.update(str(item.get("data") or "").rstrip(".").lower() for item in answers
                       if item.get("type") == 5 and str(item.get("name") or "").rstrip(".").lower() in allowed)
    expected = dns.rdatatype.from_text(kind)
    records = []
    for item in answers[:32]:
        if item.get("type") != expected or str(item.get("name") or "").rstrip(".").lower() not in allowed:
            continue
        data = item["data"]
        if expected == dns.rdatatype.TXT and not data.lstrip().startswith('"'):
            # DNS JSON can carry a decoded TXT value, not DNS presentation
            # syntax: spaces and semicolons must remain part of the record.
            value = data.encode("utf-8")
            records.append(TXT(dns.rdataclass.IN, expected, [value[i:i + 255] for i in range(0, len(value), 255)] or [b""]))
        else:
            records.append(dns.rdata.from_text(dns.rdataclass.IN, expected, data))
    return records
