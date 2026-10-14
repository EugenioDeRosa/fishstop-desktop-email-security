"""Local identity evidence, expiring caches and administrator-confirmed partners.

Message content never writes this registry. Domain control and legal identity are
separate assertions; DNS verification alone cannot assign a company name.
"""
from __future__ import annotations

import json
import os
import secrets
import sqlite3
import time
import unicodedata
import base64
import hashlib
import re
from pathlib import Path
from contextlib import contextmanager

from fishstop_engine.domain_utils import normalize_hostname, registered_domain, is_public_suffix

SCOPES = {"sender", "reply", "visit_link", "open_attachment", "provide_credentials",
          "provide_information", "pay_or_transfer", "verify_account", "change_account_settings", "claim_reward"}


def brand_key(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", str(value)).casefold().split())


@contextmanager
def connection():
    root = os.getenv("FISHSTOP_IDENTITY_DATA_DIR", "")
    if not root:
        raise ValueError("The local identity store is not configured.")
    directory = Path(root)
    directory.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(directory / "identity.sqlite", timeout=5)
    db.execute("CREATE TABLE IF NOT EXISTS evidence (key TEXT PRIMARY KEY, value TEXT NOT NULL, expires REAL NOT NULL)")
    try:
        with db:
            yield db
    finally:
        db.close()


def cached(key: str):
    try:
        with connection() as db:
            row = db.execute("SELECT value FROM evidence WHERE key=? AND expires>?", (key, time.time())).fetchone()
        return json.loads(row[0]) if row else None
    except (OSError, sqlite3.Error, ValueError, TypeError):
        return None


def put(key: str, value, ttl: float):
    try:
        with connection() as db:
            db.execute("DELETE FROM evidence WHERE expires<?", (time.time(),))
            db.execute("INSERT OR REPLACE INTO evidence VALUES (?,?,?)", (key, json.dumps(value), time.time() + ttl))
    except (OSError, sqlite3.Error, ValueError):
        pass


def local_records() -> list[dict]:
    try:
        with connection() as db:
            rows = db.execute("SELECT value FROM evidence WHERE (key LIKE 'partner:%' OR key LIKE 'directory:%') AND expires>?", (time.time(),)).fetchall()
        records = [json.loads(row[0]) for row in rows]
        try:
            key_file = os.getenv("FISHSTOP_IDENTITY_TRUSTED_KEYS", "")
            keys = json.loads(Path(key_file).read_text(encoding="utf-8")) if key_file else {}
        except (OSError, ValueError):
            keys = {}
        return [record for record in records if record.get("source") != "signed_directory" or (
            record.get("key_id") in keys and record.get("key_fingerprint") ==
            hashlib.sha256(base64.b64decode(keys[record["key_id"]], validate=True)).hexdigest())]
    except (OSError, sqlite3.Error, ValueError):
        return []


def resolve_partner(name: str) -> dict | None:
    keys = [brand_key(name)]
    # Resolve generic department/account suffixes after exact names. This is
    # reference matching, never discovery or extraction of an unnamed brand.
    role = r"(?:account|security|support|team|department|billing|payments|assistenza|sicurezza)"
    shortened = re.sub(r"(?:\s+" + role + r"){1,3}$", "", keys[0]).strip()
    if shortened and shortened != keys[0]:
        keys.append(shortened)
    local = local_records()
    catalog_records = []
    catalog = {}
    try:
        catalog = json.loads((Path(__file__).parent / "data" / "identity-catalog.json").read_text(encoding="utf-8"))
        if catalog["verified_at"] <= time.time() < catalog["expires_at"]:
            catalog_records = catalog["records"]
    except (OSError, ValueError, KeyError, TypeError):
        pass
    for key in keys:
        for records, source in [(local, "local"), (catalog_records, "catalog")]:
            matches = [entry for entry in records if key in {brand_key(entry["brand"]), *map(brand_key, entry.get("aliases", []))}]
            if matches:
                if len(matches) != 1:
                    return None
                if source == "local":
                    return matches[0]
                return {**matches[0], "id": "catalog:" + brand_key(matches[0]["brand"]),
                        "source": "maintained_catalog", "verified_at": catalog["verified_at"], "expires_at": catalog["expires_at"]}
    return None


def known_identity_names() -> list[str]:
    """Discovery names only: reading a name never establishes domain ownership."""
    records = local_records()
    try:
        catalog = json.loads((Path(__file__).parent / "data" / "identity-catalog.json").read_text(encoding="utf-8"))
        records += catalog.get("records", [])
    except (OSError, ValueError, TypeError):
        pass
    return sorted({name for record in records for name in [record.get("brand", ""), *record.get("aliases", [])]
                   if isinstance(name, str) and len(name.strip()) >= 2}, key=len, reverse=True)


def domain_value(value: str) -> str:
    value = str(value).strip().lower()
    host = normalize_hostname(value)
    import re
    if len(host) > 253 or not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", host) or is_public_suffix(host) or any(len(label) > 63 or label.startswith("-") or label.endswith("-") for label in host.split(".")):
        raise ValueError("Enter a complete company domain, without an address or URL.")
    import ipaddress
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    raise ValueError("An IP address cannot establish a company identity.")


def relationship_matches(host: str, relation: dict) -> bool:
    host, domain = normalize_hostname(host), relation["domain"]
    return host == domain or (relation["role"] == "official" and host.endswith("." + domain))


def action_authorized(link: dict, relation: dict, action: str) -> bool:
    from urllib.parse import urlparse, unquote
    if action not in relation.get("scopes", []):
        return False
    try:
        url = urlparse(str(link.get("url") or ""))
        if url.scheme != "https" or url.username or url.password or not relationship_matches(url.hostname or "", relation):
            return False
        path = unquote(url.path or "/")
        if any(part in {".", ".."} for part in path.split("/")) or "\\" in path:
            return False
        prefix = relation.get("path_prefix")
        return not prefix or path == prefix or path.startswith(prefix.rstrip("/") + "/")
    except ValueError:
        return False


def validate_relations(relations) -> list[dict]:
    if not isinstance(relations, list) or not 1 <= len(relations) <= 20:
        raise ValueError("Enter between one and twenty domain relationships.")
    clean = []
    for relation in relations:
        domain = domain_value(relation.get("domain", ""))
        role = relation.get("role")
        scopes = list(dict.fromkeys(relation.get("scopes") or []))
        if role not in {"official", "delegate"} or not scopes or not set(scopes) <= SCOPES:
            raise ValueError("Each domain must have an explicit role and permitted activities.")
        prefix = str(relation.get("path_prefix") or "")
        if role == "delegate" and set(scopes) - {"sender", "reply"}:
            if len(prefix) < 2 or not prefix.startswith("/") or any(c in prefix for c in "?#\\") or ".." in prefix:
                raise ValueError("Delegated action services require a specific authorized URL path.")
        clean.append({"domain": domain, "role": role, "scopes": scopes, "path_prefix": prefix})
    if not any(item["role"] == "official" for item in clean):
        raise ValueError("An independently confirmed official domain is required.")
    return clean


def import_directory(bundle: dict) -> dict:
    """Accept only snapshots signed by a separately configured administrator key.

    The bundle cannot supply its own trust anchor. Sequence persists across expiry
    to reject rollback. A snapshot replaces one issuer's records atomically.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    key_file = os.getenv("FISHSTOP_IDENTITY_TRUSTED_KEYS", "")
    if not key_file:
        raise ValueError("No directory signing keys have been configured by the administrator.")
    keys = json.loads(Path(key_file).read_text(encoding="utf-8"))
    payload = bundle["payload"]
    key_id = str(payload["key_id"])
    import re
    if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", key_id):
        raise ValueError("Invalid directory signing key identifier.")
    key_bytes = base64.b64decode(keys[key_id], validate=True)
    key = Ed25519PublicKey.from_public_bytes(key_bytes)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    key.verify(base64.b64decode(bundle["signature"], validate=True), encoded)
    now = time.time()
    issued, expires = float(payload["issued_at"]), float(payload["expires_at"])
    if not now - 90 * 86400 <= issued <= now + 300 or not now < expires <= issued + 90 * 86400:
        raise ValueError("The signed directory is expired or has an invalid validity period.")
    sequence = payload["sequence"]
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise ValueError("The directory sequence is invalid.")
    if not isinstance(payload["records"], list) or len(payload["records"]) > 1000:
        raise ValueError("The directory contains too many records.")
    records = []
    for item in payload["records"]:
        name, reference = str(item["brand"]).strip(), str(item["reference"]).strip()
        if not 2 <= len(name) <= 100 or not 8 <= len(reference) <= 1000:
            raise ValueError("Each directory company requires an independent verification reference.")
        records.append({"id": secrets.token_hex(12), "brand": name, "aliases": item.get("aliases", [])[:10],
                        "relations": validate_relations(item["relations"]), "reference": reference,
                        "source": "signed_directory", "verified_at": issued, "expires_at": expires, "key_id": key_id,
                        "key_fingerprint": hashlib.sha256(key_bytes).hexdigest()})
    with connection() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT value FROM evidence WHERE key=?", ("sequence:" + key_id,)).fetchone()
        if row and sequence <= json.loads(row[0]):
            raise ValueError("The directory sequence has already been imported or is a rollback.")
        db.execute("DELETE FROM evidence WHERE key LIKE ?", ("directory:" + key_id + ":%",))
        for record in records:
            db.execute("INSERT INTO evidence VALUES (?,?,?)", ("directory:" + key_id + ":" + record["id"], json.dumps(record), expires))
        db.execute("INSERT OR REPLACE INTO evidence VALUES (?,?,?)", ("sequence:" + key_id, json.dumps(sequence), now + 100 * 365 * 86400))
    return {"records": local_records()}


def registry_operation(request: dict) -> dict:
    operation = request.get("operation")
    if operation == "list":
        return {"records": local_records()}
    if operation == "import":
        return import_directory(request.get("bundle") or {})
    if operation == "add":
        name = str(request.get("brand") or "").strip()
        reference = str(request.get("reference") or "").strip()
        if request.get("identity_confirmed") is not True or len(reference) < 8:
            raise ValueError("Confirm the company identity independently and record how it was verified.")
        if not 2 <= len(name) <= 100 or len(reference) > 1000:
            raise ValueError("Enter a company name and a short verification reference.")
        clean = validate_relations(request.get("relations"))
        now = time.time()
        days = int(request.get("valid_days", 90))
        if not 1 <= days <= 365:
            raise ValueError("Verification must expire within 365 days.")
        record = {"id": secrets.token_hex(12), "brand": name,
                  "aliases": [str(alias).strip() for alias in request.get("aliases", [])[:10] if str(alias).strip()],
                  "relations": clean, "source": "administrator_confirmation", "reference": reference,
                  "verified_at": now, "expires_at": now + days * 86400}
        # A local administrator can replace a previous assertion, never email content.
        with connection() as db:
            for entry in local_records():
                if brand_key(entry["brand"]) == brand_key(name):
                    db.execute("DELETE FROM evidence WHERE key=?", ("partner:" + entry["id"],))
            db.execute("INSERT INTO evidence VALUES (?,?,?)", ("partner:" + record["id"], json.dumps(record), record["expires_at"]))
        return {"records": local_records()}
    if operation == "remove":
        with connection() as db:
            db.execute("DELETE FROM evidence WHERE key=?", ("partner:" + str(request.get("id") or ""),))
        return {"records": local_records()}
    if operation == "challenge":
        domain = domain_value(request.get("domain", ""))
        token = "fishstop-verification=" + secrets.token_urlsafe(32)
        put("challenge:" + domain, token, 86400)
        return {"domain": domain, "record_name": "_fishstop-verification." + domain, "record_value": token}
    if operation == "verify-control":
        domain = domain_value(request.get("domain", ""))
        token = cached("challenge:" + domain)
        if not token:
            raise ValueError("Create a new domain verification challenge first.")
        import dns.resolver
        answer = dns.resolver.resolve("_fishstop-verification." + domain, "TXT", lifetime=3)
        verified = any(b"".join(item.strings).decode("utf-8", "replace") == token for item in answer)
        if verified:
            put("control:" + domain, {"verified_at": time.time(), "method": "dns_txt_challenge"}, 90 * 86400)
        return {"domain": domain, "control_verified": verified,
                "message": "Domain control confirmed; company identity still requires independent confirmation." if verified else "The verification record was not found."}
    raise ValueError("Unsupported identity registry operation.")
