"""Background OTX Pulse synchronization and local IOC matching.

The analysis path never calls OTX. A separate command incrementally downloads
subscribed Pulses plus all public Pulses tagged ``phishing`` that were modified
within the configured retention window. Indicators are stored in an indexed
SQLite database and email analysis performs only point lookups.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.utils import getaddresses
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shutil
import sqlite3
import time
from typing import Callable
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from fishstop_engine.domain_utils import normalize_hostname, registered_domain

try:
    import requests
except ImportError:  # The static engine remains usable without online sync.
    requests = None


OTX_BASE_URL = "https://otx.alienvault.com"
OTX_SUBSCRIBED_PULSES = f"{OTX_BASE_URL}/api/v1/pulses/subscribed"
OTX_SEARCH_PULSES = f"{OTX_BASE_URL}/api/v1/search/pulses"
OTX_PULSE_DETAILS = f"{OTX_BASE_URL}/api/v1/pulses"
PUBLIC_PHISHING_QUERY = 'tag:"phishing"'
PAGE_SIZE = 50
INDICATOR_PAGE_SIZE = 10_000
MAX_PULSES_PER_INDICATOR = 5
INITIAL_LOOKBACK_DAYS = 365
INCREMENTAL_OVERLAP_DAYS = 1
PUBLIC_INCREMENTAL_OVERLAP_DAYS = 3
REQUEST_TIMEOUT = (5, 30)
REQUEST_ATTEMPTS = 3
DETAIL_TIMEOUT = (5, 25)
DETAIL_ATTEMPTS = 2
PUBLIC_PREFETCH_TIMEOUT = (5, 15)
PUBLIC_PREFETCH_WORKERS = 4
MAX_RETRY_DELAY_SECONDS = 5
# Public search is discovery, not a bulk feed. A single Pulse may contain more
# than half a million indicators, so a Pulse count is not a useful safety bound.
PUBLIC_SEARCH_INITIAL_MAX_PAGES = 6
PUBLIC_SEARCH_INCREMENTAL_MAX_PAGES = 2
PUBLIC_SYNC_SOFT_SECONDS = 20 * 60
PUBLIC_INDICATOR_TARGET = 1_000_000
PUBLIC_DATABASE_TARGET_BYTES = 250 * 1024 * 1024
PUBLIC_DATABASE_HARD_BYTES = 300 * 1024 * 1024
PUBLIC_COMMUNITY_PULSE_MAX_INDICATORS = 50_000
PUBLIC_TRUSTED_PULSE_MAX_INDICATORS = 300_000
PUBLIC_TRUSTED_AUTHORS = frozenset({"alienvault", "phishdestroy", "urlert_intel"})

_TYPE_ALIASES = {
    "domain": "domain",
    "hostname": "hostname",
    "url": "url",
    "uri": "url",
    "ipv4": "ipv4",
    "ipv6": "ipv6",
    "filehash-sha256": "sha256",
    "email": "email",
}


class OtxTransientError(RuntimeError):
    """OTX was reachable but a bounded request could not complete."""


class OtxAuthenticationError(RuntimeError):
    """The configured OTX credential was rejected."""


class OtxBudgetReached(RuntimeError):
    """A successful partial refresh reached its local safety budget."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _otx_datetime(value: object) -> datetime | None:
    """Parse OTX timestamps as UTC, including legacy values without an offset."""
    candidate = str(value or "").strip()
    if not candidate:
        return None
    try:
        parsed = datetime.fromisoformat(
            f"{candidate[:-1]}+00:00" if candidate[-1:].lower() == "z" else candidate
        )
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _normalized_url(value: str) -> str:
    value = re.sub(r"^hxxps://", "https://", value.strip(), flags=re.IGNORECASE)
    value = re.sub(r"^hxxp://", "http://", value, flags=re.IGNORECASE)
    value = value.replace("[.]", ".")
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value.strip()
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return value.strip()
    hostname = normalize_hostname(parsed.hostname)
    if not hostname:
        return value.strip()
    try:
        port = parsed.port
    except ValueError:
        port = None
    default_port = (parsed.scheme.lower() == "http" and port == 80) or (
        parsed.scheme.lower() == "https" and port == 443
    )
    try:
        url_hostname = f"[{hostname}]" if ipaddress.ip_address(hostname).version == 6 else hostname
    except ValueError:
        url_hostname = hostname
    host = url_hostname if port is None or default_port else f"{url_hostname}:{port}"
    return urlunsplit((parsed.scheme.lower(), host, parsed.path or "/", parsed.query, ""))


def _normalize_indicator(kind: str, value: str) -> str:
    value = str(value or "").strip().replace("[.]", ".")
    if kind in {"domain", "hostname"}:
        return normalize_hostname(value)
    if kind == "url":
        return _normalized_url(value)
    if kind in {"ipv4", "ipv6"}:
        try:
            return str(ipaddress.ip_address(value.strip("[]")))
        except ValueError:
            return ""
    if kind == "sha256":
        normalized = value.lower()
        return normalized if len(normalized) == 64 and all(character in "0123456789abcdef" for character in normalized) else ""
    if kind == "email":
        _display, address = getaddresses([value])[0] if value else ("", "")
        local, separator, domain = address.rpartition("@")
        normalized_domain = normalize_hostname(domain)
        return f"{local.casefold()}@{normalized_domain}" if separator and local and normalized_domain else ""
    return value


def _indicator_key(kind: str, value: str) -> str:
    normalized = _normalize_indicator(kind, value)
    return f"{kind}:{normalized}" if normalized else ""


def _indicator_variants(kind: str, value: str) -> list[tuple[str, str]]:
    """Normalize an IOC and derive locally useful phishing lookup keys."""
    normalized = _normalize_indicator(kind, value)
    if not normalized:
        return []
    variants = [(kind, normalized)]
    if kind == "url":
        try:
            hostname = normalize_hostname(urlsplit(normalized).hostname or "")
        except ValueError:
            hostname = ""
        if hostname:
            variants.append(("hostname", hostname))
            parent = registered_domain(hostname)
            if parent:
                variants.append(("domain", parent))
    elif kind == "email":
        domain = normalize_hostname(normalized.rpartition("@")[2])
        if domain:
            variants.append(("domain", domain))
    return list(dict.fromkeys(variants))


def _pulse_summary(pulse: dict) -> dict:
    author = pulse.get("author") or {}
    author_name = (
        pulse.get("author_name")
        or (author.get("username") if isinstance(author, dict) else "")
        or "OTX community"
    )
    return {
        "id": str(pulse.get("id") or "")[:64],
        "name": str(pulse.get("name") or "Unnamed OTX Pulse")[:180],
        "author": str(author_name)[:100],
        "modified": str(pulse.get("modified") or pulse.get("created") or "")[:64],
        "tags": [str(tag)[:60] for tag in (pulse.get("tags") or [])[:12]],
        "tlp": str(pulse.get("TLP") or pulse.get("tlp") or "")[:20],
    }


def _active_indicator(indicator: dict) -> bool:
    if indicator.get("is_active") in {False, 0, "0"}:
        return False
    expiration = str(indicator.get("expiration") or "").strip()
    if not expiration:
        return True
    parsed_expiration = _otx_datetime(expiration)
    return parsed_expiration is None or parsed_expiration > _utc_now()


def _safe_next_page(value: object) -> str | None:
    if not value:
        return None
    candidate = str(value)
    if candidate.startswith("/"):
        return f"{OTX_BASE_URL}{candidate}"
    parsed = urlsplit(candidate)
    if parsed.scheme == "https" and parsed.hostname == "otx.alienvault.com":
        return candidate
    raise RuntimeError("OTX returned an unsafe pagination URL.")


def _request_json(
    session,
    url: str,
    *,
    params: dict | None = None,
    timeout: tuple[int, int] = REQUEST_TIMEOUT,
    attempts: int = REQUEST_ATTEMPTS,
) -> dict:
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            response = session.get(url, params=params, timeout=timeout)
            status_code = int(getattr(response, "status_code", 0) or 0)
            if status_code in {401, 403}:
                raise OtxAuthenticationError(
                    "The OTX API key is invalid or not authorized."
                )
            if status_code == 429 or 500 <= status_code < 600:
                if attempt + 1 >= attempts:
                    if status_code == 429:
                        raise OtxTransientError(
                            "OTX rate limit reached after automatic retries. "
                            "The previous local cache was kept."
                        )
                    raise OtxTransientError(
                        f"OTX returned HTTP {status_code} after automatic retries. "
                        "The previous local cache was kept."
                    )
                retry_after = str(
                    getattr(response, "headers", {}).get("Retry-After", "")
                ).strip()
                try:
                    delay = float(retry_after)
                except ValueError:
                    delay = float(2 ** attempt)
                time.sleep(min(MAX_RETRY_DELAY_SECONDS, max(0.5, delay)))
                continue
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise RuntimeError("OTX returned an invalid Pulse response.")
            return payload
        except OtxAuthenticationError:
            raise
        except OtxTransientError:
            raise
        except (requests.Timeout, requests.ConnectionError) as error:
            last_error = error
            if attempt + 1 >= attempts:
                break
            time.sleep(min(MAX_RETRY_DELAY_SECONDS, 2 ** attempt))
    raise OtxTransientError(
        "OTX did not respond after automatic retries. "
        "The previous local cache was kept."
    ) from last_error


def _has_exact_phishing_tag(pulse: dict) -> bool:
    return any(str(tag).strip().casefold() == "phishing" for tag in (pulse.get("tags") or []))


def _may_have_supported_indicators(pulse: dict) -> bool:
    """Skip detail downloads when the search summary proves no useful IOC exists."""
    if isinstance(pulse.get("indicators"), list):
        return True
    counts = pulse.get("indicator_type_counts")
    if not isinstance(counts, dict):
        return True
    for kind, count in counts.items():
        if str(kind).lower() not in _TYPE_ALIASES:
            continue
        try:
            if int(count) > 0:
                return True
        except (TypeError, ValueError):
            return True
    return False


def _recent_pulse(pulse: dict, cutoff: datetime) -> bool:
    modified = _otx_datetime(pulse.get("modified") or pulse.get("created"))
    return modified is None or modified >= cutoff


def _public_pulse_details(session, pulse: dict) -> dict | None:
    if isinstance(pulse.get("indicators"), list):
        return pulse
    pulse_id = str(pulse.get("id") or "")
    if not re.fullmatch(r"[0-9a-fA-F]{24}", pulse_id):
        return None
    try:
        details = _request_json(
            session,
            f"{OTX_PULSE_DETAILS}/{pulse_id}",
            timeout=DETAIL_TIMEOUT,
            attempts=DETAIL_ATTEMPTS,
        )
    except OtxAuthenticationError:
        raise
    except (OtxTransientError, requests.RequestException, RuntimeError):
        # One slow or removed Pulse must not discard the rest of a successful
        # synchronization. Authentication failures still abort immediately.
        return None
    return details if isinstance(details.get("indicators"), list) else None


SCHEMA_VERSION = 3


def _database_connection(path: Path, *, readonly: bool = False) -> sqlite3.Connection:
    if readonly:
        connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True, timeout=5)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(path, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


def _initialize_database(connection: sqlite3.Connection) -> None:
    connection.executescript("""
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS pulses (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            author TEXT NOT NULL,
            modified_at TEXT NOT NULL,
            tags_json TEXT NOT NULL,
            tlp TEXT NOT NULL,
            last_seen_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS pulse_sources (
            pulse_id TEXT NOT NULL REFERENCES pulses(id) ON DELETE CASCADE,
            source TEXT NOT NULL,
            complete INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY (pulse_id, source)
        );
        CREATE TABLE IF NOT EXISTS indicators (
            id INTEGER PRIMARY KEY,
            kind TEXT NOT NULL,
            value TEXT NOT NULL,
            UNIQUE (kind, value)
        );
        CREATE INDEX IF NOT EXISTS idx_indicators_kind_value
            ON indicators(kind, value);
        CREATE TABLE IF NOT EXISTS pulse_indicators (
            pulse_id TEXT NOT NULL REFERENCES pulses(id) ON DELETE CASCADE,
            indicator_id INTEGER NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,
            expiration_at TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (pulse_id, indicator_id)
        );
        CREATE INDEX IF NOT EXISTS idx_pulse_indicators_indicator
            ON pulse_indicators(indicator_id, pulse_id);
    """)
    source_columns = {
        str(row[1]) for row in connection.execute("PRAGMA table_info(pulse_sources)")
    }
    if "complete" not in source_columns:
        connection.execute(
            "ALTER TABLE pulse_sources ADD COLUMN complete INTEGER NOT NULL DEFAULT 1"
        )
    connection.execute(
        "INSERT OR REPLACE INTO metadata(key, value) VALUES('schema_version', ?)",
        (str(SCHEMA_VERSION),),
    )


def _metadata(connection: sqlite3.Connection, key: str) -> str:
    row = connection.execute("SELECT value FROM metadata WHERE key = ?", (key,)).fetchone()
    return str(row[0]) if row else ""


def _set_metadata(connection: sqlite3.Connection, key: str, value: object) -> None:
    connection.execute(
        "INSERT OR REPLACE INTO metadata(key, value) VALUES(?, ?)",
        (key, str(value)),
    )


def _utc_iso(value: object, fallback: datetime) -> str:
    parsed = _otx_datetime(value) or fallback
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _pulse_identity(summary: dict) -> str:
    if summary.get("id"):
        return str(summary["id"])
    stable = f"{summary.get('author', '')}:{summary.get('name', '')}"
    return f"generated:{hashlib.sha256(stable.encode('utf-8')).hexdigest()}"


def _store_pulse(
    connection: sqlite3.Connection,
    pulse: dict,
    source: str,
    synced_at: datetime,
) -> bool:
    indicators = pulse.get("indicators")
    if not isinstance(indicators, list):
        return False
    pulse_id = _store_pulse_summary(
        connection, pulse, source, synced_at, complete=True
    )
    # Complete subscribed or inline Pulses replace their previous membership.
    connection.execute("DELETE FROM pulse_indicators WHERE pulse_id = ?", (pulse_id,))
    _store_indicator_batch(connection, pulse_id, indicators)
    return True


def _store_pulse_summary(
    connection: sqlite3.Connection,
    pulse: dict,
    source: str,
    synced_at: datetime,
    *,
    complete: bool,
) -> str:
    summary = _pulse_summary(pulse)
    pulse_id = _pulse_identity(summary)
    connection.execute(
        """INSERT INTO pulses(id, name, author, modified_at, tags_json, tlp, last_seen_at)
           VALUES(?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET
             name=excluded.name, author=excluded.author,
             modified_at=excluded.modified_at, tags_json=excluded.tags_json,
             tlp=excluded.tlp, last_seen_at=excluded.last_seen_at""",
        (
            pulse_id,
            summary["name"],
            summary["author"],
            _utc_iso(summary["modified"], synced_at),
            json.dumps(summary["tags"], ensure_ascii=False, separators=(",", ":")),
            summary["tlp"],
            _utc_iso(synced_at, synced_at),
        ),
    )
    connection.execute(
        """INSERT INTO pulse_sources(pulse_id, source, complete) VALUES(?, ?, ?)
           ON CONFLICT(pulse_id, source) DO UPDATE SET complete=excluded.complete""",
        (pulse_id, source, int(complete)),
    )
    return pulse_id


def _store_indicator_batch(
    connection: sqlite3.Connection,
    pulse_id: str,
    indicators: list,
) -> int:
    prepared: dict[tuple[str, str], str] = {}
    for indicator in indicators:
        if not isinstance(indicator, dict) or not _active_indicator(indicator):
            continue
        kind = _TYPE_ALIASES.get(str(indicator.get("type") or "").lower())
        if not kind:
            continue
        expiration = _otx_datetime(indicator.get("expiration"))
        expiration_at = _utc_iso(expiration, expiration) if expiration else ""
        for normalized_kind, value in _indicator_variants(
            kind, str(indicator.get("indicator") or "")
        ):
            prepared[(normalized_kind, value)] = expiration_at
    if not prepared:
        return 0
    connection.execute(
        """CREATE TEMP TABLE IF NOT EXISTS otx_indicator_batch (
               kind TEXT NOT NULL,
               value TEXT NOT NULL,
               expiration_at TEXT NOT NULL,
               PRIMARY KEY(kind, value)
           ) WITHOUT ROWID"""
    )
    connection.execute("DELETE FROM otx_indicator_batch")
    connection.executemany(
        "INSERT INTO otx_indicator_batch(kind, value, expiration_at) VALUES(?, ?, ?)",
        ((kind, value, expiration) for (kind, value), expiration in prepared.items()),
    )
    connection.execute(
        """INSERT OR IGNORE INTO indicators(kind, value)
           SELECT kind, value FROM otx_indicator_batch"""
    )
    connection.execute(
        """INSERT INTO pulse_indicators(pulse_id, indicator_id, expiration_at)
           SELECT ?, i.id, b.expiration_at
           FROM otx_indicator_batch b
           JOIN indicators i ON i.kind = b.kind AND i.value = b.value
           WHERE 1
           ON CONFLICT(pulse_id, indicator_id) DO UPDATE SET
             expiration_at=excluded.expiration_at""",
        (pulse_id,),
    )
    return len(prepared)


def _database_counts(connection: sqlite3.Connection) -> dict:
    pulse_count = int(connection.execute("SELECT COUNT(*) FROM pulses").fetchone()[0])
    indicator_count = int(connection.execute("SELECT COUNT(*) FROM indicators").fetchone()[0])
    subscribed = int(connection.execute(
        "SELECT COUNT(*) FROM pulse_sources WHERE source = 'subscribed'"
    ).fetchone()[0])
    public = int(connection.execute(
        "SELECT COUNT(*) FROM pulse_sources WHERE source = 'public_phishing'"
    ).fetchone()[0])
    return {
        "pulse_count": pulse_count,
        "subscribed_pulse_count": subscribed,
        "public_phishing_pulse_count": public,
        "indicator_count": indicator_count,
    }


def otx_cache_status(cache_path: str) -> dict:
    path = Path(cache_path)
    if not path.is_file():
        return {
            "status": "not_synced", "synced_at": "", "pulse_count": 0,
            "subscribed_pulse_count": 0, "public_phishing_pulse_count": 0,
            "indicator_count": 0, "skipped_pulse_count": 0,
            "truncated": False, "lookback_days": INITIAL_LOOKBACK_DAYS,
            "database_bytes": 0, "limit_reason": "",
        }
    try:
        with _database_connection(path, readonly=True) as connection:
            if _metadata(connection, "schema_version") not in {"2", str(SCHEMA_VERSION)}:
                raise RuntimeError("The local OTX database format is not supported.")
            counts = _database_counts(connection)
            return {
                "status": "ready",
                "synced_at": _metadata(connection, "synced_at"),
                **counts,
                "skipped_pulse_count": int(_metadata(connection, "skipped_pulse_count") or 0),
                "truncated": _metadata(connection, "public_search_truncated") == "1",
                "limit_reason": _metadata(connection, "public_limit_reason"),
                "lookback_days": int(_metadata(connection, "lookback_days") or INITIAL_LOOKBACK_DAYS),
                "database_bytes": path.stat().st_size,
            }
    except (OSError, sqlite3.Error) as error:
        raise RuntimeError("The local OTX database is invalid or unavailable.") from error


def _public_search_candidate(pulse: dict, cutoff: datetime) -> bool:
    """Accept OTX search summaries whose omitted tags can only be checked later."""
    tags = pulse.get("tags")
    tag_matches = _has_exact_phishing_tag(pulse)
    if isinstance(tags, list) and tags and not tag_matches:
        return False
    return _recent_pulse(pulse, cutoff) and _may_have_supported_indicators(pulse)


def _database_allocated_bytes(connection: sqlite3.Connection) -> int:
    page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
    page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
    return page_count * page_size


def _public_budget_reason(
    connection: sqlite3.Connection,
    started_at: float,
) -> str:
    if time.monotonic() - started_at >= PUBLIC_SYNC_SOFT_SECONDS:
        return "time"
    indicator_count = int(connection.execute("SELECT COUNT(*) FROM indicators").fetchone()[0])
    if indicator_count >= PUBLIC_INDICATOR_TARGET:
        return "indicators"
    allocated = _database_allocated_bytes(connection)
    if allocated >= PUBLIC_DATABASE_TARGET_BYTES:
        return "database"
    if allocated >= PUBLIC_DATABASE_HARD_BYTES:
        return "database"
    return ""


def _public_pulse_indicator_limit(pulse: dict) -> int:
    author = str(
        pulse.get("author_name")
        or ((pulse.get("author") or {}).get("username") if isinstance(pulse.get("author"), dict) else "")
    ).strip().casefold()
    return (
        PUBLIC_TRUSTED_PULSE_MAX_INDICATORS
        if author in PUBLIC_TRUSTED_AUTHORS
        else PUBLIC_COMMUNITY_PULSE_MAX_INDICATORS
    )


def _prefetch_public_indicator_page(session, pulse: dict) -> dict | None:
    pulse_id = str(pulse.get("id") or "")
    if not re.fullmatch(r"[0-9a-fA-F]{24}", pulse_id):
        return None
    try:
        return _request_json(
            session,
            f"{OTX_PULSE_DETAILS}/{pulse_id}/indicators",
            params={"limit": INDICATOR_PAGE_SIZE, "include_inactive": 0},
            timeout=PUBLIC_PREFETCH_TIMEOUT,
            attempts=1,
        )
    except OtxAuthenticationError:
        raise
    except (OtxTransientError, requests.RequestException, RuntimeError):
        return None


def _ingest_public_pulse(
    session,
    connection: sqlite3.Connection,
    pulse: dict,
    synced_at: datetime,
    started_at: float,
    report_progress: Callable[[dict], None],
    first_payload: dict | None = None,
) -> tuple[bool, str]:
    """Download one public Pulse through bounded 10k-indicator pages."""
    inline = pulse.get("indicators")
    if isinstance(inline, list):
        with connection:
            stored = _store_pulse(connection, pulse, "public_phishing", synced_at)
        return stored, _public_budget_reason(connection, started_at)

    pulse_id = str(pulse.get("id") or "")
    if not re.fullmatch(r"[0-9a-fA-F]{24}", pulse_id):
        return False, ""
    pulse_limit = _public_pulse_indicator_limit(pulse)
    next_page: str | None = f"{OTX_PULSE_DETAILS}/{pulse_id}/indicators"
    next_params: dict | None = {
        "limit": INDICATOR_PAGE_SIZE,
        "include_inactive": 0,
    }
    processed = 0
    stored_supported = 0
    first_page = True
    with connection:
        _store_pulse_summary(
            connection, pulse, "public_phishing", synced_at, complete=False
        )
    while next_page and processed < pulse_limit:
        reason = _public_budget_reason(connection, started_at)
        if reason:
            return stored_supported > 0, reason
        if first_page and first_payload is not None:
            payload = first_payload
        else:
            try:
                payload = _request_json(
                    session,
                    next_page,
                    params=next_params,
                    timeout=DETAIL_TIMEOUT,
                    attempts=DETAIL_ATTEMPTS,
                )
            except OtxAuthenticationError:
                raise
            except (OtxTransientError, requests.RequestException, RuntimeError):
                return stored_supported > 0, ""
        next_params = None
        indicators = payload.get("results")
        if not isinstance(indicators, list):
            indicators = payload.get("indicators")
        if not isinstance(indicators, list):
            return stored_supported > 0, ""
        remaining = pulse_limit - processed
        batch = indicators[:remaining]
        with connection:
            if first_page:
                connection.execute(
                    "DELETE FROM pulse_indicators WHERE pulse_id = ?", (pulse_id,)
                )
            stored_supported += _store_indicator_batch(connection, pulse_id, batch)
        first_page = False
        processed += len(batch)
        report_progress({
            "phase": "public_phishing",
            "processed": processed,
            "total": min(
                pulse_limit,
                int(payload.get("count") or pulse_limit),
            ),
            "percentage": None,
            "message": f"Indexed {processed:,} phishing indicators from the current Pulse…",
        })
        next_page = _safe_next_page(payload.get("next"))
        if len(batch) < len(indicators):
            next_page = None
    completed = not next_page or processed >= pulse_limit
    with connection:
        connection.execute(
            "UPDATE pulse_sources SET complete = ? WHERE pulse_id = ? AND source = 'public_phishing'",
            (int(completed), pulse_id),
        )
        if completed and stored_supported == 0:
            connection.execute(
                "DELETE FROM pulse_sources WHERE pulse_id = ? AND source = 'public_phishing'",
                (pulse_id,),
            )
            connection.execute(
                "DELETE FROM pulses WHERE id = ? AND NOT EXISTS "
                "(SELECT 1 FROM pulse_sources WHERE pulse_id = ?)",
                (pulse_id, pulse_id),
            )
    return stored_supported > 0, _public_budget_reason(connection, started_at)


def sync_subscribed_pulses(
    cache_path: str,
    api_key: str | None = None,
    progress: Callable[[dict], None] | None = None,
) -> dict:
    """Incrementally synchronize the locally available rolling OTX data set."""
    key = (api_key or os.getenv("OTX_API_KEY", "")).strip()
    if not key:
        raise RuntimeError("OTX is not configured: add the API key in Settings.")
    if requests is None:
        raise RuntimeError("OTX synchronization requires the requests package.")

    now = _utc_now()
    started_at = time.monotonic()
    cutoff = now - timedelta(days=INITIAL_LOOKBACK_DAYS)
    path = Path(cache_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f"{path.suffix}.{os.getpid()}.{os.urandom(6).hex()}.tmp")
    if path.is_file():
        try:
            with _database_connection(path, readonly=True) as current:
                valid_existing = _metadata(current, "schema_version") in {"2", str(SCHEMA_VERSION)}
        except (OSError, sqlite3.Error):
            valid_existing = False
        if valid_existing:
            shutil.copy2(path, temporary)
    session = requests.Session()
    session.headers.update({
        "X-OTX-API-KEY": key,
        "Accept": "application/json",
        "User-Agent": "FishStop/0.2 OTX local sync",
    })
    skipped_pulse_count = 0
    public_search_truncated = False
    report_progress = progress or (lambda _payload: None)
    report_progress({
        "phase": "preparing", "processed": 0, "total": None,
        "percentage": 2, "message": "Preparing the local OTX database…",
    })
    try:
        with _database_connection(temporary) as connection:
            _initialize_database(connection)
            previous_sync = _otx_datetime(_metadata(connection, "synced_at"))
            incremental_from = max(
                cutoff,
                (previous_sync - timedelta(days=INCREMENTAL_OVERLAP_DAYS)) if previous_sync else cutoff,
            )
            existing_counts = _database_counts(connection)
            previous_public_query = _metadata(connection, "public_query")
            continuing_bootstrap = (
                _metadata(connection, "public_search_truncated") == "1"
                and previous_public_query.endswith(f"<{INITIAL_LOOKBACK_DAYS}d")
                and existing_counts["indicator_count"] < PUBLIC_INDICATOR_TARGET
            )
            bootstrap_public = (
                existing_counts["public_phishing_pulse_count"] == 0
                or continuing_bootstrap
            )
            public_incremental_from = max(
                cutoff,
                (previous_sync - timedelta(days=PUBLIC_INCREMENTAL_OVERLAP_DAYS))
                if previous_sync else cutoff,
            )
            public_window_days = (
                INITIAL_LOOKBACK_DAYS
                if bootstrap_public
                else max(
                    PUBLIC_INCREMENTAL_OVERLAP_DAYS,
                    min(
                        INITIAL_LOOKBACK_DAYS,
                        math.ceil((now - public_incremental_from).total_seconds() / 86_400),
                    ),
                )
            )
            public_query = (
                f'{PUBLIC_PHISHING_QUERY} AND modified:<{public_window_days}d'
            )
            public_resume_url = _metadata(connection, "public_search_resume_url")
            if public_resume_url:
                public_resume_url = _safe_next_page(public_resume_url) or ""
                parsed_resume = urlsplit(public_resume_url)
                if (
                    parsed_resume.path.endswith("/search/pulses")
                    and "q" not in parse_qs(parsed_resume.query)
                ):
                    public_resume_url = ""
            public_limit_reason = ""
            seen_pulses: dict[str, set[str]] = {
                "subscribed": set(),
                "public_phishing": set(),
            }

            def pulse_is_current(pulse: dict, source: str) -> bool:
                """Reuse locally indexed details when OTX says a Pulse is unchanged."""
                pulse_id = str(pulse.get("id") or "")
                if not pulse_id:
                    return False
                row = connection.execute(
                    """SELECT p.modified_at, ps.complete
                       FROM pulses p JOIN pulse_sources ps ON ps.pulse_id = p.id
                       WHERE p.id = ? AND ps.source = ?""",
                    (pulse_id, source),
                ).fetchone()
                if row is None or not int(row["complete"]):
                    return False
                incoming_modified = _otx_datetime(
                    pulse.get("modified") or pulse.get("created")
                )
                stored_modified = _otx_datetime(row["modified_at"])
                if incoming_modified is None or stored_modified is None:
                    return False
                if incoming_modified > stored_modified:
                    return False
                connection.execute(
                    """INSERT INTO pulse_sources(pulse_id, source, complete) VALUES(?, ?, 1)
                       ON CONFLICT(pulse_id, source) DO UPDATE SET complete=1""",
                    (pulse_id, source),
                )
                return True

            def ingest_page(pulses: list, source: str) -> tuple[int, str]:
                nonlocal skipped_pulse_count
                candidates = [item for item in pulses if isinstance(item, dict)]
                if source == "public_phishing":
                    candidates = [
                        item for item in candidates
                        if _public_search_candidate(item, cutoff)
                    ]
                else:
                    candidates = [
                        item for item in candidates
                        if _has_exact_phishing_tag(item)
                        and _recent_pulse(item, cutoff)
                        and _may_have_supported_indicators(item)
                    ]
                unique_candidates = []
                for item in candidates:
                    pulse_id = str(item.get("id") or "")
                    if pulse_id and pulse_id in seen_pulses[source]:
                        continue
                    if pulse_id:
                        seen_pulses[source].add(pulse_id)
                    unique_candidates.append(item)
                candidates = unique_candidates
                with connection:
                    candidates = [
                        item for item in candidates
                        if not pulse_is_current(item, source)
                    ]
                stored = 0
                if source == "public_phishing":
                    inline = [
                        pulse for pulse in candidates
                        if isinstance(pulse.get("indicators"), list)
                    ]
                    remote = [pulse for pulse in candidates if pulse not in inline]
                    for pulse in inline:
                        succeeded, reason = _ingest_public_pulse(
                            session, connection, pulse, now, started_at, report_progress
                        )
                        stored += int(succeeded)
                        skipped_pulse_count += int(not succeeded and not reason)
                        if reason:
                            return stored, reason
                    for offset in range(0, len(remote), PUBLIC_PREFETCH_WORKERS):
                        reason = _public_budget_reason(connection, started_at)
                        if reason:
                            return stored, reason
                        wave = remote[offset:offset + PUBLIC_PREFETCH_WORKERS]
                        with ThreadPoolExecutor(max_workers=len(wave)) as executor:
                            payloads = list(executor.map(
                                lambda item: _prefetch_public_indicator_page(session, item),
                                wave,
                            ))
                        for pulse, payload in zip(wave, payloads):
                            if payload is None:
                                skipped_pulse_count += 1
                                continue
                            succeeded, reason = _ingest_public_pulse(
                                session,
                                connection,
                                pulse,
                                now,
                                started_at,
                                report_progress,
                                first_payload=payload,
                            )
                            stored += int(succeeded)
                            skipped_pulse_count += int(not succeeded and not reason)
                            if reason:
                                return stored, reason
                else:
                    for pulse in candidates:
                        with connection:
                            stored += int(_store_pulse(connection, pulse, source, now))
                return stored, ""

            def consume_pages(
                url: str,
                params: dict,
                source: str,
                progress_start: int,
                progress_end: int,
                *,
                max_pages: int | None = None,
            ) -> str:
                nonlocal public_search_truncated, public_limit_reason
                next_page: str | None = url
                next_params: dict | None = params
                visited: set[str] = set()
                processed = 0
                expected_total: int | None = None
                pages_downloaded = 0
                while next_page:
                    if next_page in visited:
                        raise RuntimeError("OTX returned a pagination loop.")
                    visited.add(next_page)
                    requested_page = (
                        f"{next_page}?{urlencode(next_params)}"
                        if next_params else next_page
                    )
                    if source == "public_phishing":
                        request_budget_reason = _public_budget_reason(
                            connection, started_at
                        )
                        if request_budget_reason:
                            public_search_truncated = True
                            public_limit_reason = request_budget_reason
                            with connection:
                                _set_metadata(
                                    connection,
                                    "public_search_resume_url",
                                    requested_page,
                                )
                            return request_budget_reason
                    payload = _request_json(session, next_page, params=next_params)
                    pages_downloaded += 1
                    next_params = None
                    pulses = payload.get("results") or []
                    if not isinstance(pulses, list):
                        raise RuntimeError("OTX returned an invalid Pulse response.")
                    _, budget_reason = ingest_page(pulses, source)
                    processed += len(pulses)
                    if expected_total is None:
                        try:
                            advertised_total = max(processed, int(payload.get("count")))
                            expected_total = advertised_total
                            if source == "public_phishing" and max_pages:
                                expected_total = min(expected_total, max_pages * PAGE_SIZE)
                        except (TypeError, ValueError):
                            expected_total = None
                    percentage = None
                    if expected_total:
                        fraction = min(1.0, processed / expected_total)
                        percentage = round(progress_start + (progress_end - progress_start) * fraction)
                    label = "subscribed" if source == "subscribed" else "public phishing"
                    report_progress({
                        "phase": source,
                        "processed": processed,
                        "total": expected_total,
                        "percentage": percentage,
                        "message": (
                            f"Downloaded {processed:,} of {expected_total:,} {label} Pulses…"
                            if expected_total else f"Downloaded {processed:,} {label} Pulses…"
                        ),
                    })
                    following_page = _safe_next_page(payload.get("next"))
                    if source == "public_phishing" and budget_reason:
                        public_search_truncated = True
                        public_limit_reason = budget_reason
                        with connection:
                            _set_metadata(connection, "public_search_resume_url", requested_page)
                        report_progress({
                            "phase": source,
                            "processed": processed,
                            "total": expected_total,
                            "percentage": progress_end,
                            "message": (
                                "OTX public enrichment reached its local safety budget; "
                                "the next refresh will resume from this page…"
                            ),
                        })
                        return budget_reason
                    next_page = following_page
                    if source == "public_phishing":
                        with connection:
                            _set_metadata(connection, "public_search_resume_url", next_page or "")
                    if next_page and max_pages and pages_downloaded >= max_pages:
                        public_search_truncated = True
                        public_limit_reason = "pages"
                        return "pages"
                if source == "public_phishing":
                    public_search_truncated = False
                    public_limit_reason = ""
                return ""

            consume_pages(
                OTX_SUBSCRIBED_PULSES,
                {"limit": PAGE_SIZE, "modified_since": incremental_from.isoformat()},
                "subscribed",
                5,
                25,
            )
            public_pages = (
                PUBLIC_SEARCH_INITIAL_MAX_PAGES
                if bootstrap_public or public_resume_url
                else PUBLIC_SEARCH_INCREMENTAL_MAX_PAGES
            )
            consume_pages(
                public_resume_url or OTX_SEARCH_PULSES,
                {} if public_resume_url else {
                    "q": public_query,
                    "sort": "-modified",
                    "page": 1,
                    "limit": PAGE_SIZE,
                },
                "public_phishing",
                25,
                95,
                max_pages=public_pages,
            )

            report_progress({
                "phase": "indexing", "processed": 0, "total": None,
                "percentage": 97, "message": "Finalizing the local IOC index…",
            })
            cutoff_iso = _utc_iso(cutoff, cutoff)
            with connection:
                connection.execute("DELETE FROM pulses WHERE modified_at < ?", (cutoff_iso,))
                connection.execute(
                    "DELETE FROM pulse_indicators WHERE expiration_at != '' AND expiration_at < ?",
                    (_utc_iso(now, now),),
                )
                connection.execute(
                    "DELETE FROM indicators WHERE NOT EXISTS "
                    "(SELECT 1 FROM pulse_indicators WHERE indicator_id = indicators.id)"
                )
                incomplete_public = int(connection.execute(
                    "SELECT COUNT(*) FROM pulse_sources "
                    "WHERE source = 'public_phishing' AND complete = 0"
                ).fetchone()[0])
                if incomplete_public and not public_search_truncated:
                    public_search_truncated = True
                    public_limit_reason = "partial"
                synced_at = _utc_iso(now, now)
                _set_metadata(connection, "synced_at", synced_at)
                _set_metadata(connection, "lookback_days", INITIAL_LOOKBACK_DAYS)
                _set_metadata(connection, "skipped_pulse_count", skipped_pulse_count)
                _set_metadata(
                    connection,
                    "public_search_truncated",
                    int(public_search_truncated),
                )
                _set_metadata(connection, "public_limit_reason", public_limit_reason)
                _set_metadata(connection, "public_query", public_query)
                _set_metadata(connection, "public_window_days", public_window_days)
                counts = _database_counts(connection)
                connection.execute("PRAGMA optimize")
        if os.name != "nt":
            temporary.chmod(0o600)
        os.replace(temporary, path)
        # Remove the version-1 JSON cache only after the new database has been
        # committed successfully. A failed migration never destroys fallback data.
        path.with_suffix(".json").unlink(missing_ok=True)
    finally:
        temporary.unlink(missing_ok=True)
        close_session = getattr(session, "close", None)
        if callable(close_session):
            close_session()

    status = otx_cache_status(str(path))
    report_progress({
        "phase": "complete", "processed": status["pulse_count"],
        "total": status["pulse_count"], "percentage": 100,
        "message": "OTX Pulse database synchronized.",
    })
    if status["truncated"]:
        reason_labels = {
            "time": "the 20 minute refresh budget",
            "database": "the 250 MB database target",
            "indicators": "the 1,000,000-indicator target",
            "pages": "the per-refresh discovery page budget",
            "partial": "temporarily unavailable public Pulse pages",
        }
        reason = reason_labels.get(status.get("limit_reason"), "its local safety budget")
        status["message"] = (
            f"Public phishing enrichment reached {reason}. Synchronized data was "
            "kept and the next refresh will continue incrementally."
        )
    elif skipped_pulse_count:
        status["message"] = (
            f"OTX intelligence was synchronized; {skipped_pulse_count} "
            "temporarily unavailable Pulse(s) were skipped."
        )
    else:
        status["message"] = (
            "The complete rolling 365-day OTX phishing database is available locally."
        )
    return status


def _report_candidates(report: dict) -> list[tuple[str, str, str]]:
    candidates: list[tuple[str, str, str]] = []
    for link in report.get("links") or []:
        if str(link.get("scheme") or "").lower() not in {"http", "https"}:
            continue
        url = str(link.get("url") or "")
        host = str(link.get("host") or "")
        if url:
            candidates.append(("url", url, "link"))
        if host:
            candidates.extend((("hostname", host, "link host"), ("domain", host, "link host")))
            parent = registered_domain(host)
            if parent and parent != host.lower().rstrip("."):
                candidates.append(("domain", parent, "link domain"))
    for field in ("from_", "return_path", "reply_to"):
        value = str(report.get(field) or "")
        for _, address in getaddresses([value]):
            normalized = _normalize_indicator("email", address)
            if not normalized:
                continue
            candidates.append(("email", normalized, "sender identity"))
            domain = normalized.rsplit("@", 1)[1]
            candidates.extend((
                ("hostname", domain, "sender identity"),
                ("domain", domain, "sender identity"),
            ))
    for hop in report.get("received_hops") or []:
        ips = hop.get("all_ips") or ([hop.get("sender_ip")] if hop.get("sender_ip") else [])
        for ip in ips:
            try:
                parsed = ipaddress.ip_address(str(ip).strip("[]"))
            except ValueError:
                continue
            if parsed.is_global:
                candidates.append(("ipv4" if parsed.version == 4 else "ipv6", str(parsed), "email route"))
    for attachment in report.get("attachments") or []:
        sha256 = str(attachment.get("hash_sha256") or "")
        if sha256:
            candidates.append(("sha256", sha256, "attachment"))
    return candidates


def apply_local_otx_intelligence(report: dict, cache_path: str | None = None) -> dict:
    """Attach local OTX matches without performing any network operation."""
    cache_path = cache_path or os.getenv("FISHSTOP_OTX_CACHE_PATH", "")
    path = Path(cache_path) if cache_path else None
    if path is None or not path.is_file():
        report["otx_intelligence"] = {
            "status": "unavailable",
            "message": "No synchronized OTX Pulse database is available.",
            "matches": [],
        }
        return report
    matches: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    try:
        with _database_connection(path, readonly=True) as connection:
            if _metadata(connection, "schema_version") not in {"2", str(SCHEMA_VERSION)}:
                raise sqlite3.DatabaseError("unsupported schema")
            cache_status = {**_database_counts(connection),
                "synced_at": _metadata(connection, "synced_at"),
                "skipped_pulse_count": int(_metadata(connection, "skipped_pulse_count") or 0),
                "lookback_days": int(_metadata(connection, "lookback_days") or INITIAL_LOOKBACK_DAYS),
                "truncated": _metadata(connection, "public_search_truncated") == "1",
            }
            for kind, value, source in _report_candidates(report):
                normalized = _normalize_indicator(kind, value)
                dedupe = (kind, normalized, source)
                if not normalized or dedupe in seen:
                    continue
                seen.add(dedupe)
                rows = connection.execute(
                    """SELECT p.id, p.name, p.author, p.modified_at, p.tags_json, p.tlp,
                              COUNT(*) OVER() AS match_count
                       FROM indicators i
                       JOIN pulse_indicators pi ON pi.indicator_id = i.id
                       JOIN pulses p ON p.id = pi.pulse_id
                       WHERE i.kind = ? AND i.value = ?
                       ORDER BY p.modified_at DESC LIMIT ?""",
                    (kind, normalized, MAX_PULSES_PER_INDICATOR),
                ).fetchall()
                if not rows:
                    continue
                pulses = [{
                    "id": row["id"], "name": row["name"], "author": row["author"],
                    "modified": row["modified_at"], "tags": json.loads(row["tags_json"]),
                    "tlp": row["tlp"],
                    "url": f"{OTX_BASE_URL}/pulse/{row['id']}",
                } for row in rows]
                matches.append({
                    "indicator": normalized,
                    "indicator_type": kind,
                    "source": source,
                    "confidence": "strong",
                    "pulse_count": int(rows[0]["match_count"]),
                    "pulses": pulses,
                })
    except (OSError, sqlite3.Error, ValueError):
        report["otx_intelligence"] = {
            "status": "unavailable",
            "message": "The synchronized OTX Pulse database could not be read.",
            "matches": [],
        }
        return report

    report["otx_intelligence"] = {
        "status": "match" if matches else "no_match",
        "synced_at": cache_status["synced_at"],
        "pulse_count": cache_status["pulse_count"],
        "subscribed_pulse_count": cache_status["subscribed_pulse_count"],
        "public_phishing_pulse_count": cache_status["public_phishing_pulse_count"],
        "indicator_count": cache_status["indicator_count"],
        "skipped_pulse_count": cache_status["skipped_pulse_count"],
        "lookback_days": cache_status["lookback_days"],
        "truncated": cache_status["truncated"],
        "matches": matches[:20],
        "message": (
            f"{len(matches)} indicator match(es) found in synchronized OTX Pulses."
            if matches
            else (
                "No match was found in the locally available OTX data; public "
                "search coverage was limited by OTX. This is neutral evidence."
                if cache_status["truncated"]
                else "No match was found in the synchronized 365-day OTX database; this is neutral evidence."
            )
        ),
    }
    if matches:
        strongest = matches[0]
        report.setdefault("flags", []).append({
            "level": "HIGH",
            "field": "OTX Threat Intelligence",
            "message": (
                f"{strongest['indicator_type'].upper()} indicator '{strongest['indicator']}' appears in "
                f"{strongest['pulse_count']} synchronized OTX Pulse(s). "
                "An exact OTX indicator match is treated as high-risk threat intelligence."
            ),
        })
    return report
