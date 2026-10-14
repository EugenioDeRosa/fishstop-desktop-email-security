"""Conservative Public API quotas shared across analysis subprocesses."""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time
import requests


def get(url, *, headers, timeout):
    key = hashlib.sha256(headers["x-apikey"].encode()).hexdigest()
    indicator = hashlib.sha256(url.encode()).hexdigest()
    path = Path(os.getenv("FISHSTOP_VT_CACHE_PATH", str(Path.home() / ".fishstop" / "vt-cache.sqlite3")))
    path.parent.mkdir(parents=True, exist_ok=True)
    now = time.time()
    def response(status, payload):
        result = requests.Response()
        result.status_code = status
        result._content = payload.encode()
        return result
    try:
        with closing(sqlite3.connect(path, timeout=5)) as db, db:
            db.execute("CREATE TABLE IF NOT EXISTS calls (key TEXT, stamp REAL)")
            db.execute("CREATE TABLE IF NOT EXISTS cache (key TEXT, indicator TEXT, stamp REAL, status INTEGER, payload TEXT, PRIMARY KEY(key, indicator))")
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM calls WHERE stamp < ?", (now - 86400,))
            db.execute("DELETE FROM cache WHERE stamp < ?", (now - 3600,))
            cached = db.execute("SELECT status,payload FROM cache WHERE key=? AND indicator=?", (key, indicator)).fetchone()
            if cached:
                return response(*cached)
            minute, daily = db.execute("SELECT SUM(stamp > ?),COUNT(*) FROM calls WHERE key=?", (now - 60, key)).fetchone()
            if (minute or 0) >= 4 or daily >= 500:
                return response(429, json.dumps({"error": {"message": "Local VirusTotal Public API quota reached"}}))
            db.execute("INSERT INTO calls VALUES (?,?)", (key, now))
    except (sqlite3.Error, OSError) as error:
        raise requests.ConnectionError("Cannot safely enforce VirusTotal quotas") from error
    result = requests.get(url, headers=headers, timeout=timeout)
    if result.status_code in (200, 404):
        try:
            with closing(sqlite3.connect(path, timeout=5)) as db, db:
                db.execute("INSERT OR REPLACE INTO cache VALUES (?,?,?,?,?)", (key, indicator, now, result.status_code, result.text))
        except sqlite3.Error:
            pass
    return result
