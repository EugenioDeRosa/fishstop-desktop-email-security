"""Deterministic analysis of bank details (IBAN) in a message.

IBANs are validated (country length and ISO 7064 mod-97 checksum) so that
arbitrary numbers are not reported. Signals describe payment-diversion
patterns; the IBAN itself is never sent anywhere and is masked in reports.
"""
from __future__ import annotations

import hashlib
import os
import re
import secrets
import sqlite3
import time
from contextlib import closing
from pathlib import Path

from fishstop_engine.domain_utils import mailbox_candidates, registered_domain

IBAN_LENGTHS = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22, "BH": 22, "BR": 29,
    "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22, "DK": 18, "DO": 28, "EE": 20, "EG": 29,
    "ES": 24, "FI": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28,
    "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20,
    "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "MC": 27, "MD": 24, "ME": 22, "MK": 19,
    "MR": 27, "MT": 31, "MU": 30, "NL": 18, "NO": 15, "PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29,
    "RO": 24, "RS": 22, "SA": 24, "SC": 31, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "ST": 25, "SV": 28,
    "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20,
}
_IBAN_CANDIDATE_RE = re.compile(r"\b([A-Z]{2}[ \t]?\d{2}(?:[ \t-]?[A-Z0-9]){10,30})\b", re.IGNORECASE)
_CHANGE_RE = re.compile(
    r"nuov[oaie]\s+(?:iban|coordinate|conto(?:\s+corrente)?|banca|estremi)|"
    r"coordinate\s+bancarie\s+(?:aggiornate|variate|nuove|modificate)|"
    r"(?:abbiamo|è\s+stat[oa]|sono\s+state)\s+(?:cambiat[oaie]|modificat[oaie]|variat[oaie]|aggiornat[oaie])\s+(?:la\s+|le\s+|il\s+|l['’]\s*)?(?:banca|conto|iban|coordinate)|"
    r"(?:variazione|cambio|aggiornamento)\s+(?:delle\s+|di\s+|dell['’]\s*|del\s+)?(?:coordinate|iban|conto|banca|estremi\s+bancari)|"
    r"non\s+(?:più\s+)?(?:utilizzare|usare|effettuare\s+pagamenti\s+su)\s+(?:il\s+|l['’]\s*)?(?:vecchio|precedente)\s+(?:conto|iban)|"
    r"new\s+(?:bank(?:ing)?|account|payment|remittance)\s+(?:details|information|account|instructions)|"
    r"updated\s+(?:bank(?:ing)?|payment|account|remittance)\s+(?:details|information|instructions)|"
    r"(?:changed|change\s+of|changing)\s+(?:our\s+)?(?:bank(?:ing)?|account|payment)\s*(?:details|account|information)?|"
    r"do\s+not\s+(?:use|pay\s+(?:to|into))\s+the\s+(?:old|previous)\s+account|"
    r"nuevos\s+datos\s+bancarios|nueva\s+cuenta|cambio\s+de\s+(?:cuenta|banco)|"
    r"nouvelles?\s+coordonn[ée]es\s+bancaires|nouveau\s+rib|changement\s+de\s+(?:banque|compte|rib)|"
    r"neue\s+(?:bankverbindung|kontodaten|iban|kontonummer)|ge[äa]nderte\s+bankverbindung",
    re.IGNORECASE,
)
MEMORY_TTL_DAYS = 730


def _valid_iban(candidate: str) -> str:
    iban = re.sub(r"[\s-]+", "", candidate).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]+", iban):
        return ""
    if IBAN_LENGTHS.get(iban[:2]) != len(iban):
        return ""
    rearranged = iban[4:] + iban[:4]
    numeric = "".join(str(int(char, 36)) for char in rearranged)
    return iban if int(numeric) % 97 == 1 else ""


def extract_ibans(text: str) -> list[str]:
    found: list[str] = []
    for match in _IBAN_CANDIDATE_RE.finditer(text or ""):
        candidate = match.group(1)
        # Trim trailing words captured after the IBAN (e.g. "IT60X... BIC").
        tokens = re.split(r"([ \t-])", candidate)
        for end in range(len(tokens), 0, -1):
            iban = _valid_iban("".join(tokens[:end]))
            if iban:
                if iban not in found:
                    found.append(iban)
                break
    return found[:10]


def mask_iban(iban: str) -> str:
    return f"{iban[:4]} **** {iban[-4:]}" if len(iban) > 8 else "****"


def _sender_country(report: dict) -> str:
    senders = [address for _, address in mailbox_candidates(report.get("from_") or "")]
    if len(senders) != 1:
        return ""
    domain = registered_domain(senders[0].rsplit("@", 1)[-1])
    tld = domain.rsplit(".", 1)[-1].upper() if "." in domain else ""
    tld = "GB" if tld == "UK" else tld
    return tld if tld in IBAN_LENGTHS else ""


def assess_payment_details(report: dict, segments: list[dict]) -> dict:
    """Extract IBANs by position (new text, quoted history, attachments)."""
    outer = next((segment for segment in segments if segment.get("id") == "outer"), None)
    new_text = str(outer.get("text") if outer else report.get("body_clean") or "")
    quoted_text = "\n".join(str(segment.get("text") or "") for segment in segments if segment.get("id") != "outer")
    attachment_text = "\n".join(
        str((attachment.get("pdf_security") or {}).get("text_excerpt") or "")
        + "\n" + str((attachment.get("html_security") or {}).get("text") or "")
        for attachment in report.get("attachments") or [])
    body_ibans = extract_ibans(new_text)
    quoted_ibans = [iban for iban in extract_ibans(quoted_text) if iban not in body_ibans]
    attachment_ibans = extract_ibans(attachment_text)
    change = _CHANGE_RE.search(new_text)
    country = _sender_country(report)
    alerts: list[dict] = []

    def alert(level: str, key: str, message: str) -> None:
        alerts.append({"level": level, "key": key, "message": message})

    if body_ibans and quoted_ibans:
        alert("HIGH", "iban_changed_in_thread",
              f"The new text gives bank details ({', '.join(mask_iban(i) for i in body_ibans[:2])}) different from those "
              f"in the quoted conversation ({', '.join(mask_iban(i) for i in quoted_ibans[:2])}): a typical payment-diversion pattern.")
    unmatched = [iban for iban in body_ibans if attachment_ibans and iban not in attachment_ibans]
    if unmatched:
        alert("HIGH", "iban_body_attachment_mismatch",
              f"The message body asks for payment to {mask_iban(unmatched[0])}, but the attached document shows "
              f"{mask_iban(attachment_ibans[0])}.")
    foreign = [iban for iban in body_ibans if country and iban[:2] != country]
    if body_ibans and change:
        corroborated = bool(foreign)
        alert("HIGH" if corroborated else "MEDIUM", "iban_change_request",
              f"The message announces changed bank details ('{change.group(0)[:60]}') and provides "
              f"{mask_iban(body_ibans[0])}."
              + (f" The account is registered in {foreign[0][:2]} while the sender domain is in {country}." if corroborated else "")
              + " Confirm through a contact you already know before paying.")
    elif foreign:
        alert("LOW", "iban_foreign_country",
              f"The bank account {mask_iban(foreign[0])} is registered in {foreign[0][:2]} while the sender domain is in {country}.")
    return {
        "body_ibans": [mask_iban(iban) for iban in body_ibans],
        "quoted_ibans": [mask_iban(iban) for iban in quoted_ibans],
        "attachment_ibans": [mask_iban(iban) for iban in attachment_ibans],
        "change_phrase": change.group(0)[:80] if change else "",
        "sender_country": country,
        "alerts": alerts,
        "_body_ibans_raw": body_ibans,
    }


# ── Local memory of bank details per sender domain ─────────────────────────
# Only salted hashes are stored. The memory can raise an alert when a known
# sender introduces a different account; it never lowers the risk of an
# account it has seen, so a previously sent message cannot whitelist an IBAN.

def _memory_path() -> Path | None:
    root = os.getenv("FISHSTOP_IDENTITY_DATA_DIR", "")
    return Path(root) / "payment-memory.sqlite" if root else None


def _connect(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=5)
    db.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS accounts (sender TEXT, digest TEXT, message TEXT, seen REAL, "
               "PRIMARY KEY (sender, digest, message))")
    return db


def _digest(db, iban: str) -> str:
    row = db.execute("SELECT value FROM meta WHERE key='salt'").fetchone()
    salt = row[0] if row else secrets.token_hex(16)
    if not row:
        db.execute("INSERT INTO meta VALUES ('salt', ?)", (salt,))
    return hashlib.sha256((salt + iban).encode()).hexdigest()


def apply_payment_memory(report: dict, message_digest: str) -> list[dict]:
    """Compare body IBANs with accounts previously seen from the same sender domain."""
    details = report.get("payment_details") or {}
    ibans = details.pop("_body_ibans_raw", None) or []
    path = _memory_path()
    sender = report.get("from_registered_domain") or ""
    if not ibans or not path or not sender or not message_digest:
        return []
    alerts: list[dict] = []
    try:
        with closing(_connect(path)) as db, db:
            db.execute("DELETE FROM accounts WHERE seen < ?", (time.time() - MEMORY_TTL_DAYS * 86400,))
            known = {row[0] for row in db.execute(
                "SELECT digest FROM accounts WHERE sender=? AND message<>?", (sender, message_digest))}
            for iban in ibans:
                digest = _digest(db, iban)
                if known and digest not in known:
                    alerts.append({"level": "MEDIUM", "key": "iban_new_for_sender",
                                   "message": f"{mask_iban(iban)} differs from the bank details previously seen from "
                                              f"{sender} on this device. Confirm the change through a known contact."})
                db.execute("INSERT OR IGNORE INTO accounts VALUES (?,?,?,?)", (sender, digest, message_digest, time.time()))
    except (OSError, sqlite3.Error):
        return []
    if alerts and details.get("change_phrase"):
        for item in alerts:
            item["level"] = "HIGH"
    return alerts
