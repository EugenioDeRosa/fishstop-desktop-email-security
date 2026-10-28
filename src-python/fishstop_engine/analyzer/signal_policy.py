"""Single severity table for static findings (see data/signal-policy.json).

The interface shows HIGH RISK for any decisive finding and REVIEW for any
supporting finding. The Python policy derives the same effects from the same
table, so the semantic verdict, the interface and the SIEM export agree.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

POLICY_PATH = Path(__file__).resolve().parents[1] / "data" / "signal-policy.json"


@lru_cache(maxsize=1)
def signal_policy() -> dict:
    return json.loads(POLICY_PATH.read_text(encoding="utf-8"))


def _field_key(field: str) -> str:
    return re.sub(r"\s+", " ", str(field or "").strip().casefold())


def verdict_signals(report: dict) -> list[dict]:
    """Return verdict-relevant findings with a stable id and effect.

    Mirrors the interface filters: MIME diagnostics are ignored; delivery and
    sender checks of the outer message are ignored when an embedded message is
    the selected target; Return-Path differences are ignored when DMARC passed.
    """
    policy = signal_policy()
    effects = policy["level_effects"]
    ignored_prefixes = tuple(policy.get("ignored_field_prefixes") or [])
    embedded_ignored = set(policy.get("embedded_target_ignored_fields") or [])
    embedded = report.get("selected_target_authentication_scope") == "embedded_unavailable"
    dmarc = ((report.get("effective_auth_results") or {}).get("DMARC")
             or (report.get("auth_results") or {}).get("DMARC") or {})
    dmarc_passed = str(dmarc.get("status") or "").lower() in {"pass", "bestguesspass"}
    routing = report.get("reply_to_routing") or {}
    signals: list[dict] = []
    for flag in report.get("flags") or []:
        key = _field_key(flag.get("field"))
        level = str(flag.get("level") or "INFO").upper()
        if key.startswith(ignored_prefixes):
            continue
        if embedded and key in embedded_ignored:
            continue
        if dmarc_passed and key == "return-path":
            continue
        if key == "reply-to" and routing.get("level") and routing.get("level") != "NONE":
            level = str(routing["level"]).upper()
        if key == "link" and re.search(r"potentially executable|script content", str(flag.get("message") or ""), re.I) \
                and re.search(r"`?mailto:", str(flag.get("message") or ""), re.I):
            continue
        effect_override = ""
        if key == "dkim" and re.search(r"\bDKIM (?:NONE|MISSING)\b", str(flag.get("message") or ""), re.I):
            # A missing signature is an absence of evidence (common in exports).
            effect_override = "informational"
        entry = (policy.get("fields") or {}).get(key) or {}
        if key.endswith(" inspection incomplete") and not entry:
            entry = {"id": "coverage." + key.split(" ", 1)[0], "category": "coverage"}
        signals.append({
            "id": entry.get("id") or "static." + re.sub(r"[^a-z0-9]+", "_", key).strip("_"),
            "category": entry.get("category") or "static",
            "field": flag.get("field"),
            "level": level,
            "effect": effect_override or effects.get(level, "informational"),
            "message": flag.get("message"),
        })
    return signals


def technical_effect(report: dict) -> tuple[str, list[str]]:
    """Return (strongest effect, field labels) for the technical axis."""
    signals = verdict_signals(report)
    decisive = [signal for signal in signals if signal["effect"] == "decisive"]
    if decisive:
        return "decisive", list(dict.fromkeys(str(signal["field"]) for signal in decisive))
    supporting = [signal for signal in signals if signal["effect"] == "supporting"]
    if supporting:
        return "supporting", list(dict.fromkeys(str(signal["field"]) for signal in supporting))
    return "informational", []
