"""Local multilingual organisation extraction for impersonation analysis."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from fishstop_engine.domain_utils import registrable_label


MAX_SEGMENT_CHARS = 1_000
MAX_BODY_SEGMENTS = 6
_CONFUSABLES = str.maketrans({
    # Common Cyrillic/Greek homoglyphs used to disguise Latin brand names.
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "І": "I", "К": "K", "М": "M", "О": "O", "Р": "P", "Т": "T", "Х": "X", "Υ": "Y",
    "а": "a", "с": "c", "е": "e", "і": "i", "ј": "j", "о": "o", "р": "p", "ѕ": "s", "х": "x", "у": "y", "һ": "h", "ԁ": "d",
    "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X",
    "α": "a", "β": "b", "γ": "y", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "χ": "x",
})
_FOOTER_ENTITY_RE = re.compile(r"\b(?:all\s+rights?|copyright|automated\s+message|team\s*this)\b", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[A-Z0-9._%+\-]+@([A-Z0-9.\-]+\.[A-Z]{2,})", re.IGNORECASE)
_NON_BRAND_TOKENS = {"com", "net", "org", "www", "mail", "email", "support", "noreply", "no-reply"}
_ENTITY_TYPES = {"ORG", "LOC", "PER"}
GLINER_LABELS = (
    "brand",
    "company",
    "organization",
    "financial institution",
    "online service",
    "government agency",
    "person",
    "location",
)
GLINER_THRESHOLD = 0.35
_GLINER_TYPE_MAP = {
    "brand": "ORG",
    "company": "ORG",
    "organization": "ORG",
    "financial institution": "ORG",
    "online service": "ORG",
    "government agency": "ORG",
    "person": "PER",
    "location": "LOC",
}


def _clip(value: object, limit: int = MAX_SEGMENT_CHARS) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text[:limit].rstrip()


def _segments(report: dict[str, Any]) -> list[tuple[str, str]]:
    """Keep the NER task focused on visible sender, subject and body text."""
    values: list[tuple[str, str]] = []
    for source, value in (
        ("sender", report.get("from_")),
        ("subject", report.get("subject")),
    ):
        text = _clip(value, 480)
        if text:
            values.append((source, text))

    body = str(report.get("body_for_ai") or report.get("body_clean") or "").strip()
    for index in range(0, len(body), MAX_SEGMENT_CHARS):
        if len(values) >= MAX_BODY_SEGMENTS + 2:
            break
        text = _clip(body[index:index + MAX_SEGMENT_CHARS])
        if text:
            values.append(("body", text))
    return values


def _normalise_entity(value: object) -> str:
    text = re.sub(r"\s+", " ", str(value or "").replace("##", " ")).strip(" .,:;!?()[]{}\"'")
    return text


def _latin_skeleton(value: str) -> str:
    """Normalise look-alike Unicode letters without changing quoted evidence."""
    return str(value or "").translate(_CONFUSABLES)


def _sender_domain_claims(report: dict[str, Any], text: str) -> list[str]:
    """Recover a claimed brand when its visible text matches the sender domain."""
    candidates: list[str] = []
    for domain in _EMAIL_RE.findall(str(report.get("from_") or "")):
        label = registrable_label(domain).replace("-", " ")
        compact = re.sub(r"\s+", "", label)
        if len(compact) < 3 or compact.casefold() in _NON_BRAND_TOKENS:
            continue
        if re.search(rf"(?<![a-z0-9]){re.escape(compact)}(?![a-z0-9])", _latin_skeleton(text), re.IGNORECASE):
            candidates.append(label.title())
    return list(dict.fromkeys(candidates))


def _is_low_quality_entity(raw_value: object, name: str, text: str, start: int, end: int) -> bool:
    """Reject token fragments and entities embedded inside addresses/domains.

    This is deliberately language-agnostic: it uses token boundaries and the
    NER model's own span, rather than a catalogue of brands or phishing terms.
    """
    raw = str(raw_value or "").strip()
    compact = re.sub(r"[^\w]", "", name, flags=re.UNICODE)
    if raw.startswith("##") or len(compact) < 3 or name.casefold() in _NON_BRAND_TOKENS:
        return True
    before = text[start - 1] if start > 0 and start <= len(text) else ""
    after = text[end] if 0 <= end < len(text) else ""
    # A real organisation mention is a complete token.  Substrings such as
    # '##esco' in 'Bradesco' and labels inside email/URL hosts are not claims.
    if before.isalnum() or after.isalnum():
        return True
    if (before and before in ".@_-") or (after and after in ".@_-"):
        return True
    return False


def _predict_entities(model: Any, texts: list[str]) -> list[list[dict[str, Any]]]:
    """Run GLiNER in one CPU batch and retain the legacy entity schema."""
    if hasattr(model, "inference"):
        batches = model.inference(
            [_latin_skeleton(text) for text in texts],
            list(GLINER_LABELS),
            threshold=GLINER_THRESHOLD,
            flat_ner=True,
        )
        normalized: list[list[dict[str, Any]]] = []
        for predictions in batches:
            normalized.append([
                {
                    "entity_group": _GLINER_TYPE_MAP.get(
                        str(prediction.get("label") or "").casefold(),
                        "",
                    ),
                    "word": prediction.get("text"),
                    "start": prediction.get("start"),
                    "end": prediction.get("end"),
                    "score": prediction.get("score"),
                }
                for prediction in predictions
            ])
        return normalized

    # Preserve a small compatibility seam for unit tests and older local
    # development environments while the experimental branch is evaluated.
    return [model(_latin_skeleton(text)) for text in texts]


def extract_organisations(report: dict[str, Any], pipeline) -> dict[str, Any]:
    """Extract identity candidates without treating each entity as a brand claim.

    The public function name remains stable for the sidecar API, but its result
    deliberately retains organisations, locations and people.  Brand
    intelligence can therefore reject locations before doing any public-domain
    lookup instead of relying on a possibly incorrect ORG prediction alone.
    """
    segments = _segments(report)
    if not segments:
        return {
            "status": "skipped",
            "message": "No visible sender, subject, or body text is available for identity analysis.",
            "entities": [],
        }

    texts = [text for _, text in segments]
    # Segments remain below GLiNER's configured context window. Running them
    # together avoids repeating the label-encoding and model-call overhead on
    # CPU-only computers.
    raw_batches = _predict_entities(pipeline, texts)

    entities: dict[str, dict[str, Any]] = {}
    for (source, text), predictions in zip(segments, raw_batches):
        for prediction in predictions:
            label = str(prediction.get("entity_group") or prediction.get("entity") or "").upper()
            entity_type = label.removeprefix("B-").removeprefix("I-")
            if entity_type not in _ENTITY_TYPES:
                continue
            raw_name = prediction.get("word")
            name = _normalise_entity(raw_name)
            start = max(0, int(prediction.get("start") or 0))
            end = min(len(text), int(prediction.get("end") or 0))
            if _is_low_quality_entity(raw_name, name, text, start, end) or _FOOTER_ENTITY_RE.search(name):
                continue
            key = name.casefold()
            item = entities.setdefault(key, {
                "name": name,
                "confidence": 0.0,
                "entity_type": entity_type,
                "entity_types": [],
                "occurrences": [],
            })
            item["confidence"] = max(item["confidence"], float(prediction.get("score") or 0.0))
            if entity_type not in item["entity_types"]:
                item["entity_types"].append(entity_type)
            excerpt = _clip(text[max(0, start - 70):min(len(text), end + 110)], 220)
            occurrence = {"source": source, "evidence": excerpt}
            if occurrence not in item["occurrences"]:
                item["occurrences"].append(occurrence)

    # Do not let the local part or the DNS suffix of an email address become a
    # claimed organisation.  They are transport identifiers, not visible brand
    # evidence.  The visible display name, subject and body remain available.
    all_visible_text = "\n".join(_EMAIL_RE.sub("", text) for text in texts)
    for name in _sender_domain_claims(report, all_visible_text):
        key = name.casefold()
        item = entities.setdefault(key, {
            "name": name,
            "confidence": 0.95,
            "entity_type": "ORG",
            "entity_types": [],
            "occurrences": [],
        })
        item["confidence"] = max(item["confidence"], 0.95)
        # A domain-derived candidate is strong evidence of a sender identity,
        # and the visible domain label is therefore also an organisation
        # candidate. DOMAIN records where that evidence came from.
        if "ORG" not in item["entity_types"]:
            item["entity_types"].append("ORG")
        if "DOMAIN" not in item["entity_types"]:
            item["entity_types"].append("DOMAIN")
        if not item.get("entity_type"):
            item["entity_type"] = "ORG"
        occurrence = {"source": "sender domain", "evidence": _clip(str(report.get("from_") or ""), 220)}
        if occurrence not in item["occurrences"]:
            item["occurrences"].append(occurrence)
        compact = re.sub(r"\s+", "", name)
        for source, original in segments:
            if not re.search(rf"(?<![a-z0-9]){re.escape(compact)}(?![a-z0-9])", _latin_skeleton(original), re.IGNORECASE):
                continue
            visible = {"source": source, "evidence": _clip(original, 220)}
            if visible not in item["occurrences"]:
                item["occurrences"].append(visible)

    results = sorted(
        entities.values(),
        key=lambda item: (-item["confidence"], item["name"].casefold()),
    )[:12]
    return {
        "status": "ok",
        "entities": results,
        "segments_analyzed": len(segments),
        "message": (
            f"{len(results)} identity entity candidate(s) extracted locally."
            if results else "No identity entity was extracted from visible email text."
        ),
    }
