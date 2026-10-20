"""Structural compaction of mail text, without guessing which claims matter.

Never summarise, score, shorten URLs, or discard unique prose. Full MIME sources
remain in the SOC report; this module only changes the model's text view.
"""
import difflib
import re

_TURN_BOUNDARY = re.compile(
    r"^\s*(?:\[(?:TARGET|CONTEXT|PRIOR CONTEXT|LATER FOLLOW-UP CONTEXT).*MESSAGE|"
    r"(?:from|da|de|sent|inviato|subject|oggetto)\s*:|"
    r"(?:on .+ wrote|il giorno .+ ha scritto|.+ escribi[oó])\s*:|"
    r"[-_]{3,}.*(?:original|forwarded|inoltrato|originale))", re.I)
_REPEAT_MARKER = "[Repeated block: identical text is already present above.]"
_MIME_MARKER = "[HTML alternative; shared paragraphs occur above]"
_OMISSION_MARKER = "[This version also omits passages present in the other version.]"
_SHARED_GAP_MARKER = "[Shared paragraphs omitted here; they are present in the primary version.]"


def without_compaction_notices(text: str) -> str:
    """Parser annotations describe layout; they cannot ground email quotations.

    Use before whitespace flattening. An original line identical to an annotation
    is conservatively excluded too, rather than inventing trustworthy provenance.
    """
    notices = {_REPEAT_MARKER, _MIME_MARKER, _OMISSION_MARKER,
               _SHARED_GAP_MARKER, "[HTML alternative]"}
    return "\n".join(line for line in str(text or "").splitlines()
                     if line.strip() not in notices)


def _key(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def compact_repeated_blocks(text: str) -> tuple[str, dict]:
    """Keep one exact copy of substantial repeated layout blocks.

    A reference marker retains the fact and position of each repetition. Do not
    deduplicate between conversation turns or individual short fields/commands.
    """
    text = str(text or "")
    lines = text.splitlines()
    keys = [_key(line) for line in lines]
    output, seen = [], {}
    removed = blocks = 0
    index = 0
    while index < len(lines):
        if _TURN_BOUNDARY.match(lines[index]):
            seen.clear()
        best = 0
        for previous in seen.get(keys[index], [])[-8:] if keys[index] else []:
            length = 0
            while (index + length < len(lines) and previous + length < index
                   and length < 256 and keys[previous + length] == keys[index + length]
                   and not _TURN_BOUNDARY.match(lines[index + length])):
                length += 1
            segment = lines[index:index + length]
            if (sum(bool(_key(line)) for line in segment) >= 3
                    and sum(len(line) for line in segment) >= 512):
                best = max(best, length)
        if best:
            output.append(_REPEAT_MARKER)
            removed += sum(len(line) for line in lines[index:index + best])
            blocks += 1
            index += best
            continue
        if keys[index]:
            seen.setdefault(keys[index], []).append(index)
        output.append(lines[index])
        index += 1
    result = "\n".join(output).strip()
    return result, {"duplicate_blocks": blocks, "duplicate_characters": removed,
                    "before_characters": len(text), "after_characters": len(result)}


def merge_mime_alternatives(primary: str, alternative: str) -> tuple[str, dict]:
    """Retain all changed alternative paragraphs with neighbouring context.

    Equal blocks occur once; replacements, insertions, deletions and reordering
    retain surrounding text so a removed negation cannot disappear silently.
    No fuzzy word matching, sender lists or security-keyword filters are used.
    """
    primary, alternative = str(primary or "").strip(), str(alternative or "").strip()
    if not primary:
        return alternative, {"alternative_characters_omitted": 0, "alternatives_differ": False}
    if not alternative or _key(primary) == _key(alternative):
        return primary, {"alternative_characters_omitted": len(alternative), "alternatives_differ": False}
    # A paragraph may wrap over several physical lines in the plain part.
    def paragraphs(value):
        return [p for p in re.split(r"\n\s*\n", value) if p.strip()]
    before, after = paragraphs(primary), paragraphs(alternative)
    # HTML text has one rendered paragraph per line, often with no blank lines.
    # Only use that finer segmentation when both views have physical lines.
    if len(after) == 1 and len(alternative.splitlines()) > 1:
        after = [p for p in alternative.splitlines() if p.strip()]
    if len(before) == 1 and len(primary.splitlines()) > 1:
        before = [p for p in primary.splitlines() if p.strip()]
    if len(before) + len(after) > 4096:
        return primary + "\n\n[HTML alternative]\n" + alternative, {
            "alternative_characters_omitted": 0, "alternatives_differ": True}
    matcher = difflib.SequenceMatcher(None, [_key(p) for p in before], [_key(p) for p in after], autojunk=False)
    keep = set()
    omitted_passage = False
    for operation, i1, i2, j1, j2 in matcher.get_opcodes():
        if operation == "equal":
            continue
        omitted_passage |= operation == "delete"
        keep.update(range(max(0, j1 - 1), min(len(after), max(j2, j1 + 1) + 1)))
    # If segmentation itself differs, preserving the alternative is safer than
    # claiming that meaningful wording was redundant.
    if not keep:
        keep.update(range(len(after)))
    retained_parts = []
    previous = None
    for index in sorted(keep):
        if previous is not None and index > previous + 1:
            retained_parts.append(_SHARED_GAP_MARKER)
        retained_parts.append(after[index])
        previous = index
    retained = "\n\n".join(retained_parts)
    notice = _MIME_MARKER
    if omitted_passage:
        notice += "\n" + _OMISSION_MARKER
    result = primary + "\n\n" + notice + "\n" + retained
    full = primary + "\n\n[HTML alternative]\n" + alternative
    if len(result) >= len(full):
        return full, {"alternative_characters_omitted": 0, "alternatives_differ": True}
    source_retained = "\n\n".join(after[index] for index in sorted(keep))
    return result, {"alternative_characters_omitted": max(0, len(alternative) - len(source_retained)),
                    "alternatives_differ": True}
