"""
Utilities for selecting the email text that should be sent to BERT.

Replies and forwards often contain more than one conversation layer. The full
body remains useful for link extraction and manual inspection, but the model
should see the most relevant layer only.
"""

import re

from fishstop_engine.ai_input import compact_ai_body


_FORWARD_MARKER_RE = re.compile(
    r"^\s*(?:"
    r"-{2,}\s*forwarded message\s*-{2,}|"
    r"begin forwarded message:|"
    r"forwarded message|"
    r"messaggio inoltrato|"
    r"inizio messaggio inoltrato"
    r")\s*$",
    re.IGNORECASE,
)

_REPLY_MARKER_RE = re.compile(
    r"^\s*(?:"
    r"on .+ wrote:|"
    r"il giorno .+ ha scritto:|"
    r"le .+ a ecrit\s*:|"
    r"am .+ schrieb .+:|"
    r"-{2,}\s*original message\s*-{2,}|"
    r"-{2,}\s*messaggio originale\s*-{2,}"
    r")\s*$",
    re.IGNORECASE,
)

_FORWARDED_HEADER_RE = re.compile(
    r"^\s*(?:"
    r"from|da|de|sent|inviato|date|data|to|a|cc|bcc|subject|oggetto"
    r")\s*:",
    re.IGNORECASE,
)

_OUTLOOK_REPLY_FROM_RE = re.compile(r"^\s*(?:from|da|de)\s*:", re.IGNORECASE)
_OUTLOOK_REPLY_HEADER_RE = re.compile(
    r"^\s*(?:sent|inviato|date|data|to|a|cc|bcc|subject|oggetto)\s*:",
    re.IGNORECASE,
)

# The label between dash runs is localized by mail clients (for example
# ``---------- Original message ----------``), so recognition below relies on
# the structural header block that follows it rather than on its wording.
_THREAD_SEPARATOR_RE = re.compile(r"^\s*[_=*-]{8,}(?:\s*[^\r\n]*?\s*[_=*-]{8,})?\s*$")
_THREAD_SEPARATOR_HEADER_RE = re.compile(
    r"^\s*(?:from|da|de|sent|inviato|date|data|to|a|cc|bcc|subject|oggetto)\s*:",
    re.IGNORECASE,
)
_GENERIC_HEADER_LINE_RE = re.compile(
    r"^\s*[\wÀ-ÖØ-öø-ÿ][\wÀ-ÖØ-öø-ÿ ._-]{0,32}\s*:\s*\S",
    re.IGNORECASE,
)

# In a forwarded payload, mail clients localize the leading date freely
# ("Tuesday", "Martedì", "martes", ...), while the reply verb remains a
# reliable structural delimiter.  It is deliberately used only after a
# forwarding separator, never to cut a normal standalone message.
_FORWARDED_THREAD_REPLY_RE = re.compile(
    r"^\s*.+\b(?:wrote|ha\s+scritto|escribi[oó]|a\s+[ée]crit|schrieb)\s*:\s*$",
    re.IGNORECASE,
)


_AI_TAIL_BOILERPLATE_RE = re.compile(
    r"^\s*(?:"
    r"please consider the impact on the environment before printing|"
    r"this e-?mail may contain|"
    r"this message may contain|"
    r"this e-?mail\s*\(including any attachment\)\s+is a corporate message|"
    r"this e-?mail is intended solely|"
    r"all (?:the )?information and attachments contained in (?:this )?(?:e-?mail|message)|"
    r"the contents of this (?:e-?mail|message) (?:and any attachments )?are confidential|"
    r"this e-?mail was sent to you by|"
    r"legal disclosure\b|"
    r"privacy statement\b|"
    r"if you no longer wish to receive|"
    r"to opt out of future communications|"
    r"if you'd like me to stop sending you emails|"
    r"if you would like me to stop sending you emails|"
    r"this message was sent to .{0,180}(?:unsubscribe|manage your settings)|"
    r"unsubscribe\b|"
    r"informativa privacy\b|"
    r"prima di stampare\b|"
    r"questo messaggio è stato inviato da un indirizzo email di sola notifica|"
    r"il presente messaggio di posta elettronica|"
    r"il presente messaggio,?\s*(?:inclus[oaie]|con)\b|"
    r"questa e-?mail(?: e qualsiasi allegato)?|"
    r"questa email(?: e qualsiasi allegato)?|"
    r"wiadomość ta przeznaczona jest wyłącznie|"
    r"niniejsza wiadomość(?: e-?mail)?(?: wraz z załącznikami)?|"
    r"riservatezza\b|"
    r"avvertenza di riservatezza\b|"
    r"nota di riservatezza\b"
    r")",
    re.IGNORECASE,
)

_AI_SIGNATURE_START_RE = re.compile(
    r"^\s*(?:"
    r"cordiali saluti|"
    r"distinti saluti|"
    r"un saluto|"
    r"saluti|"
    r"saludos|"
    r"un saludo|"
    r"atentamente|"
    r"best regards|"
    r"kind regards|"
    r"regards|"
    r"thanks|"
    r"thank you"
    r"|grazie"
    r"|good luck"
    r"|sincerely"
    r"|cheers"
    r"|pozdrawiam"
    r")\s*,?\s*$",
    re.IGNORECASE,
)


def _meaningful_line_count(lines: list[str]) -> int:
    return sum(1 for line in lines if line.strip())


def _signature_start_before_footer(lines: list[str], footer_index: int) -> int:
    """Return the start of a contact-card-like block before a legal footer."""
    for index in range(footer_index - 1, -1, -1):
        visible = lines[index].strip().strip("*_` ")
        if _AI_SIGNATURE_START_RE.match(visible) and _meaningful_line_count(lines[:index]) >= 2:
            return index

    contact_patterns = (
        re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}"),
        re.compile(r"\b(?:tel|phone|fax|mobile|cell)\b", re.IGNORECASE),
        re.compile(r"\+?\d[\d .()/-]{7,}"),
        re.compile(r"\b(?:www\.|https?://)", re.IGNORECASE),
    )
    window_start = max(0, footer_index - 32)
    window = lines[window_start:footer_index]
    contact_lines = [
        window_start + index
        for index, line in enumerate(window)
        if any(pattern.search(line) for pattern in contact_patterns)
    ]
    if len(contact_lines) < 2:
        return footer_index

    # HTML-to-text conversion may insert blank lines between each contact-card
    # row.  Start at the preceding paragraph, not at the first phone/email row,
    # so the person's name and title disappear with the signature too.
    paragraph_breaks = [index for index in range(contact_lines[0] - 1, window_start - 1, -1) if not lines[index].strip()]
    if paragraph_breaks:
        return paragraph_breaks[min(3, len(paragraph_breaks) - 1)] + 1
    # Some HTML alternatives flatten the card into one uninterrupted run. In
    # that case remove a short lead-in too (name, role and company), while
    # retaining the preceding operational sentence or call-to-action.
    return max(window_start, contact_lines[0] - 6)


def _trim_ai_tail(lines: list[str]) -> tuple[list[str], int]:
    """Remove signatures, legal footers and unsubscribe blocks from the AI body."""
    end = len(lines)
    while end > 0 and not lines[end - 1].strip():
        end -= 1
    lines = lines[:end]

    # A legal notice can be followed by a second, local mail-client signature
    # (for example when someone forwards the message).  Find it in document
    # order, rather than only at the physical end of the text.
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        before = lines[:index]
        visible = stripped.strip("*_` ")
        if not (_AI_TAIL_BOILERPLATE_RE.match(visible) and _meaningful_line_count(before) >= 1):
            continue
        # Consecutive translated legal notices are one footer.  Begin at the
        # first one, otherwise an English copy would leave its Polish (or
        # other-language) counterpart in the semantic input.
        footer_start = index
        probe = index - 1
        while probe >= 0:
            if not lines[probe].strip():
                probe -= 1
                continue
            prior_visible = lines[probe].strip().strip("*_` ")
            if not _AI_TAIL_BOILERPLATE_RE.match(prior_visible):
                break
            footer_start = probe
            probe -= 1
        cutoff = _signature_start_before_footer(lines, footer_start)
        return lines[:cutoff], len(lines) - cutoff

    # With no legal footer, a tail sign-off is still removable. Search from
    # the end because forwarded threads can contain a sign-off per turn.
    for index in range(len(lines) - 1, -1, -1):
        line = lines[index]
        stripped = line.strip()
        if not stripped:
            continue
        before = lines[:index]
        # Plain alternatives frequently preserve HTML emphasis around a sign-off
        # (for example ``*Saludos,*``).  Compare the visible text, not its
        # presentation markers, so footer links do not become fake calls to
        # action for the AI.
        visible = stripped.strip("*_` ")
        if _AI_SIGNATURE_START_RE.match(visible) and _meaningful_line_count(before) >= 2:
            return before, len(lines) - index
    return lines, 0


def _finalize_body_ai(
    lines: list[str],
    removed_quotes: int = 0,
    removed_headers: int = 0,
    removed_tail_before: int = 0,
) -> tuple[str, int, int, int]:
    selected, removed_tail = _trim_ai_tail(lines)
    return compact_ai_body(_join_significant(selected)), removed_quotes, removed_headers, removed_tail_before + removed_tail


def _normalize_lines(text: str) -> list[str]:
    text = (text or "").replace("\r\n", "\n").replace("\r", "\n")
    return [line.rstrip() for line in text.split("\n")]


def _join_significant(lines: list[str]) -> str:
    text = "\n".join(lines).strip()
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _remove_quoted_lines(lines: list[str]) -> tuple[list[str], int]:
    kept: list[str] = []
    removed = 0
    for line in lines:
        if line.lstrip().startswith(">"):
            removed += 1
            continue
        kept.append(line)
    return kept, removed


def _strip_forwarded_headers(lines: list[str]) -> tuple[list[str], int]:
    stripped = 0
    index = 0
    while index < len(lines):
        line = lines[index].strip()
        if not line:
            stripped += 1
            index += 1
            continue
        if _FORWARDED_HEADER_RE.match(line):
            stripped += 1
            index += 1
            continue
        break
    return lines[index:], stripped


def _latest_forwarded_turns(lines: list[str], max_boundaries: int = 3) -> tuple[list[str], int]:
    """Keep the newest few turns of a forwarded conversation for AI classification.

    A forwarded mailbox thread can contain months of legitimate correspondence.
    That history is still retained in ``body_clean`` for the analyst, but sending
    it unchanged to a classifier dilutes the latest instruction.  Retaining three
    reply boundaries preserves the immediately preceding request and any stated
    change (for example newly updated payment details), without sending months
    of unrelated history. Reply delimiters are structural email markers, not
    language- or sender-specific rules.
    """
    boundaries = 0
    for index, line in enumerate(lines):
        if index and (
            _REPLY_MARKER_RE.match(line)
            or _FORWARDED_THREAD_REPLY_RE.match(line)
        ):
            boundaries += 1
            if boundaries >= max_boundaries:
                return lines[:index], len(lines[index:])
    return lines, 0


def _remove_interturn_tail_noise(lines: list[str]) -> tuple[list[str], int]:
    """Drop signature/footer text at the end of each retained forwarded turn."""
    boundaries = [
        index
        for index, line in enumerate(lines)
        if index and (_REPLY_MARKER_RE.match(line) or _FORWARDED_THREAD_REPLY_RE.match(line))
    ]
    if not boundaries:
        return lines, 0

    output: list[str] = []
    removed = 0
    start = 0
    for boundary in boundaries:
        segment, count = _trim_ai_tail(lines[start:boundary])
        output.extend(segment)
        output.append(lines[boundary])
        removed += count
        start = boundary + 1
    output.extend(lines[start:])
    return output, removed


def _looks_like_outlook_reply_header(lines: list[str], index: int) -> bool:
    if not _OUTLOOK_REPLY_FROM_RE.match(lines[index]):
        return False

    nearby_headers = 0
    for line in lines[index + 1:index + 7]:
        stripped = line.strip()
        if not stripped:
            continue
        if _OUTLOOK_REPLY_HEADER_RE.match(stripped):
            nearby_headers += 1
            continue
        if nearby_headers:
            break

    return nearby_headers >= 2


def _looks_like_thread_separator(lines: list[str], index: int) -> bool:
    if not _THREAD_SEPARATOR_RE.match(lines[index]):
        return False
    following = [line.strip() for line in lines[index + 1:index + 10] if line.strip()]
    named_headers = sum(1 for line in following if _THREAD_SEPARATOR_HEADER_RE.match(line))
    generic_headers = sum(1 for line in following if _GENERIC_HEADER_LINE_RE.match(line))
    return named_headers >= 2 or generic_headers >= 2


def select_body_for_ai(body_clean: str) -> dict:
    """
    Returns a BERT-focused body while preserving metadata about the selection.

    - Forwarded emails: use the forwarded payload after the separator.
    - Replies: use the new message before the quoted conversation.
    - Normal emails: use the cleaned body, without quoted ``>`` lines.
    """
    lines = _normalize_lines(body_clean)
    if not any(line.strip() for line in lines):
        return {
            "body_ai": "",
            "body_context": "empty",
            "body_ai_removed_quoted_lines": 0,
            "body_ai_removed_header_lines": 0,
            "body_ai_removed_tail_lines": 0,
        }

    for index, line in enumerate(lines):
        if _FORWARD_MARKER_RE.match(line):
            selected, removed_headers = _strip_forwarded_headers(lines[index + 1:])
            selected, removed_quotes = _remove_quoted_lines(selected)
            selected, removed_thread = _latest_forwarded_turns(selected)
            selected, removed_interturn_tail = _remove_interturn_tail_noise(selected)
            body_ai, removed_quotes, removed_headers, removed_tail = _finalize_body_ai(
                selected,
                removed_quotes,
                removed_headers + removed_thread,
                removed_interturn_tail,
            )
            return {
                "body_ai": body_ai,
                "body_context": "forwarded",
                "body_ai_removed_quoted_lines": removed_quotes,
                "body_ai_removed_header_lines": removed_headers,
                "body_ai_removed_tail_lines": removed_tail,
            }

    for index, line in enumerate(lines):
        if _REPLY_MARKER_RE.match(line):
            selected, removed_quotes = _remove_quoted_lines(lines[:index])
            body_ai, removed_quotes, removed_headers, removed_tail = _finalize_body_ai(
                selected, removed_quotes, 0
            )
            if body_ai:
                return {
                    "body_ai": body_ai,
                    "body_context": "reply",
                    "body_ai_removed_quoted_lines": removed_quotes,
                    "body_ai_removed_header_lines": removed_headers,
                    "body_ai_removed_tail_lines": removed_tail,
                }
            break

    for index, line in enumerate(lines):
        if _looks_like_outlook_reply_header(lines, index):
            selected, removed_quotes = _remove_quoted_lines(lines[:index])
            body_ai, removed_quotes, removed_headers, removed_tail = _finalize_body_ai(
                selected, removed_quotes, len(lines[index:])
            )
            if body_ai:
                return {
                    "body_ai": body_ai,
                    "body_context": "reply",
                    "body_ai_removed_quoted_lines": removed_quotes,
                    "body_ai_removed_header_lines": removed_headers,
                    "body_ai_removed_tail_lines": removed_tail,
                }
            break

    for index, line in enumerate(lines):
        if _looks_like_thread_separator(lines, index):
            selected, removed_quotes = _remove_quoted_lines(lines[:index])
            body_ai, removed_quotes, removed_headers, removed_tail = _finalize_body_ai(
                selected, removed_quotes, len(lines[index:])
            )
            if body_ai:
                return {
                    "body_ai": body_ai,
                    "body_context": "reply",
                    "body_ai_removed_quoted_lines": removed_quotes,
                    "body_ai_removed_header_lines": removed_headers,
                    "body_ai_removed_tail_lines": removed_tail,
                }
            break

    selected, removed_quotes = _remove_quoted_lines(lines)
    body_ai, removed_quotes, removed_headers, removed_tail = _finalize_body_ai(
        selected, removed_quotes, 0
    )
    return {
        "body_ai": body_ai,
        "body_context": "normal",
        "body_ai_removed_quoted_lines": removed_quotes,
        "body_ai_removed_header_lines": removed_headers,
        "body_ai_removed_tail_lines": removed_tail,
    }
