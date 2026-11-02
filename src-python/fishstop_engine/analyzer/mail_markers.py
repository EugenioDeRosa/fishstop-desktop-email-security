"""Localized structural markers written by mail clients into message bodies.

Mail clients translate both the forwarding separator and the labels of the
embedded header block (Gmail: ``---------- Messaggio inoltrato ---------``,
Apple Mail: ``Début du message réexpédié :``, Thunderbird:
``-------- Weitergeleitete Nachricht --------``).  Every module that splits a
body into conversation layers must recognise the same set, otherwise one layer
treats a forward as a reply and drops the forwarded message.
"""

import re

# Labels that introduce a forwarded message.  Reply labels such as
# "Original message" are intentionally absent: there the new text is above.
FORWARD_LABELS = (
    # English (Gmail, Thunderbird, Apple Mail)
    r"forwarded message",
    r"begin forwarded message",
    # Italian
    r"messaggio inoltrato",
    r"inizio (?:del )?messaggio inoltrato",
    # Spanish
    r"mensaje reenviado",
    r"(?:inicio|comienzo) del mensaje reenviado",
    # Portuguese (BR and PT)
    r"mensagem (?:re)?encaminhada",
    r"(?:in[ií]cio|come[cç]o) da mensagem (?:re)?encaminhada",
    # French
    r"message transf[ée]r[ée]",
    r"d[ée]but du message (?:transf[ée]r[ée]|r[ée]exp[ée]di[ée])",
    # German
    r"weitergeleitete nachricht",
    r"anfang der weitergeleiteten nachricht",
    # Dutch
    r"doorgestuurd bericht",
    r"begin (?:van (?:het )?)?doorgestuurde? bericht",
)

FORWARD_LABEL_PATTERN = "(?:" + "|".join(FORWARD_LABELS) + ")"

# A whole line holding a forward label, optionally framed by dash/underscore
# runs and optionally followed by a colon (Apple Mail).
FORWARD_MARKER_RE = re.compile(
    r"^\s*(?:[-_=*]{2,}\s*)?" + FORWARD_LABEL_PATTERN + r"(?:\s*[-_=*]{2,})?\s*:?\s*[-_=*]*\s*$",
    re.IGNORECASE,
)

# Header labels of an embedded (forwarded or quoted) header block, mapped to
# a canonical field.  Longer labels must be tried first in the alternation.
HEADER_LABEL_KEYS = {
    # sender
    "from": "from", "da": "from", "de": "from", "von": "from", "van": "from",
    # date
    "sent": "date", "date": "date", "data": "date",
    "inviato": "date", "inviato il": "date",
    "fecha": "date", "enviado": "date", "enviado el": "date", "enviada": "date", "enviada em": "date",
    "envoyé": "date", "envoyé le": "date",
    "datum": "date", "gesendet": "date", "verzonden": "date",
    # recipients
    "to": "to", "a": "to", "para": "to", "à": "to", "an": "to", "aan": "to",
    "cc": "cc", "copia": "cc", "kopie": "cc",
    "bcc": "bcc", "ccn": "bcc", "cco": "bcc", "copia nascosta": "bcc",
    # subject
    "subject": "subject", "oggetto": "subject", "asunto": "subject", "assunto": "subject",
    "objet": "subject", "sujet": "subject", "betreff": "subject", "onderwerp": "subject",
}

SENDER_HEADER_LABELS = tuple(label for label, key in HEADER_LABEL_KEYS.items() if key == "from")
NON_SENDER_HEADER_LABELS = tuple(label for label, key in HEADER_LABEL_KEYS.items() if key != "from")


def label_alternation(labels) -> str:
    """Regex alternation with the longest labels first and spaces made flexible."""
    ordered = sorted(set(labels), key=len, reverse=True)
    return "(?:" + "|".join(re.escape(label).replace(r"\ ", r"\s+") for label in ordered) + ")"


HEADER_LABEL_PATTERN = label_alternation(HEADER_LABEL_KEYS)
SENDER_HEADER_LABEL_PATTERN = label_alternation(SENDER_HEADER_LABELS)
NON_SENDER_HEADER_LABEL_PATTERN = label_alternation(NON_SENDER_HEADER_LABELS)


def header_key(label: str) -> str:
    """Canonical field for a matched header label (whitespace-insensitive)."""
    return HEADER_LABEL_KEYS[re.sub(r"\s+", " ", label.strip()).casefold()]
