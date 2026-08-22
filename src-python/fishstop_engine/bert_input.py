"""Shared BERT text preprocessing for training and inference."""

import re
import unicodedata

from fishstop_engine.ai_input import compact_ai_body


def normalize_bert_text(text: str) -> str:
    if not text:
        return ""
    text = unicodedata.normalize("NFKC", str(text))
    text = "".join(
        char if char in "\n\t" or unicodedata.category(char) != "Cc" else " "
        for char in text
    )
    if re.search(r"<[a-zA-Z][^>]*>", text):
        try:
            from fishstop_engine.analyzer.html_utils import strip_html
        except Exception:
            text = re.sub(r"<[^>]+>", " ", text)
        else:
            text = strip_html(text)
    text = text.lower()
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def prepare_bert_input(subject: str, body: str) -> str:
    """Prepare body-only model input.

    ``subject`` remains in the signature for compatibility with existing
    dataset/runtime callers, but is deliberately not sent to BERT.
    """

    del subject
    return normalize_bert_text(
        compact_ai_body(body)
    )
