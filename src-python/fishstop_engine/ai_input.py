"""Normalized email body input shared by the AI models."""

import re
import unicodedata


_HTML_TAG_RE = re.compile(
    r"</?[A-Za-z][A-Za-z0-9:-]*(?:\s[^>]*)?/?>",
    re.DOTALL,
)

def compact_ai_body(body: str) -> str:
    """Return normalized visible body text without replacing its values."""

    if not body:
        return ""

    text = unicodedata.normalize("NFKC", str(body))
    if _HTML_TAG_RE.search(text):
        try:
            from fishstop_engine.analyzer.html_utils import strip_html
        except Exception:
            text = re.sub(r"<[^>]+>", " ", text)
        else:
            text = strip_html(text)

    text = "".join(
        char if char in "\n\t" or unicodedata.category(char) != "Cc" else " "
        for char in text
    )
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r" *\n *", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()
