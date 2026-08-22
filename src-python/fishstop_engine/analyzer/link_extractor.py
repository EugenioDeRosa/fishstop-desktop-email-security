"""
analyzer/link_extractor.py - URL extraction from email bodies.

Espone:
  - extract_links(body_plain, body_html) : lista di link strutturati

Handles plain text and HTML while preserving visible link text.
"""

import re
from urllib.parse import urlparse

try:
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover - fallback per ambienti minimali
    BeautifulSoup = None

from .html_utils import strip_html
from .lookalike import is_ip_url
from fishstop_engine.analysis_limits import EmailAnalysisLimitError, MAX_LINKS


_URL_RE = re.compile(
    r"""(?i)\b(?:https?://|ftp://|www\.)"""
    r"""(?:[^\W_][\w\-]*\.)+[^\W_]{2,}"""
    r"""(?::\d{1,5})?"""
    r"""(?:/[^\s"'<>\]\)]*)?""",
    re.VERBOSE,
)
_BARE_DOMAIN_RE = re.compile(
    r"""(?i)(?<![@\w.-])(?:[^\W_][\w\-]*\.)+[^\W_]{2,}(?![\w.-])""",
    re.VERBOSE,
)
_HREF_RE = re.compile(r"""href\s*=\s*["']?(https?://[^\s"'<>]+)""", re.IGNORECASE)
_ANCHOR_RE = re.compile(
    r"""<a\b[^>]*href\s*=\s*["']?(?P<href>https?://[^\s"'<>]+)["']?[^>]*>(?P<text>.*?)</a>""",
    re.IGNORECASE | re.DOTALL,
)
_WEB_SCHEMES = {"http", "https"}
_BRACKETED_PLACEHOLDER_USERINFO_RE = re.compile(
    r"^(?P<scheme>https?://)\[[^\]/?#@]*\]@(?P<destination>.+)$",
    re.IGNORECASE,
)
_NON_ACTION_CONTAINER_MARKER_RE = re.compile(
    r"(?:^|[-_])(?:email[-_]?signature|mail[-_]?signature|signature|footer)(?:$|[-_])",
    re.IGNORECASE,
)


def _normalize_malformed_userinfo(value: str) -> str:
    """Recover the destination from URLs such as https://[token]@example.com/."""
    value = (value or "").strip()
    match = _BRACKETED_PLACEHOLDER_USERINFO_RE.match(value)
    if not match:
        return value
    return f"{match.group('scheme')}{match.group('destination')}"


def _safe_urlparse(value: str):
    """Parse untrusted email URLs without allowing malformed brackets to abort analysis."""
    try:
        return urlparse(_normalize_malformed_userinfo(value))
    except ValueError:
        return None


def _is_web_url_candidate(value: str) -> bool:
    value = (value or "").strip()
    if not value:
        return False
    parsed = _safe_urlparse(value)
    if parsed is None:
        return False
    if parsed.scheme:
        return parsed.scheme.lower() in _WEB_SCHEMES
    return value.lower().startswith("www.") or bool(_BARE_DOMAIN_RE.fullmatch(value.rstrip(".,;)")))


def _contains_non_ascii(value: str) -> bool:
    return any(ord(ch) > 127 for ch in value or "")


def _with_scheme(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    if value.startswith("//"):
        return "https:" + value
    if value.lower().startswith("www.") or "://" not in value:
        return "http://" + value
    return value


def _url_dedupe_key(value: str) -> str:
    parsed = _safe_urlparse(value)
    if parsed is None:
        return value
    return parsed._replace(
        scheme=parsed.scheme.lower(),
        netloc=parsed.netloc.lower(),
        path=parsed.path or "/",
    ).geturl()


def _registered_domain(host: str) -> str:
    parts = (host or "").lower().rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host or ""


def _extract_display_destination(display: str) -> tuple[str, str]:
    text = display or ""
    match = _URL_RE.search(text) or _BARE_DOMAIN_RE.search(text)
    if not match:
        return "", ""
    candidate = _with_scheme(match.group(0).strip().rstrip(".,;)"))
    try:
        parsed = _safe_urlparse(candidate)
    except Exception:
        return "", ""
    if parsed is None:
        return "", ""
    return candidate, (parsed.hostname or "").lower()


def _same_registered_domain(left: str, right: str) -> bool:
    return bool(left and right and _registered_domain(left) == _registered_domain(right))


def _possible_shortener(host: str, path: str) -> tuple[bool, str]:
    labels = (host or "").split(".")
    sld = labels[-2] if len(labels) >= 2 else host
    token = (path or "").strip("/").split("/", 1)[0]
    compact_host = len(sld) <= 5 and len(host or "") <= 12
    compact_token = 4 <= len(token) <= 12 and bool(re.fullmatch(r"[A-Za-z0-9_-]+", token))
    mixed_token = any(ch.isalpha() for ch in token) and any(ch.isdigit() for ch in token)

    if compact_host and compact_token:
        reason = "compact host with short opaque path"
        if mixed_token:
            reason += " containing letters and digits"
        return True, reason
    return False, ""


def _html_node_has_non_action_marker(node) -> bool:
    attrs = getattr(node, "attrs", None)
    if attrs is None:
        return False
    if str(getattr(node, "name", "") or "").lower() == "footer":
        return True
    marker_values = [
        str(node.get("id") or ""),
        *[str(value) for value in (node.get("class") or [])],
    ]
    return any(
        _NON_ACTION_CONTAINER_MARKER_RE.search(value)
        for value in marker_values
    )


def _html_link_role(anchor) -> str:
    """Classify links using HTML structure, never visible-language keywords."""
    rel_values = {
        str(value).strip().lower()
        for value in (anchor.get("rel") or [])
    }
    if "unsubscribe" in rel_values:
        return "unsubscribe"
    for node in [anchor, *list(anchor.parents)]:
        attrs = getattr(node, "attrs", None)
        if attrs is None:
            continue
        if _html_node_has_non_action_marker(node):
            return "signature"
    return "body_action"


def extract_links(
    body_plain: str,
    body_html: str,
    *,
    max_links: int = MAX_LINKS,
) -> list[dict]:
    """
    Extracts all links from the email body.

    Besides the real destination, HTML links keep the visible text
    and are flagged when the text shows a different domain than the href destination.
    """
    seen: set[str] = set()
    links: list[dict] = []

    def _add(
        url: str,
        display: str,
        source: str,
        *,
        role: str = "body_action",
    ) -> None:
        raw_url = (url or "").strip().rstrip(".,;)")
        if not _is_web_url_candidate(raw_url):
            return
        url = _normalize_malformed_userinfo(_with_scheme(raw_url))
        dedupe_key = _url_dedupe_key(url)
        if not url or dedupe_key in seen:
            return
        if len(links) >= max_links:
            raise EmailAnalysisLimitError(
                f"Email contains more than {max_links} unique links."
            )
        parsed = _safe_urlparse(url)
        if parsed is None:
            return
        host = (parsed.hostname or "").lower()
        scheme = parsed.scheme.lower()
        if scheme not in _WEB_SCHEMES or not host:
            return
        seen.add(dedupe_key)

        display_text = (display or "").strip()
        display_url, display_host = _extract_display_destination(display_text)
        is_shortener, shortener_reason = _possible_shortener(host, parsed.path)

        links.append({
            "url": url,
            "display_text": display_text[:120],
            "display_url": display_url,
            "display_host": display_host,
            "display_mismatch": bool(display_host and host and not _same_registered_domain(display_host, host)),
            "host": host,
            "scheme": scheme,
            "source": source,
            "role": role,
            "actionable": role == "body_action",
            "is_ip": is_ip_url(host),
            "is_possible_shortener": is_shortener,
            "shortener_reason": shortener_reason,
        })

    def _add_unicode_bare_domains(text: str, source: str) -> None:
        text = text or ""
        for m in _BARE_DOMAIN_RE.finditer(text):
            prefix = text[max(0, m.start() - 8):m.start()].lower()
            if prefix.endswith(("http://", "https://", "ftp://")):
                continue
            domain = m.group(0)
            if _contains_non_ascii(domain):
                _add(domain, "", source)

    if body_html:
        if BeautifulSoup is not None:
            soup = BeautifulSoup(body_html, "html.parser")
            for anchor in soup.find_all("a", limit=max_links + 1):
                href = anchor.get("href")
                if href:
                    _add(
                        href,
                        anchor.get_text(" ", strip=True),
                        "html_href",
                        role=_html_link_role(anchor),
                    )
            for tag in list(soup.find_all(True)):
                if tag.parent is not None and _html_node_has_non_action_marker(tag):
                    tag.decompose()
        else:
            matched_spans = []
            for m in _ANCHOR_RE.finditer(body_html):
                matched_spans.append(m.span())
                _add(m.group("href"), strip_html(m.group("text")), "html_href")
            for m in _HREF_RE.finditer(body_html):
                if any(start <= m.start() < end for start, end in matched_spans):
                    continue
                _add(m.group(1), "", "html_href")

        html_stripped = strip_html(str(soup)) if BeautifulSoup is not None else strip_html(body_html)
        for m in _URL_RE.finditer(html_stripped):
            _add(m.group(0), "", "html_text")
        _add_unicode_bare_domains(html_stripped, "html_domain")

    if body_plain:
        for m in _URL_RE.finditer(body_plain):
            _add(m.group(0), "", "plain_text")
        _add_unicode_bare_domains(body_plain, "plain_domain")

    return links
