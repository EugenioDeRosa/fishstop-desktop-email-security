"""
analyzer/link_extractor.py - URL extraction from email bodies.

Espone:
  - extract_links(body_plain, body_html) : lista di link strutturati

Handles plain text and HTML while preserving visible link text.
"""

import re
from urllib.parse import parse_qsl, unquote, urlparse

try:
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover - fallback per ambienti minimali
    BeautifulSoup = None

from .html_utils import strip_html
from .lookalike import is_ip_url
from fishstop_engine.analysis_limits import EmailAnalysisLimitError, MAX_LINKS


_URL_RE = re.compile(
    r"""(?i)\b(?:https?://|ftp://|www\.)"""
    r"""(?:[^\s/@]+(?::[^\s/@]*)?@)?"""
    r"""(?:[^\W_][\w\-]*\.)+[^\W_]{2,}"""
    r"""(?::\d{1,5})?"""
    r"""(?:/[^\s"'<>\]\)]*)?""",
    re.VERBOSE,
)
_BARE_DOMAIN_RE = re.compile(
    r"""(?i)(?<![@\w.-])(?:[^\W_][\w\-]*\.)+[^\W_]{2,}(?![\w.-])""",
    re.VERBOSE,
)
_EMAIL_RE = re.compile(r"[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}", re.IGNORECASE)
_HREF_RE = re.compile(r"""href\s*=\s*["']?((?:https?://|mailto:)[^\s"'<>]+)""", re.IGNORECASE)
_ANCHOR_RE = re.compile(
    r"""<a\b[^>]*href\s*=\s*["']?(?P<href>(?:https?://|mailto:)[^\s"'<>]+)["']?[^>]*>(?P<text>.*?)</a>""",
    re.IGNORECASE | re.DOTALL,
)
_WEB_SCHEMES = {"http", "https"}
_ACTION_SCHEMES = {*_WEB_SCHEMES, "mailto"}
_BRACKETED_PLACEHOLDER_USERINFO_RE = re.compile(
    r"^(?P<scheme>https?://)\[[^\]/?#@]*\]@(?P<destination>.+)$",
    re.IGNORECASE,
)
_NON_ACTION_CONTAINER_MARKER_RE = re.compile(
    r"(?:^|[-_])(?:email[-_]?signature|mail[-_]?signature|signature|footer)(?:$|[-_])",
    re.IGNORECASE,
)
_REDIRECT_PARAM_NAMES = {
    "url", "u", "uri", "target", "to", "dest", "destination", "redirect",
    "redirect_uri", "return", "returnurl", "next", "continue", "goto", "link",
}
_NESTED_WEB_URL_RE = re.compile(r"https?://[^\s<>()\[\]{}\"']+", re.IGNORECASE)
_BUTTON_CLASS_RE = re.compile(r"(?:^|[-_\s])(?:btn|button|cta|call[-_ ]?to[-_ ]?action)(?:$|[-_\s])", re.IGNORECASE)
_BUTTON_URL_RE = re.compile(
    r"(?:window\s*\.\s*)?(?:location(?:\s*\.\s*href)?|open)\s*\(?(?:\s*=\s*)?[\"'](?P<url>https?://[^\"'\s<>]+)",
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
        return parsed.scheme.lower() in _ACTION_SCHEMES
    return value.lower().startswith("www.") or bool(_BARE_DOMAIN_RE.fullmatch(value.rstrip(".,;)")))


def _contains_non_ascii(value: str) -> bool:
    return any(ord(ch) > 127 for ch in value or "")


def _with_scheme(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    if value.lower().startswith("mailto:"):
        return value
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
        query=unquote(parsed.query or ""),
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


def _decode_repeated(value: str) -> str:
    decoded = value
    for _ in range(3):
        candidate = unquote(decoded)
        if candidate == decoded:
            break
        decoded = candidate
    return decoded


def _url_intelligence(parsed, original: str, host: str) -> dict:
    """Inspect URL structure only; nested destinations are never requested."""
    try:
        port = parsed.port
    except ValueError:
        port = None
    scheme = (parsed.scheme or "").lower()
    standard_port = 80 if scheme == "http" else 443 if scheme == "https" else None
    has_userinfo = bool(parsed.username is not None or parsed.password is not None)
    has_credentials = bool(parsed.username or parsed.password)
    redirect_targets: list[str] = []
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        if name.lower() not in _REDIRECT_PARAM_NAMES:
            continue
        decoded = _decode_repeated(value)
        candidates = _NESTED_WEB_URL_RE.findall(decoded)
        if not candidates and decoded.lower().startswith(("http%3a", "https%3a")):
            candidates = _NESTED_WEB_URL_RE.findall(_decode_repeated(decoded))
        for candidate in candidates:
            if candidate not in redirect_targets:
                redirect_targets.append(candidate[:500])
    redirect_hosts = []
    for target in redirect_targets:
        target_parsed = _safe_urlparse(target)
        target_host = (target_parsed.hostname or "").lower() if target_parsed else ""
        if target_host and target_host not in redirect_hosts:
            redirect_hosts.append(target_host)
    return {
        "has_userinfo": has_userinfo,
        "has_credentials": has_credentials,
        "nonstandard_port": port is not None and port != standard_port,
        "port": port,
        "nested_redirect_count": len(redirect_targets),
        "redirect_targets": redirect_targets[:5],
        "redirect_hosts": redirect_hosts[:5],
        "unicode_path_or_query": (
            _contains_non_ascii(parsed.path)
            or _contains_non_ascii(parsed.query)
            or _contains_non_ascii(_decode_repeated(parsed.path))
            or _contains_non_ascii(_decode_repeated(parsed.query))
        ),
        "unicode_host": _contains_non_ascii(host),
        "raw_at_sign": "@" in original.split("?", 1)[0],
    }


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


def _html_anchor_is_call_to_action(anchor) -> bool:
    """Recognize button-like HTML anchors structurally, not by their wording."""
    if anchor.find(["button", "input"]) is not None:
        return True
    if str(anchor.get("role") or "").strip().lower() == "button":
        return True
    markers = " ".join([
        str(anchor.get("id") or ""),
        " ".join(str(value) for value in (anchor.get("class") or [])),
        str(anchor.get("name") or ""),
    ])
    if _BUTTON_CLASS_RE.search(markers):
        return True
    for node in [anchor, *list(anchor.descendants)]:
        attrs = getattr(node, "attrs", None)
        if attrs is None:
            continue
        style = str(node.get("style") or "").lower().replace(" ", "")
        if "padding:" in style and (
            "background:" in style
            or "background-color:" in style
            or "border:" in style
        ):
            return True
    return False


def extract_links(
    body_plain: str,
    body_html: str,
    *,
    embedded_urls: list[dict] | None = None,
    max_links: int = MAX_LINKS,
) -> list[dict]:
    """
    Extracts all links from the email body.

    Besides the real destination, HTML links keep the visible text
    and are flagged when the text shows a different domain than the href destination.
    """
    seen: set[str] = set()
    seen_signature_destinations: set[str] = set()
    links: list[dict] = []

    def _add(
        url: str,
        display: str,
        source: str,
        *,
        role: str = "body_action",
        html_call_to_action: bool = False,
    ) -> None:
        raw_url = (url or "").strip().rstrip(".,;)")
        if not _is_web_url_candidate(raw_url):
            return
        url = _normalize_malformed_userinfo(_with_scheme(raw_url))
        dedupe_key = _url_dedupe_key(url)
        if not url:
            return
        if dedupe_key in seen:
            if html_call_to_action:
                for existing in links:
                    if _url_dedupe_key(existing.get("url") or "") == dedupe_key:
                        existing["html_call_to_action"] = True
                        if source == "html_button":
                            existing["source"] = source
                        break
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
        if scheme == "mailto":
            address = parsed.path.split("?", 1)[0].strip()
            if not _EMAIL_RE.fullmatch(address):
                return
            host = address.rsplit("@", 1)[-1].lower()
        elif scheme not in _WEB_SCHEMES or not host:
            return
        seen.add(dedupe_key)

        display_text = (display or "").strip()
        display_url, display_host = _extract_display_destination(display_text)
        # A mailto label is often just a display name or the local part of an
        # email address (e.g. ``eugenio.derosa``). It is not a web
        # destination and must never be treated as a masked-domain mismatch.
        if scheme == "mailto":
            display_url, display_host = "", ""
        is_shortener, shortener_reason = _possible_shortener(host, parsed.path) if scheme in _WEB_SCHEMES else (False, "")
        intelligence = _url_intelligence(parsed, url, host) if scheme in _WEB_SCHEMES else {
            "has_userinfo": False, "has_credentials": False, "nonstandard_port": False,
            "port": None, "nested_redirect_count": 0, "redirect_targets": [], "redirect_hosts": [],
            "unicode_path_or_query": False, "unicode_host": False, "raw_at_sign": False,
        }
        redirect_hosts = intelligence.get("redirect_hosts") or []
        # Signature services can wrap a legitimate destination in a signed
        # redirect. When the visible domain agrees with the final embedded
        # destination, the wrapper is not a masked-link indicator.
        resolved_display_destination = bool(
            display_host
            and redirect_hosts
            and _same_registered_domain(display_host, redirect_hosts[-1])
        )
        signature_tracking_redirect = bool(
            role == "signature"
            and intelligence.get("nested_redirect_count")
            and (not display_host or resolved_display_destination)
        )
        if signature_tracking_redirect:
            # Corporate signatures are commonly repeated in quoted replies.
            # Keep one transparent record for each final destination instead
            # of filling the report with identical tracking wrappers.
            signature_key = _registered_domain(redirect_hosts[-1])
            if signature_key in seen_signature_destinations:
                return
            seen_signature_destinations.add(signature_key)

        links.append({
            "url": url,
            "display_text": display_text[:120],
            "display_url": display_url,
            "display_host": display_host,
            "display_mismatch": bool(
                scheme in _WEB_SCHEMES
                and display_host
                and host
                and not _same_registered_domain(display_host, host)
                and not resolved_display_destination
            ),
            "host": host,
            "scheme": scheme,
            "source": source,
            "role": role,
            "actionable": role == "body_action",
            "html_call_to_action": html_call_to_action,
            "resolved_display_destination": resolved_display_destination,
            "signature_tracking_redirect": signature_tracking_redirect,
            "is_ip": is_ip_url(host),
            "is_possible_shortener": is_shortener,
            "shortener_reason": shortener_reason,
            **intelligence,
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
                        html_call_to_action=_html_anchor_is_call_to_action(anchor),
                    )
            for control in soup.find_all(["button", "input"], limit=max_links + 1):
                onclick = str(control.get("onclick") or "")
                data_target = str(control.get("data-href") or control.get("data-url") or "")
                match = _BUTTON_URL_RE.search(onclick)
                target = data_target or (match.group("url") if match else "")
                if target:
                    _add(
                        target,
                        control.get_text(" ", strip=True) or str(control.get("value") or ""),
                        "html_button",
                        html_call_to_action=True,
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

    for item in embedded_urls or []:
        _add(
            str(item.get("url") or ""),
            str(item.get("label") or ""),
            str(item.get("source") or "attachment"),
            role="body_action",
        )

    return links
