"""
analyzer/html_utils.py - Pulizia e normalizzazione HTML per l'analisi email.

Espone:
  - strip_html(html)  : converts raw HTML into clean text

Gli attaccanti inseriscono tag o commenti HTML invisibili in mezzo alle parole
(es. Pa<!-- x -->ypal) per aggirare i filtri basati su stringhe. Senza
stripping, BERT riceve token sporchi e le regex sui link non trovano le URL reali.
"""

import html as html_lib
import re

try:
    from bs4 import BeautifulSoup
    _BS4_AVAILABLE = True
except ImportError:
    _BS4_AVAILABLE = False


_ACTIVE_PREVIEW_TAGS = {
    "script",
    "iframe",
    "object",
    "embed",
    "form",
    "input",
    "button",
    "meta",
    "base",
    "link",
    "svg",
    "math",
}

_URL_PREVIEW_ATTRS = {
    "href",
    "src",
    "srcset",
    "xlink:href",
    "action",
    "formaction",
    "poster",
    "background",
    "dynsrc",
    "lowsrc",
    "srcdoc",
}

_DANGEROUS_STYLE_RE = re.compile(
    r"(?is)(?:expression\s*\(|url\s*\(|@import|behavior\s*:|-moz-binding\s*:|javascript\s*:|vbscript\s*:|data\s:)"
)

_UTF7_SHIFT_SEQUENCE_RE = re.compile(r"\+[A-Za-z0-9/]{3,}-")
_HTML_TAG_RE = re.compile(
    r"(?is)<\s*/?\s*(?:html|head|body|table|tbody|tr|td|div|span|p|br|a|img|style|strong|ul|li)\b"
)

_BLOCK_TEXT_TAGS = {
    "address", "article", "aside", "blockquote", "dd", "div", "dl", "dt",
    "figcaption", "figure", "footer", "h1", "h2", "h3", "h4", "h5", "h6",
    "header", "hr", "li", "main", "nav", "ol", "p", "pre", "section",
    "table", "tbody", "td", "tfoot", "th", "thead", "tr", "ul",
}
_HIDDEN_STYLE_RE = re.compile(
    r"(?is)(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\D|$)|font-size\s*:\s*0(?:\D|$))"
)
_SIGNATURE_MARKER_RE = re.compile(
    r"(?:^|[-_])(?:email[-_]?signature|mail[-_]?signature|signature)(?:$|[-_])",
    re.IGNORECASE,
)


def recover_mislabelled_utf7_html(value: str) -> str:
    """Recover an HTML body encoded as UTF-7 but declared as another charset.

    UTF-7 is entirely ASCII, so a normal UTF-8 decode succeeds without errors
    and leaves strings such as ``+ADw-html+AD4-`` untouched. Recovery is only
    accepted when several UTF-7 shift sequences are present and strict UTF-7
    decoding turns them into multiple real HTML tags. Ordinary text containing
    an isolated ``+...-`` sequence is therefore left unchanged.
    """
    value = str(value or "")
    if not value or _HTML_TAG_RE.search(value):
        return value

    sequences = _UTF7_SHIFT_SEQUENCE_RE.findall(value)
    if len(sequences) < 4 or "+ADw" not in value or not any(
        marker in value for marker in ("+AD4", "+AD0", "+ACI")
    ):
        return value

    try:
        decoded = value.encode("ascii", errors="strict").decode("utf-7", errors="strict")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return value

    if len(_HTML_TAG_RE.findall(decoded)) < 2:
        return value
    if len(_UTF7_SHIFT_SEQUENCE_RE.findall(decoded)) >= len(sequences):
        return value
    return decoded


def _parse_html_for_preview(html: str):
    try:
        return BeautifulSoup(html, "lxml")
    except Exception:
        return BeautifulSoup(html, "html.parser")


def _sanitize_preview_soup(html: str, block_images: bool = True) -> str:
    soup = _parse_html_for_preview(html)

    for tag in soup(list(_ACTIVE_PREVIEW_TAGS)):
        tag.decompose()

    if block_images:
        for img in soup.find_all("img"):
            src = str(img.get("src") or "").strip()
            alt = str(img.get("alt") or "").strip()
            label = "Immagine remota bloccata"
            if alt:
                label = f"{label}: {alt[:120]}"
            elif src:
                label = f"{label}: sorgente esterna rimossa"
            placeholder = soup.new_tag("div")
            placeholder.string = label
            placeholder["style"] = (
                "display:block; box-sizing:border-box; min-height:96px; padding:18px; "
                "margin:8px 0; border:1px dashed #d0d7de; border-radius:6px; "
                "background:#f6f8fa; color:#57606a; text-align:center; "
                "font-family:Arial,sans-serif; font-size:14px;"
            )
            placeholder["title"] = "Immagine remota non caricata per evitare tracking o contenuti esterni."
            img.replace_with(placeholder)

    for tag in soup.find_all(True):
        for attr in list(tag.attrs):
            attr_l = attr.lower()
            value = tag.attrs.get(attr)
            if attr_l.startswith("on") or attr_l in _URL_PREVIEW_ATTRS:
                del tag.attrs[attr]
                if tag.name == "a":
                    tag.attrs["title"] = "Link rimosso per sicurezza: usa la box Links found in the email."
                    tag.attrs["style"] = "color: inherit; text-decoration: none; cursor: default;"
                continue
            if attr_l == "style" and _DANGEROUS_STYLE_RE.search(str(value or "")):
                del tag.attrs[attr]
                continue
            if attr_l in {"target", "ping"}:
                del tag.attrs[attr]

    return soup.body.decode_contents() if soup.body else str(soup)


def strip_html(html: str) -> str:
    """
    Converts raw HTML into clean text suitable for AI analysis and checks
    testuali.

    Strategia (in ordine):
      1. BeautifulSoup (lxml > html.parser come backend) per un parsing robusto
         che gestisce HTML malformato, encoding errors e tag annidati.
      2. Removes <script> and <style> before text extraction to
         evitare che codice JS o CSS venga passato al modello.
      3. Separatore '\\n' tra i tag per preservare la struttura dei paragrafi.
      4. Regex fallback if BeautifulSoup is not installed: removes all tags
         con un pattern greedy-safe e decodifica le entity HTML principali.
    """
    if not html or not html.strip():
        return ""

    if _BS4_AVAILABLE:
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            soup = BeautifulSoup(html, "html.parser")

        for tag in soup(["script", "style", "head", "template", "svg", "math"]):
            tag.decompose()

        for tag in list(soup.find_all(True)):
            # Decomposing a hidden parent invalidates its descendants that are
            # still present in this snapshot of find_all().
            if tag.parent is None or tag.attrs is None:
                continue
            if tag.attrs.get("hidden") is not None:
                tag.decompose()
                continue
            if str(tag.get("aria-hidden") or "").strip().lower() == "true":
                tag.decompose()
                continue
            if _HIDDEN_STYLE_RE.search(str(tag.get("style") or "")):
                tag.decompose()

        for image in soup.find_all("img"):
            alt = str(image.get("alt") or "").strip()
            image.replace_with(f" {alt} " if alt else "")
        for line_break in soup.find_all("br"):
            line_break.replace_with("\n")
        for tag in soup.find_all(_BLOCK_TEXT_TAGS):
            tag.insert_before("\n")
            tag.insert_after("\n")

        # Do not insert separators between inline nodes: Pa<span>y</span>Pal
        # must become PayPal, not "Pa y Pal".
        text = soup.get_text(separator="")
    else:
        # Fallback regex
        html = re.sub(r"(?is)<(script|style|head|iframe|object|embed|form|button|input|meta)\b[^>]*>.*?</\1>", " ", html)
        html = re.sub(r"(?is)<(script|style|head|iframe|object|embed|form|button|input|meta)\b[^>]*?/?>", " ", html)
        block_names = "|".join(sorted(_BLOCK_TEXT_TAGS | {"br"}))
        html = re.sub(rf"(?is)<\s*/?\s*(?:{block_names})\b[^>]*>", "\n", html)
        text = re.sub(r"<[^>]+>", "", html)
        text = html_lib.unescape(text)

    lines = [line.strip() for line in text.splitlines()]
    lines = [l for l in lines if l]
    cleaned = "\n".join(lines)
    cleaned = re.sub(r" {2,}", " ", cleaned)

    return cleaned.strip()


def strip_html_for_intent(html: str) -> str:
    """Extract visible message text while excluding explicit signature blocks."""
    if not html or not html.strip():
        return ""
    if not _BS4_AVAILABLE:
        without_signatures = re.sub(
            r"""(?is)<(?:div|section|table|footer)\b[^>]*(?:id|class)\s*=\s*
                ["'][^"']*signature[^"']*["'][^>]*>.*?</(?:div|section|table|footer)>""",
            " ",
            html,
            flags=re.VERBOSE,
        )
        return strip_html(without_signatures)

    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        soup = BeautifulSoup(html, "html.parser")

    for tag in list(soup.find_all(True)):
        if tag.parent is None or tag.attrs is None:
            continue
        marker_values = [
            str(tag.get("id") or ""),
            *[str(value) for value in (tag.get("class") or [])],
        ]
        if any(_SIGNATURE_MARKER_RE.search(value) for value in marker_values):
            tag.decompose()

    return strip_html(str(soup))


def sanitize_html_for_preview(html: str) -> str:
    """
    Restituisce HTML renderizzabile nella dashboard senza contenuti attivi.

    The preview helps the analyst understand the message layout and text, not
    per eseguire codice dell'email o consentire click verso risorse esterne.
    Rimuove quindi script, iframe, form, embed, event handler inline e tutte le
    destinazioni href/src/action.
    """
    if not html or not html.strip():
        return "<p><em>Nessun HTML disponibile.</em></p>"

    if not _BS4_AVAILABLE:
        safe_html = re.sub(r"(?is)<(script|style|head|iframe|object|embed|form|button|input|meta|base|link|svg|math)\b[^>]*>.*?</\1>", " ", html)
        safe_html = re.sub(r"(?is)<(script|style|head|iframe|object|embed|form|button|input|meta|base|link|svg|math)\b[^>]*?/?>", " ", safe_html)
        safe_html = re.sub(r"(?is)<img\b[^>]*>", "[Immagine remota bloccata]", safe_html)
        safe_html = re.sub(r"""(?is)\son[a-z0-9_-]+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)""", "", safe_html)
        safe_html = re.sub(r"""(?is)\s(?:href|src|srcset|xlink:href|action|formaction|poster|background|dynsrc|lowsrc|srcdoc|ping)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)""", "", safe_html)
        safe_html = re.sub(r"(?i)\b(?:javascript|vbscript|data)\s*:", "#", safe_html)
        escaped = html_lib.escape(safe_html)
        return f"<pre style='white-space: pre-wrap'>{escaped}</pre>"

    body = _sanitize_preview_soup(html, block_images=True)
    return f"""
    <div style="font-family: Arial, sans-serif; font-size: 14px; line-height: 1.45; color: #24292f;">
      {body}
    </div>
    """


def sanitize_html_for_js_preview(html: str) -> str:
    """
    Restituisce una preview isolata: il JavaScript dell'email non viene mai
    eseguito. Resta solo un piccolo script interno, protetto da CSP nonce, che
    disabilita i click sui link anche se il DOM cambia.
    """
    if not html or not html.strip():
        return "<p><em>Nessun HTML disponibile.</em></p>"

    if _BS4_AVAILABLE:
        body = _sanitize_preview_soup(html, block_images=True)
    else:
        body = sanitize_html_for_preview(html)

    nonce = "fishstop-preview-guard"
    csp = (
        "default-src 'none'; "
        "img-src data:; "
        "style-src 'unsafe-inline'; "
        f"script-src 'nonce-{nonce}'; "
        "connect-src 'none'; frame-src 'none'; object-src 'none'; "
        "base-uri 'none'; form-action 'none'"
    )
    link_guard = f"""
    <meta http-equiv="Content-Security-Policy" content="{html_lib.escape(csp, quote=True)}">
    <style>
      a, a:visited {{
        color: inherit !important;
        text-decoration: none !important;
        cursor: default !important;
        pointer-events: none !important;
      }}
    </style>
    <script nonce="{nonce}">
    (function () {{
      function disableLinks(root) {{
        var scope = root || document;
        scope.querySelectorAll('a').forEach(function (link) {{
          link.removeAttribute('href');
          link.removeAttribute('target');
          link.removeAttribute('ping');
          link.setAttribute('aria-disabled', 'true');
          link.setAttribute('title', 'Link disabilitato nella preview.');
        }});
      }}

      document.addEventListener('click', function (event) {{
        if (event.target && event.target.closest && event.target.closest('a')) {{
          event.preventDefault();
          event.stopImmediatePropagation();
        }}
      }}, true);

      document.addEventListener('DOMContentLoaded', function () {{
        disableLinks(document);
        var observer = new MutationObserver(function () {{ disableLinks(document); }});
        observer.observe(document.documentElement, {{ childList: true, subtree: true, attributes: true }});
      }});
    }}());
    </script>
    """
    return f"""
    {link_guard}
    <div style="font-family: Arial, sans-serif; font-size: 14px; line-height: 1.45; color: #24292f;">
      {body}
    </div>
    """
