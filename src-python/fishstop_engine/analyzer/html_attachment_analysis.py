"""Bounded, static HTML attachment inspection. Never execute or fetch content."""
import re
from bs4 import BeautifulSoup, UnicodeDammit
from .html_form_analysis import analyze_html_forms, _is_sensitive_field, _field_label

MAX_HTML_ATTACHMENT_BYTES = 1_000_000

# Static script behaviours. Nothing is executed: patterns describe what the
# document would do when opened in a browser.
_REDIRECT_RE = re.compile(
    r"(?:window\.|document\.|top\.|self\.|parent\.)?location(?:\.href)?\s*=(?!=)|"
    r"location\.(?:replace|assign)\s*\(|window\.open\s*\(|"
    r"window\.navigate\s*\(", re.I)
_DECODE_RE = re.compile(
    r"\batob\s*\(|\bunescape\s*\(|decodeURIComponent\s*\(|String\.fromCharCode\s*\(|"
    r"\beval\s*\(|new\s+Function\s*\(|document\.write(?:ln)?\s*\(|\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){20,}", re.I)
_SMUGGLING_RE = re.compile(
    r"new\s+Blob\s*\(|URL\.createObjectURL\s*\(|msSaveOrOpenBlob|msSaveBlob|"
    r"\.download\s*=|Uint8Array\s*\(", re.I)
_EXFIL_RE = re.compile(
    r"api\.telegram\.org/bot|discord(?:app)?\.com/api/webhooks|hooks\.slack\.com/|"
    r"\bfetch\s*\(|XMLHttpRequest|sendBeacon\s*\(|\$\.(?:ajax|post)\s*\(", re.I)
_LARGE_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{20000,}={0,2}")
_META_REFRESH_RE = re.compile(r"url\s*=\s*['\"]?\s*(?:https?:)?//", re.I)


def _script_behaviours(soup, html: str, is_svg: bool) -> list[dict]:
    script_text = "\n".join(script.get_text() or "" for script in soup.find_all("script"))
    handler_text = "\n".join(
        str(value) for element in soup.find_all(True)
        for name, value in element.attrs.items() if str(name).lower().startswith("on"))
    code = script_text + "\n" + handler_text
    findings: list[dict] = []

    def add(key: str, severity: str, label: str, evidence: str = "") -> None:
        findings.append({"key": key, "severity": severity, "label": label, "evidence": evidence[:160]})

    redirect = bool(_REDIRECT_RE.search(code))
    decoding = bool(_DECODE_RE.search(code))
    refresh = any(
        _META_REFRESH_RE.search(str(meta.get("content") or ""))
        for meta in soup.find_all("meta", attrs={"http-equiv": re.compile(r"^refresh$", re.I)}))
    if refresh:
        add("html_meta_refresh", "high", "The document automatically redirects the viewer to a web page when opened.")
    if redirect:
        add("html_script_redirect", "high",
            "A script navigates the viewer to another page when the document is opened.",
            (_REDIRECT_RE.search(code).group(0) if _REDIRECT_RE.search(code) else ""))
    if decoding:
        add("html_script_obfuscation", "high" if redirect or refresh else "medium",
            "A script decodes or generates content at runtime (atob/unescape/eval/document.write), a common way to hide a phishing page.",
            _DECODE_RE.search(code).group(0))
    if _SMUGGLING_RE.search(code) and (decoding or _LARGE_BASE64_RE.search(html)):
        add("html_smuggling", "high",
            "A script assembles and saves a file from embedded data (HTML smuggling).",
            _SMUGGLING_RE.search(code).group(0))
    exfil = _EXFIL_RE.search(code)
    if exfil:
        severity = "high" if re.search(r"telegram|discord|slack", exfil.group(0), re.I) else "medium"
        add("html_script_network", severity,
            "A script sends data to a remote service when the document is used.", exfil.group(0))
    if is_svg and (code.strip() or soup.find("foreignobject") or soup.find("foreignObject")):
        add("svg_active_content", "high" if code.strip() else "medium",
            "The SVG image contains scripts or embedded HTML; images received by email should not contain active content.")
    elif code.strip() and not findings:
        add("html_script_present", "medium",
            "The attached document contains scripts; legitimate attachments rarely need them.")
    return findings


def analyze_html_attachment(payload: bytes, from_domain: str = "", *, is_svg: bool = False) -> dict:
    complete = len(payload) <= MAX_HTML_ATTACHMENT_BYTES
    html = UnicodeDammit(payload[:MAX_HTML_ATTACHMENT_BYTES], is_html=True).unicode_markup
    if not html:
        return {"status": "partial", "analysis_complete": False, "risk_level": "unknown",
                "forms": {}, "script_count": 0, "credential_field_count": 0,
                "findings": [], "urls": [], "text": "", "summary": "HTML payload is empty or could not be decoded."}
    forms = analyze_html_forms(html, from_domain=from_domain)
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        soup = BeautifulSoup(html, "html.parser")
    findings = [{"key": "html_form", "label": form["message"],
                 "severity": form["risk"], "evidence": form["action"] or "Relative or missing form destination"}
                for form in forms.get("forms", []) if form["risk"] in {"medium", "high"}]
    scripts = soup.find_all("script")
    credential_fields = []
    for field in soup.find_all(["input", "textarea", "select"]):
        if not _is_sensitive_field(field):
            continue
        owner = soup.find("form", id=field.get("form")) if field.get("form") else field.find_parent("form")
        credential_fields.append({"label": _field_label(field)[:100], "associated_form": owner is not None,
                                  "form_action": str(owner.get("action") or "") if owner is not None else ""})
    findings.extend(_script_behaviours(soup, html, is_svg))
    orphan_fields = [field for field in credential_fields if not field["associated_form"]]
    if orphan_fields:
        findings.append({"key": "html_unassociated_credentials", "severity": "medium",
                         "label": "Sensitive fields exist outside the parsed forms; their submission destination is unconfirmed.",
                         "evidence": "; ".join(field["label"] for field in orphan_fields[:8])})
    urls = []
    for element in soup.find_all(["a", "form", "script", "iframe"]):
        url = str(element.get("action") or element.get("href") or element.get("src") or "").strip()
        if url.startswith("//"):
            url = "https:" + url
        if not url and element.name == "script":
            continue
        if re.match(r"https?://", url, re.I) and url not in urls:
            urls.append(url)
        if len(urls) >= 25:
            break
    for element in soup(["script", "style"]):
        element.decompose()
    risk = "high" if any(f["severity"] == "high" for f in findings) else "medium" if findings else "clean"
    behaviour_labels = list(dict.fromkeys(
        finding["label"] for finding in findings
        if finding["key"].startswith(("html_script", "html_meta", "html_smuggling", "svg_"))))
    summary = (
        ("; ".join(behaviour_labels) + "; " if behaviour_labels else "")
        + f"Static {'SVG' if is_svg else 'HTML'} inspection: {forms.get('form_count', 0)} forms, {len(scripts)} scripts; "
        + (forms.get("message") or "No form data")
        + (f" {len(orphan_fields)} sensitive field(s) have no confirmed form association." if orphan_fields else "")
        + (" HTML inspection size limit reached." if not complete else "")
    )
    return {"status": "complete" if complete else "partial", "analysis_complete": complete,
            "risk_level": risk, "forms": forms, "script_count": len(scripts),
            "credential_field_count": len(credential_fields), "credential_fields": credential_fields[:16],
            "unassociated_sensitive_field_count": len(orphan_fields),
            "findings": findings, "urls": urls, "text": soup.get_text(" ", strip=True)[:3000],
            "summary": summary}
