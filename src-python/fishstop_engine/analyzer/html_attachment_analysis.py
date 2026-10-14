"""Bounded, static HTML attachment inspection. Never execute or fetch content."""
import re
from bs4 import BeautifulSoup, UnicodeDammit
from .html_form_analysis import analyze_html_forms, _is_sensitive_field, _field_label

MAX_HTML_ATTACHMENT_BYTES = 1_000_000


def analyze_html_attachment(payload: bytes, from_domain: str = "") -> dict:
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
        if re.match(r"https?://", url, re.I) and url not in urls:
            urls.append(url)
        if len(urls) >= 25:
            break
    for element in soup(["script", "style"]):
        element.decompose()
    risk = "high" if any(f["severity"] == "high" for f in findings) else "medium" if findings else "clean"
    return {"status": "complete" if complete else "partial", "analysis_complete": complete,
            "risk_level": risk, "forms": forms, "script_count": len(scripts),
            "credential_field_count": len(credential_fields), "credential_fields": credential_fields[:16],
            "unassociated_sensitive_field_count": len(orphan_fields),
            "findings": findings, "urls": urls, "text": soup.get_text(" ", strip=True)[:3000],
            "summary": f"Static HTML inspection: {forms.get('form_count', 0)} forms, {len(scripts)} scripts; "
                       + (forms.get("message") or "No form data")
                       + (f" {len(orphan_fields)} sensitive field(s) have no confirmed form association." if orphan_fields else "")
                       + (" HTML inspection size limit reached." if not complete else "")}
