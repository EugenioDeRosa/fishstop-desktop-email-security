"""Static inspection of HTML forms embedded in email bodies.

Nothing in this module submits a form or resolves a destination.  It only
examines the already-parsed HTML source to identify credential-harvesting
patterns that the safe preview deliberately removes.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None


_SENSITIVE_FIELD_RE = re.compile(
    r"(?:pass(?:word|wd)?|pwd|credential|otp|one[ _-]?time|token|auth(?:entication)?|pin)"
    r"|(?:\b(?:verification|security)[ _-]?(?:code|key)\b)",
    re.IGNORECASE,
)
_UNSAFE_ACTION_SCHEMES = {"javascript", "data", "vbscript"}


def _registered_domain(value: str) -> str:
    domain = (value or "").lower().strip().rstrip(".")
    if not domain:
        return ""
    try:
        from publicsuffix2 import get_sld

        return str(get_sld(domain) or domain).lower().rstrip(".")
    except Exception:
        labels = domain.split(".")
        return ".".join(labels[-2:]) if len(labels) >= 2 else domain


def _field_label(field) -> str:
    values = [
        str(field.get("type") or "").strip(),
        str(field.get("name") or "").strip(),
        str(field.get("id") or "").strip(),
        str(field.get("autocomplete") or "").strip(),
        str(field.get("placeholder") or "").strip(),
    ]
    return " ".join(value for value in values if value).strip()


def _is_sensitive_field(field) -> bool:
    field_type = str(field.get("type") or "").strip().lower()
    return field_type == "password" or bool(_SENSITIVE_FIELD_RE.search(_field_label(field)))


def _action_details(action: str, from_domain: str) -> tuple[str, str, bool]:
    """Return action kind, host and whether it differs from visible sender."""
    value = (action or "").strip()
    if not value:
        return "missing", "", False
    parsed = urlparse(value)
    scheme = parsed.scheme.lower()
    if scheme in _UNSAFE_ACTION_SCHEMES:
        return "unsafe_scheme", "", True
    if not scheme and not value.startswith("//"):
        return "relative", "", False
    if value.startswith("//"):
        parsed = urlparse(f"https:{value}")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return "unresolved", "", False
    external = bool(from_domain and _registered_domain(host) != _registered_domain(from_domain))
    return "external" if external else "same_sender", host, external


def analyze_html_forms(html: str, from_domain: str = "") -> dict:
    """Return local form-harvesting evidence suitable for the static report."""
    base = {"status": "not_applicable", "form_count": 0, "forms": [], "message": "No HTML body is available."}
    if not html or not html.strip():
        return base
    if BeautifulSoup is None:
        return {**base, "status": "unavailable", "message": "HTML form inspection requires BeautifulSoup."}
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        soup = BeautifulSoup(html, "html.parser")

    forms: list[dict] = []
    for form in soup.find_all("form"):
        action = str(form.get("action") or "").strip()
        method = str(form.get("method") or "get").strip().lower() or "get"
        fields = form.find_all(["input", "textarea", "select"])
        # Some mail templates contain empty ``form`` placeholders solely for
        # layout/CSS.  They cannot collect or submit data, so do not surface
        # them as actual forms in the analyst UI.
        if not fields and not action and method == "get":
            continue
        sensitive = [field for field in fields if _is_sensitive_field(field)]
        sensitive_labels = list(dict.fromkeys(_field_label(field)[:100] for field in sensitive if _field_label(field)))
        action_kind, action_host, external = _action_details(action, from_domain)

        if sensitive and (external or action_kind == "unsafe_scheme"):
            risk = "high"
            message = "Sensitive credential fields submit to a destination unrelated to the visible sender."
        elif sensitive:
            risk = "medium"
            message = "Sensitive credential fields are embedded in the email HTML."
        elif method == "post" and external:
            risk = "medium"
            message = "The form submits POST data to a destination unrelated to the visible sender."
        elif action_kind == "unsafe_scheme":
            risk = "high"
            message = "The form uses an unsafe action scheme."
        else:
            risk = "low"
            message = "An HTML form is present but no credential-harvesting pattern was confirmed."

        forms.append({
            "risk": risk,
            "method": method.upper(),
            "action": action,
            "action_host": action_host,
            "action_kind": action_kind,
            "external_action": external,
            "field_count": len(fields),
            "sensitive_fields": sensitive_labels[:8],
            "message": message,
        })

    if not forms:
        return {**base, "status": "clean", "message": "No HTML forms were found."}
    risks = {item["risk"] for item in forms}
    status = "suspicious" if "high" in risks else "review" if "medium" in risks else "clean"
    return {
        "status": status,
        "form_count": len(forms),
        "forms": forms[:10],
        "message": (
            "Credential-harvesting form pattern detected."
            if status == "suspicious"
            else "HTML form requires review." if status == "review" else "HTML form found without a confirmed credential-harvesting pattern."
        ),
    }
