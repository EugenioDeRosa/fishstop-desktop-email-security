"""Detect HTML presentation tricks that change what a recipient copies.

This module deliberately performs a small, deterministic CSS inspection.  It
does not render sender-controlled HTML and it never executes CSS or scripts.
"""

from __future__ import annotations

import re

from .constants import DANGEROUS_ATTACHMENT_EXTENSIONS

try:
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover - the analyzer has a regex fallback
    BeautifulSoup = None


_CSS_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_CSS_RULE_RE = re.compile(r"([^{}]{1,500})\{([^{}]{0,5000})\}", re.DOTALL)
_CLASS_SELECTOR_RE = re.compile(r"\.([A-Za-z_][\w-]*)")
_ID_SELECTOR_RE = re.compile(r"#([A-Za-z_][\w-]*)")
_UNC_PATH_RE = re.compile(r"(?<!\\)\\\\[A-Za-z0-9][^\s<>\"']{2,500}")
_COPY_ACTION_RE = re.compile(
    r"(?is)\b(?:copy|select)\b.{0,180}\b(?:paste|file\s+explorer|run\s+dialog|win\s*\+\s*r)\b"
)


def _properties(declarations: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for declaration in declarations.split(";"):
        name, separator, value = declaration.partition(":")
        if not separator:
            continue
        result[name.strip().lower()] = value.strip().lower()
    return result


def _zero_alpha_colour(value: str) -> bool:
    compact = re.sub(r"\s+", "", value.lower())
    if compact in {"transparent", "#0000", "#00000000"}:
        return True
    match = re.fullmatch(r"rgba\([^,]+,[^,]+,[^,]+,([^)]+)\)", compact)
    if not match:
        return False
    alpha = match.group(1).rstrip("%")
    try:
        return float(alpha) == 0
    except ValueError:
        return False


def _is_transparent_text(properties: dict[str, str]) -> bool:
    return (
        properties.get("opacity", "").strip() in {"0", "0.0", "0%"}
        or _zero_alpha_colour(properties.get("color", ""))
        or _zero_alpha_colour(properties.get("-webkit-text-fill-color", ""))
    )


def _is_selectable_overlay(properties: dict[str, str]) -> bool:
    selectable = any(
        value.strip() in {"text", "all"}
        for name, value in properties.items()
        if name == "user-select" or name.endswith("-user-select")
    )
    positioned = properties.get("position", "").strip() in {"absolute", "fixed"}
    try:
        raised = int(re.match(r"-?\d+", properties.get("z-index", "0"))[0]) > 0
    except (TypeError, ValueError):
        raised = False
    return selectable and (positioned or raised)


def _dangerous_network_paths(value: str) -> list[str]:
    paths: list[str] = []
    for match in _UNC_PATH_RE.finditer(value):
        path = match.group(0).rstrip(".,;:!?)]}")
        filename = path.rsplit("\\", 1)[-1]
        extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if extension in DANGEROUS_ATTACHMENT_EXTENSIONS and path not in paths:
            paths.append(path)
    return paths


def _clip(value: str, limit: int = 220) -> str:
    compact = re.sub(r"\s+", " ", value).strip()
    return compact if len(compact) <= limit else compact[: limit - 1].rstrip() + "…"


def _action_evidence(value: str) -> str:
    for segment in re.split(r"(?<=[.!?])\s+|[\r\n]+", value):
        if _COPY_ACTION_RE.search(segment):
            return _clip(segment, 180)
    match = _COPY_ACTION_RE.search(value)
    return _clip(match.group(0), 180) if match else ""


def analyze_html_copy_deception(html: str) -> dict:
    """Describe transparent selectable overlays and dangerous copied paths."""
    if not html or not html.strip():
        return {
            "status": "not_applicable",
            "finding_count": 0,
            "message": "No HTML body is available for copy-deception analysis.",
            "findings": [],
        }

    if BeautifulSoup is None:
        paths = _dangerous_network_paths(html)
        action = _action_evidence(re.sub(r"<[^>]+>", " ", html))
        findings = []
        if paths and action:
            findings.append({
                "technique": "dangerous_copy_run_instruction",
                "severity": "medium",
                "hidden_text": "",
                "visible_text": "",
                "dangerous_paths": paths[:5],
                "action_evidence": action,
                "message": "The message asks the recipient to copy a network path that ends in executable or script content.",
            })
        return {
            "status": "review" if findings else "clean",
            "finding_count": len(findings),
            "message": "A dangerous copy/paste instruction was detected." if findings else "No HTML copy-deception pattern was detected.",
            "findings": findings,
        }

    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        soup = BeautifulSoup(html, "html.parser")

    suspicious_elements: list[tuple[object, str]] = []
    seen_elements: set[int] = set()
    css = "\n".join(tag.get_text(" ", strip=False) for tag in soup.find_all("style"))
    css = _CSS_COMMENT_RE.sub(" ", css[:250_000])
    for selector_blob, declarations in _CSS_RULE_RE.findall(css)[:500]:
        properties = _properties(declarations)
        if not (_is_transparent_text(properties) and _is_selectable_overlay(properties)):
            continue
        for selector in selector_blob.split(",")[:20]:
            label = re.sub(r"\s+", " ", selector).strip()
            candidates = []
            for class_name in _CLASS_SELECTOR_RE.findall(selector):
                candidates.extend(soup.find_all(class_=class_name, limit=30))
            for element_id in _ID_SELECTOR_RE.findall(selector):
                element = soup.find(id=element_id)
                if element is not None:
                    candidates.append(element)
            for element in candidates:
                if id(element) in seen_elements:
                    continue
                seen_elements.add(id(element))
                suspicious_elements.append((element, label))

    for element in soup.find_all(style=True, limit=5000):
        properties = _properties(str(element.get("style") or ""))
        if not (_is_transparent_text(properties) and _is_selectable_overlay(properties)):
            continue
        if id(element) not in seen_elements:
            seen_elements.add(id(element))
            suspicious_elements.append((element, "inline style"))

    full_text = soup.get_text("\n", strip=True)
    action = _action_evidence(full_text)
    findings: list[dict] = []
    detected_paths: set[str] = set()
    for element, selector in suspicious_elements[:30]:
        hidden_text = _clip(element.get_text(" ", strip=True))
        if not hidden_text:
            continue
        sibling_texts = []
        if element.parent is not None:
            for sibling in element.parent.find_all(recursive=False):
                if sibling is element or id(sibling) in seen_elements:
                    continue
                text = _clip(sibling.get_text(" ", strip=True))
                if text and text.casefold() != hidden_text.casefold():
                    sibling_texts.append(text)
        visible_text = min(sibling_texts, key=len) if sibling_texts else ""
        paths = _dangerous_network_paths(hidden_text)
        detected_paths.update(paths)
        severity = "high" if paths and visible_text else "medium"
        message = (
            "Transparent selectable HTML is layered over different visible text and contains a network path ending in executable or script content."
            if severity == "high"
            else "Transparent selectable HTML is layered over content the recipient may believe they are copying."
        )
        findings.append({
            "technique": "transparent_selectable_overlay",
            "severity": severity,
            "selector": _clip(selector, 120),
            "hidden_text": hidden_text,
            "visible_text": visible_text,
            "dangerous_paths": paths[:5],
            "action_evidence": action,
            "message": message,
        })

    remaining_paths = [
        path for path in _dangerous_network_paths(full_text)
        if path not in detected_paths
    ]
    if remaining_paths and action:
        findings.append({
            "technique": "dangerous_copy_run_instruction",
            "severity": "medium",
            "selector": "",
            "hidden_text": "",
            "visible_text": "",
            "dangerous_paths": remaining_paths[:5],
            "action_evidence": action,
            "message": "The message asks the recipient to copy a network path that ends in executable or script content.",
        })

    high = any(item["severity"] == "high" for item in findings)
    return {
        "status": "suspicious" if high else "review" if findings else "clean",
        "finding_count": len(findings),
        "message": (
            "The HTML attempts to replace visible copied text with a hidden executable network path."
            if high
            else "A copy/paste instruction involving hidden or executable content requires review."
            if findings
            else "No HTML copy-deception pattern was detected."
        ),
        "findings": findings,
    }
