"""Bounded presentation-only CSS. No URLs, imports, animation or positioning."""
import re
from time import monotonic

try:
    import tinycss2
    from tinycss2.color3 import parse_color
except ImportError:
    tinycss2 = None

_ENUMS = {
    "text-align": {"left", "right", "center", "justify", "start", "end"},
    "vertical-align": {"top", "middle", "bottom", "baseline", "text-top", "text-bottom"},
    "font-style": {"normal", "italic", "oblique"},
    "text-decoration": {"none", "underline", "line-through", "overline"},
    "text-transform": {"none", "uppercase", "lowercase", "capitalize"},
    "white-space": {"normal", "nowrap", "pre", "pre-wrap", "pre-line"},
    "word-break": {"normal", "break-all", "keep-all", "break-word"},
    "overflow-wrap": {"normal", "break-word", "anywhere"},
    "border-collapse": {"collapse", "separate"},
    "table-layout": {"auto", "fixed"},
    "display": {"block", "inline", "inline-block", "table", "table-row", "table-cell", "none"},
    "visibility": {"visible", "hidden", "collapse"},
}
_LENGTH_NAMES = {"width", "height", "max-width", "min-width", "max-height", "min-height",
                 "font-size", "line-height", "letter-spacing", "border-spacing", "border-radius",
                 "padding", "margin", "padding-top", "padding-right", "padding-bottom", "padding-left",
                 "margin-top", "margin-right", "margin-bottom", "margin-left"}
_COLORS = {"color", "background-color", "border-color", "border-top-color", "border-right-color", "border-bottom-color", "border-left-color"}
_BORDERS = {"border", "border-top", "border-right", "border-bottom", "border-left"}
_LENGTH = re.compile(r"(?:0|\d+(?:\.\d+)?(?:px|pt|em|rem|%))", re.I)
_SIMPLE_SELECTOR = re.compile(r"(?:\*|[a-z][a-z0-9-]*)?(?:[.#][a-z_][a-z0-9_-]*)*", re.I)


def _color(value):
    return bool(re.fullmatch(r"#[0-9a-f]{8}", value, re.I)) or parse_color(value) is not None


def _length(value):
    if not _LENGTH.fullmatch(value):
        return False
    number = float(re.match(r"[\d.]+", value)[0])
    return number <= (100 if value.endswith("%") else 2000 if value.endswith(("px", "pt")) else 100)


def safe_value(name, value):
    if tinycss2 is None:
        return None
    value = value.strip().lower()
    if len(value) > 200 or any(c in value for c in "\\@{};<>"):
        return None
    if name in _COLORS or name == "background":
        return value if _color(value) else None
    if name in _ENUMS:
        return value if value in _ENUMS[name] else None
    if name == "font-weight":
        return value if value in {"normal", "bold", "bolder", "lighter", *map(str, range(100, 1000, 100))} else None
    if name == "font-family":
        return value if re.fullmatch(r"[a-z0-9 ,'\"-]+", value) else None
    if name in _LENGTH_NAMES:
        parts = value.split()
        if value in {"auto", "normal"} and name != "font-size":
            return value
        if name == "line-height" and re.fullmatch(r"\d+(?:\.\d+)?", value) and 0 <= float(value) <= 10:
            return value
        return value if 1 <= len(parts) <= 4 and all(_length(part) or (name.startswith("margin") and part == "auto") for part in parts) else None
    if name in _BORDERS:
        parts = value.split()
        if value == "none":
            return value
        return value if len(parts) == 3 and _length(parts[0]) and parts[1] in {"solid", "dashed", "dotted", "double"} and _color(parts[2]) else None
    return None


def declarations(css):
    if tinycss2 is None:
        return []
    clean = []
    for item in tinycss2.parse_declaration_list(css[:4096] if isinstance(css, str) else css,
                                              skip_comments=True, skip_whitespace=True)[:80]:
        if item.type != "declaration":
            continue
        value = safe_value(item.lower_name, tinycss2.serialize(item.value))
        if value is not None:
            clean.append((item.lower_name, value, bool(item.important)))
    return clean


def inline_presentation(soup):
    """Resolve simple local style rules into safe inline declarations once."""
    if tinycss2 is None:
        for tag in soup.find_all(True):
            tag.attrs.pop("style", None)
        return
    winners = {}
    assignments = 0
    deadline = monotonic() + 0.5

    def apply(tag, items, specificity, order):
        nonlocal assignments
        styles = winners.setdefault(id(tag), {})
        for name, value, important in items:
            weight = (important, *specificity, order)
            if name not in styles or weight >= styles[name][0]:
                styles[name] = (weight, value)
            assignments += 1

    rules_used = 0
    for sheet in soup.find_all("style")[:16]:
        if monotonic() >= deadline:
            break
        rules = tinycss2.parse_stylesheet(sheet.get_text()[:65536], skip_comments=True, skip_whitespace=True)
        for rule in rules[:256]:
            if monotonic() >= deadline:
                break
            if rule.type != "qualified-rule":
                continue  # No @import, @font-face, media queries or keyframes.
            items = declarations(rule.content)
            for selector in tinycss2.serialize(rule.prelude).split(",")[:16]:
                selector = selector.strip()
                segments = re.split(r"\s+|[>+~]", selector)
                if not selector or len(selector) > 160 or not all(not part or _SIMPLE_SELECTOR.fullmatch(part) for part in segments):
                    continue
                rules_used += 1
                if rules_used > 256 or assignments > 50000 or monotonic() >= deadline:
                    break
                specificity = (0, selector.count("#"), selector.count("."), sum(bool(re.match(r"[a-z]", part, re.I)) for part in segments))
                try:
                    for tag in soup.select(selector, limit=1000):
                        apply(tag, items, specificity, rules_used)
                except Exception:
                    continue
    for tag in soup.find_all(True):
        apply(tag, declarations(str(tag.get("style") or "")), (1, 0, 0, 0), rules_used + 1)
        styles = winners.get(id(tag), {})
        if styles:
            tag["style"] = ";".join(f"{name}:{value}" for name, (_, value) in styles.items())
        else:
            tag.attrs.pop("style", None)
