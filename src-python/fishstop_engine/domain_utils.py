"""Canonical hostname and Public Suffix List helpers."""

from __future__ import annotations

import ipaddress
import warnings

try:
    from publicsuffix2 import get_sld, get_tld
except ImportError:  # Static parsing remains conservative in minimal environments.
    get_sld = None
    get_tld = None


def normalize_hostname(value: str) -> str:
    """Return a lowercase ASCII hostname suitable for security comparisons."""
    host = str(value or "").strip().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host:
        return ""
    try:
        return ipaddress.ip_address(host).compressed.lower()
    except ValueError:
        pass

    labels: list[str] = []
    for label in host.split("."):
        if not label:
            return ""
        try:
            labels.append(label.encode("idna").decode("ascii").lower())
        except UnicodeError:
            return ""
    return ".".join(labels)


def registered_domain(value: str) -> str:
    """Return the PSL registrable domain, conservatively handling unknown TLDs."""
    host = normalize_hostname(value)
    if not host:
        return ""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    if get_sld is None or get_tld is None:
        return host
    try:
        # strict=True is deliberate. With strict=False, an unknown suffix such
        # as .example would collapse evil.example and paypal.example to the same
        # value. Keeping the complete host is the safer fallback.
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore",
                category=DeprecationWarning,
                module=r"publicsuffix2(?:\..*)?",
            )
            public_suffix = get_tld(host, strict=True)
            registrable = get_sld(host, strict=True)
    except (TypeError, ValueError, UnicodeError):
        return host
    if not public_suffix or not registrable:
        return host
    return normalize_hostname(str(registrable)) or host


def is_public_suffix(value: str) -> bool:
    """Return whether a hostname is itself a PSL boundary.

    This includes private suffixes such as shared hosting platforms when they
    are present in the bundled Public Suffix List. A match on the boundary is
    not evidence that every customer subdomain is malicious.
    """
    host = normalize_hostname(value)
    if not host or get_tld is None:
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    try:
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore",
                category=DeprecationWarning,
                module=r"publicsuffix2(?:\..*)?",
            )
            suffix = get_tld(host, strict=True)
    except (TypeError, ValueError, UnicodeError):
        return False
    return normalize_hostname(str(suffix or "")) == host


def registrable_label(value: str) -> str:
    """Return the label immediately preceding the public suffix."""
    registrable = registered_domain(value)
    if not registrable:
        return ""
    try:
        ipaddress.ip_address(registrable)
        return ""
    except ValueError:
        pass
    return registrable.split(".", 1)[0]


def same_registered_domain(left: str, right: str) -> bool:
    """Compare two hosts using their PSL registrable domains."""
    left_registered = registered_domain(left)
    right_registered = registered_domain(right)
    return bool(
        left_registered
        and right_registered
        and left_registered == right_registered
    )
