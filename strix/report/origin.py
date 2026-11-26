# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""Structural web origin of a report target, for the deterministic dedupe identity gate.

The host rules mirror Recon's shared host normaliser (``hostfold.Normalize`` in the
control plane and ``normalize_host`` in the egress sidecar): ASCII only, ASCII-only
lowercase, one trailing dot dropped, label characters ``a-z 0-9 - _``, IPv6 literals
canonicalised, no zone IDs. Strix cannot import those modules, so the rules are
repeated here and must change together with them.

Anything that does not parse cleanly has no origin, so two such targets are never
the same origin and a proof is never merged on their account.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit


_LABEL_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-_")
_DEFAULT_PORTS = {"http": 80, "https": 443}


def _canonical_host(host: str) -> str | None:
    if not host or not host.isascii() or "%" in host:
        return None
    host = "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in host)
    if host.endswith("."):
        host = host[:-1]
    if not host:
        return None
    if ":" in host:
        try:
            return str(ipaddress.IPv6Address(host))
        except ValueError:
            return None
    labels = host.split(".")
    if any(not label or any(c not in _LABEL_CHARS for c in label) for label in labels):
        return None
    return host


def origin_of(target: object) -> tuple[str, str, int] | None:
    """Return ``(scheme, canonical host, effective port)`` or ``None`` if unparseable."""
    text = str(target or "").strip()
    if not text or "\\" in text or any(c.isspace() or ord(c) < 32 for c in text):
        return None
    try:
        parts = urlsplit(text)
        port = parts.port
        hostname = parts.hostname
    except ValueError:
        return None
    if parts.scheme not in _DEFAULT_PORTS or "@" in parts.netloc or hostname is None:
        return None
    host = _canonical_host(hostname)
    if host is None:
        return None
    return parts.scheme, host, _DEFAULT_PORTS[parts.scheme] if port is None else port
