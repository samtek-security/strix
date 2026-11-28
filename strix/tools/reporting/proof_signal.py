# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""The signal that proved a finding, in the shape a live retest can compare against.

A retest replays the proof request and looks for this signal instead of trusting the status
code alone. It is stored in the report and sent back to the target, so every literal must be
bounded and survive secret redaction unchanged.
"""

from __future__ import annotations

import math
import re
from typing import Any


_CHECKS = ("body_marker", "reflection", "header", "timing")
_MAX_LITERAL = 512
_MAX_HEADER_NAME = 128
_HEADER_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")  # RFC 9110 field name
_TIMING_KEYS = ("delay_ms", "baseline_ms", "tolerance_ms")
_MAX_TIMING_MS = 14000  # baseline plus delay has to fit inside a 15 s replay request


def _is_literal(value: Any) -> bool:
    from strix.llm.redaction import redact_text  # noqa: PLC0415
    from strix.tools.exploitation.tool import _redact_text  # noqa: PLC0415

    return (
        isinstance(value, str)
        and 0 < len(value) <= _MAX_LITERAL
        and redact_text(value) == value
        and _redact_text(value) == value
    )


_LITERAL_RULE = f"must be 1 to {_MAX_LITERAL} characters and carry no secret"


def _header_check(value: Any) -> tuple[dict[str, str] | None, str | None]:
    if not isinstance(value, dict) or set(value) - {"name", "contains"}:
        return None, "proof_signal.header takes 'name' and an optional 'contains'"
    name = value.get("name")
    name = name.strip() if isinstance(name, str) else ""
    if not _HEADER_TOKEN.fullmatch(name) or len(name) > _MAX_HEADER_NAME or not _is_literal(name):
        return None, "proof_signal.header.name must be an HTTP header name"
    needle = value.get("contains")
    if needle is None:
        return {"name": name}, None
    # "Name: value" is how a header secret is recognised, so the pair is checked too.
    if not _is_literal(needle) or not _is_literal(f"{name}: {needle}"):
        return None, f"proof_signal.header.contains {_LITERAL_RULE}"
    return {"name": name, "contains": needle}, None


def _timing_check(value: Any) -> tuple[dict[str, float] | None, str | None]:
    rule = (
        "proof_signal.timing takes non-negative delay_ms, baseline_ms and tolerance_ms with "
        f"delay_ms > 2 * tolerance_ms and baseline_ms + delay_ms <= {_MAX_TIMING_MS}"
    )
    if not isinstance(value, dict) or set(value) != set(_TIMING_KEYS):
        return None, rule
    numbers = [value[key] for key in _TIMING_KEYS]
    if any(
        isinstance(n, bool) or not isinstance(n, (int, float)) or not math.isfinite(n) or n < 0
        for n in numbers
    ):
        return None, rule
    delay, baseline, tolerance = numbers
    if delay <= 0 or tolerance * 2 >= delay or baseline + delay > _MAX_TIMING_MS:
        return None, rule
    return dict(zip(_TIMING_KEYS, numbers, strict=True)), None


def normalize_proof_signal(raw: Any) -> tuple[dict[str, Any] | None, list[str]]:
    """Return the signal as it is stored, or the reasons it cannot be. Omitted is ``(None, [])``."""
    if raw is None or raw == {}:
        return None, []
    if not isinstance(raw, dict) or set(raw) - set(_CHECKS):
        return None, [f"proof_signal takes only these checks: {', '.join(_CHECKS)}"]

    signal: dict[str, Any] = {}
    errors: list[str] = []
    for name, value in raw.items():
        if name == "header":
            checked, error = _header_check(value)
        elif name == "timing":
            checked, error = _timing_check(value)
        elif _is_literal(value):
            checked, error = value, None
        else:
            checked, error = None, f"proof_signal.{name} {_LITERAL_RULE}"
        if error:
            errors.append(error)
        else:
            signal[name] = checked
    return (None, errors) if errors else (signal, [])


def normalize_auth_role(raw: Any) -> tuple[str | None, list[str]]:
    """Return the role label a proof ran as. Omitted or blank is ``(None, [])``."""
    role = raw.strip() if isinstance(raw, str) else raw
    if role is None or role == "":
        return None, []
    if not _is_literal(role):
        return None, [f"auth_role {_LITERAL_RULE}"]
    return role, []
