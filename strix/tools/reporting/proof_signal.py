# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""The signal that proved a finding, in the shape a live retest can compare against.

A retest replays the proof request and looks for this signal instead of trusting the status
code alone. It is stored in the report and sent back to the target, so every literal must be
bounded and survive secret redaction unchanged.
"""

from __future__ import annotations

import logging
import math
import re
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from agents import RunContextWrapper


logger = logging.getLogger(__name__)

UNOBSERVED_WARNING = (
    "proof_signal was not stored: the captured response of the proving exchange (the first "
    "id cited) does not show it. Copy the value from that response and set it with "
    "update_vulnerability_report."
)
UNTIMED_WARNING = (
    "proof_signal was not stored: this capture records no response time, so timing cannot be "
    "checked on it. Use a body, reflection or header check if the response shows one."
)
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
    checked: Any
    error: str | None
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


def _response_shows(signal: dict[str, Any], raw: str, roundtrip_ms: float | None) -> bool:
    head, _, body = raw.replace("\r\n", "\n").partition("\n\n")
    headers: dict[str, list[str]] = {}
    for line in head.split("\n")[1:]:
        name, colon, value = line.partition(":")
        if colon:
            headers.setdefault(name.strip().lower(), []).append(value.strip())

    for check, expected in signal.items():
        if check == "header":
            values = headers.get(expected["name"].lower())
            if values is None or expected.get("contains", "") not in ", ".join(values):
                return False
        elif check == "timing":
            slow = expected["baseline_ms"] + expected["delay_ms"] - expected["tolerance_ms"]
            if not roundtrip_ms or roundtrip_ms < slow:
                return False
        elif expected.replace("\r\n", "\n") not in body:
            return False
    return True


async def observed_proof_signal(
    ctx: RunContextWrapper, raw: Any, exchange_id: str | None
) -> tuple[Any, str | None]:
    """Keep a signal only when the captured proving response shows it.

    A retest can clear a finding when the stored value is absent from the replayed response, so
    a mistyped or remembered value could clear a live one. With no signal stored, the retest
    judges by status as before. Returns ``(signal, warning)``. An unusable signal comes back
    untouched for the caller's validation to reject.
    """
    from strix.tools.proxy import caido_api  # noqa: PLC0415
    from strix.tools.proxy.tools import _call, resolve_proxy_client  # noqa: PLC0415

    signal, errors = normalize_proof_signal(raw)
    if errors or signal is None:
        return raw, None
    try:
        client = await resolve_proxy_client(ctx) if exchange_id else None
        if client is not None:
            result = await _call(
                client,
                lambda c: caido_api.get_request_with_client(c, str(exchange_id), part="response"),
            )
            response = getattr(result, "response", None)
            captured = getattr(response, "raw", None)
            if isinstance(captured, bytes | bytearray):
                captured = bytes(captured).decode("utf-8", errors="replace")
            roundtrip = getattr(response, "roundtrip_time", None)
            if captured and "timing" in signal and not roundtrip:
                return None, UNTIMED_WARNING
            if captured and _response_shows(signal, captured, roundtrip):
                return signal, None
    except Exception:  # noqa: BLE001 - an unreadable capture proves nothing about the signal
        logger.debug("proof signal check failed for %s", exchange_id, exc_info=True)
    return None, UNOBSERVED_WARNING
