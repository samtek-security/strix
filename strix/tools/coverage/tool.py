# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""Grey-box coverage evidence — per-role access-control probes.

``record_probe`` logs ONE authenticated per-role action outcome ({role, endpoint, check,
outcome}). These aggregate into the per-role coverage table (endpoints tested, access-
control / IDOR / tenant-isolation checks, denied-as-expected) that the CCIC/auditor package
needs as proof of which roles were actually exercised. A live run that records these shows
REAL coverage instead of the declared-only zeros. Mirrored to ``{state_dir}/role_probes.json``
(same durable pattern as notes/todos/exploitation-queue) so it survives a resume.
"""

from __future__ import annotations

import json
import logging
import tempfile
import threading
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)

VALID_CHECKS = ("authn", "access-control", "idor", "tenant-isolation")
VALID_OUTCOMES = ("allowed", "denied", "vulnerable")

_probes: list[dict[str, Any]] = []
_probes_path: Path | None = None
_io_lock = threading.RLock()


def hydrate_probes_from_disk(state_dir: Path) -> None:
    global _probes_path  # noqa: PLW0603
    _probes_path = state_dir / "role_probes.json"
    with _io_lock:
        _probes.clear()
        if not _probes_path.exists():
            return
        try:
            data = json.loads(_probes_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.exception("role_probes.json unreadable; starting empty")
            return
        if isinstance(data, list):
            _probes.extend(p for p in data if isinstance(p, dict))
            logger.info("role probes hydrated (%d)", len(_probes))


def _persist() -> None:
    path = _probes_path
    if path is None:
        return
    try:
        with _io_lock:
            payload = json.dumps(_probes, ensure_ascii=False, default=str)
            path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=str(path.parent),
                prefix=f".{path.name}.", suffix=".tmp", delete=False,
            ) as tmp:
                tmp.write(payload)
                tmp_path = Path(tmp.name)
            tmp_path.replace(path)
    except Exception:
        logger.exception("role probes persist failed")


def all_probes() -> list[dict[str, Any]]:
    """The recorded probes, for the activity to fold into per-role coverage."""
    with _io_lock:
        return list(_probes)


@function_tool(timeout=30)
async def record_probe(
    ctx: RunContextWrapper,
    role: str,
    endpoint: str,
    check: str,
    outcome: str,
) -> str:
    """Record ONE authenticated per-role access-control probe (grey-box coverage evidence).

    Call this EVERY time you test whether a role CAN or CANNOT reach an endpoint/object —
    INCLUDING the ones that are correctly blocked (a denied cross-role access is coverage
    evidence, not nothing). These aggregate into the per-role coverage table shown to the
    CCIC/auditor; a run that skips them shows zero coverage even after real testing.

    Args:
        role: the role you acted AS — match a configured auth role (e.g. "Administrator",
            "Cloud User").
        endpoint: the endpoint/object you probed (e.g. "/api/graphql users",
            "/rest/basket/2").
        check: `authn` (you authenticated as the role) | `access-control` (function-level
            authorization) | `idor` (object-level / direct object reference) |
            `tenant-isolation` (cross-tenant access).
        outcome: `allowed` (the role could do it) | `denied` (correctly blocked) |
            `vulnerable` (should have been blocked but wasn't — ALSO file a finding).
    """
    c = (check or "").strip().lower()
    o = (outcome or "").strip().lower()
    if c not in VALID_CHECKS:
        return json.dumps({"success": False, "error": f"check must be one of {VALID_CHECKS}"})
    if o not in VALID_OUTCOMES:
        return json.dumps({"success": False, "error": f"outcome must be one of {VALID_OUTCOMES}"})
    if len(_probes) >= 2000:
        return json.dumps({"success": False, "error": "probe log is full (2000)"})
    with _io_lock:
        _probes.append({
            "role": (role or "").strip() or "unknown",
            "endpoint": (endpoint or "").strip(),
            "check": c,
            "outcome": o,
        })
    _persist()
    return json.dumps({"success": True, "recorded": len(_probes)})
