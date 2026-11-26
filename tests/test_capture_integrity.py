# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""Gateway capture integrity is checked at promotion and recorded on the report (recon#512)."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest
from agents.tool_context import ToolContext

from strix.report.state import ReportState, set_global_report_state
from strix.report.writer import render_vulnerability_md
from strix.tools.exploitation import tool as ex


if TYPE_CHECKING:
    from pathlib import Path

_ID = "gw-0123456789ab-" + "a" * 32
_SHA = "b" * 64
_STAMP = "2026-11-26T10:00:00Z"
_CVSS = {
    "attack_vector": "N", "attack_complexity": "L", "privileges_required": "N",
    "user_interaction": "N", "scope": "U", "confidentiality": "H",
    "integrity": "H", "availability": "H",
}


class _Gateway:
    _is_gateway_capture = True

    def __init__(self, *, verified: bool | None, sha: str | None = _SHA) -> None:
        self.verified = verified
        self.sha = sha

    async def capture_exists(self, request_id: str) -> bool:
        return request_id == _ID

    async def view_request(self, request_id: str, *, part: str = "request") -> Any:
        del request_id, part
        extra: dict[str, Any] = {}
        if self.verified is not None:
            extra["integrity_verified"] = self.verified
        return SimpleNamespace(
            request=SimpleNamespace(raw="GET /x HTTP/1.1\r\n\r\n"),
            response=SimpleNamespace(raw="HTTP/1.1 200 OK\r\n\r\nusers"),
            integrity_sha256=self.sha,
            captured_at=_STAMP,
            **extra,
        )


async def _promote(
    client: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[dict, ReportState]:
    monkeypatch.chdir(tmp_path)  # ReportState writes recon_runs/ under the current directory
    ex.hydrate_queue_from_disk(tmp_path)
    ex._queue["q-0001"] = {
        "id": "q-0001", "title": "SQLi", "guard_evidence": "raw concat", "minimal_witness": "id=1",
        "confidence": "high", "endpoint": "/x", "status": "queued",
    }
    rs = ReportState("run")
    set_global_report_state(rs)
    args = {
        "item_id": "q-0001", "status": "exploited", "caido_request_id": _ID,
        "impact": "I", "technical_analysis": "TA", "poc_script_code": "curl x",
        "remediation_steps": "fix", "assumptions": "A", "counterevidence": "C",
        "severity_change_conditions": "S", "fix_effort": "low", "cvss_breakdown": _CVSS,
    }
    ctx = ToolContext(
        context={"caido_client": client}, tool_name="promote_finding",
        tool_call_id="c", tool_arguments="{}",
    )
    try:
        out = await ex.promote_finding.on_invoke_tool(ctx, json.dumps(args))
    finally:
        set_global_report_state(None)
    return json.loads(out), rs


@pytest.mark.asyncio
async def test_a_verified_capture_records_its_hash_and_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out, rs = await _promote(_Gateway(verified=True), tmp_path, monkeypatch)
    assert out["verdict"] == "exploited", out
    report = rs.vulnerability_reports[0]
    assert report["capture_integrity_sha256"] == _SHA
    assert report["captured_at"] == _STAMP
    md = render_vulnerability_md(report)
    assert _SHA in md and _STAMP in md


@pytest.mark.asyncio
@pytest.mark.parametrize("verified", [False, None])
async def test_a_capture_that_does_not_verify_files_a_lead(
    verified: bool | None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out, rs = await _promote(_Gateway(verified=verified), tmp_path, monkeypatch)
    assert out["verdict"] == "lead", out
    assert "integrity could not be verified" in out["reason"]
    report = rs.vulnerability_reports[0]
    assert report["proof_status"] == "lead"
    assert "capture_integrity_sha256" not in report and "proof_source" not in report
    assert "http_exchange_ids" not in report


@pytest.mark.asyncio
async def test_a_capture_with_no_recorded_hash_files_a_lead(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out, rs = await _promote(_Gateway(verified=True, sha=None), tmp_path, monkeypatch)
    assert out["verdict"] == "lead", out
    assert "capture_integrity_sha256" not in rs.vulnerability_reports[0]
