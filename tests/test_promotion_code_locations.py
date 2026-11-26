# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""A promoted report keeps the source location the candidate was queued with (recon#513)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest
from agents.tool_context import ToolContext

from strix.report.state import ReportState, set_global_report_state
from strix.tools.exploitation import tool as ex


if TYPE_CHECKING:
    from pathlib import Path

_CVSS = {
    "attack_vector": "N", "attack_complexity": "L", "privileges_required": "N",
    "user_interaction": "N", "scope": "U", "confidentiality": "H",
    "integrity": "H", "availability": "H",
}
_FIELDS = {
    "impact": "I", "technical_analysis": "TA", "poc_script_code": "curl x",
    "remediation_steps": "fix", "assumptions": "A", "counterevidence": "C",
    "severity_change_conditions": "S", "fix_effort": "low", "cvss_breakdown": _CVSS,
}


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("app/views.py:42", [{"file": "app/views.py", "start_line": 42, "end_line": 42}]),
        ("app/views.py:42-57", [{"file": "app/views.py", "start_line": 42, "end_line": 57}]),
        ("app/views.py#L42-L57", [{"file": "app/views.py", "start_line": 42, "end_line": 57}]),
        ("app/my views.py:7", [{"file": "app/my views.py", "start_line": 7, "end_line": 7}]),
        ("app/views.py", None),
        ("app/views.py:abc", None),
        ("../etc/passwd:3", None),
        ("/etc/passwd:3", None),
        ("app/views.py:50-40", None),
        ("app/views.py:" + "9" * 5000, None),
        ("", None),
        (None, None),
    ],
)
def test_the_queued_location_parses_or_is_ignored(raw: str | None, expected: Any) -> None:
    assert ex._queued_code_locations({"vulnerable_code_location": raw}) == expected


async def _promote(
    args: dict[str, Any], item: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[dict, ReportState]:
    monkeypatch.chdir(tmp_path)  # ReportState writes recon_runs/ under the current directory
    ex.hydrate_queue_from_disk(tmp_path)
    ex._queue["q-0001"] = {
        "id": "q-0001", "title": "SQLi", "guard_evidence": "g", "minimal_witness": "w",
        "confidence": "high", "endpoint": "/x", "status": "queued", **item,
    }
    rs = ReportState("run")
    set_global_report_state(rs)
    ctx = ToolContext(
        context={}, tool_name="promote_finding", tool_call_id="c", tool_arguments="{}"
    )
    try:
        out = await ex.promote_finding.on_invoke_tool(
            ctx, json.dumps({"item_id": "q-0001", **args})
        )
    finally:
        set_global_report_state(None)
    return json.loads(out), rs


def _exploited(**extra: Any) -> dict[str, Any]:
    # No exchange source in this context, so the claim files as a lead: it still goes through
    # _do_create, which is the path that carries the location.
    return {"status": "exploited", "request": "GET /x", "response": "200 OK", **_FIELDS, **extra}


@pytest.mark.asyncio
async def test_a_downgraded_promotion_keeps_the_queued_location(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out, rs = await _promote(
        _exploited(), {"vulnerable_code_location": "app/views.py:42-57"}, tmp_path, monkeypatch
    )
    assert out["success"] is True, out
    assert rs.vulnerability_reports[0]["code_locations"] == [
        {"file": "app/views.py", "start_line": 42, "end_line": 57}
    ]


@pytest.mark.asyncio
async def test_structured_locations_win_over_the_queued_string(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    structured = [{"file": "app/auth.py", "start_line": 10, "end_line": 12, "snippet": "x = 1"}]
    out, rs = await _promote(
        _exploited(code_locations=structured),
        {"vulnerable_code_location": "app/views.py:42"},
        tmp_path,
        monkeypatch,
    )
    assert out["success"] is True, out
    assert rs.vulnerability_reports[0]["code_locations"] == structured


@pytest.mark.asyncio
async def test_an_unparsable_location_does_not_stop_the_promotion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out, rs = await _promote(
        _exploited(), {"vulnerable_code_location": "somewhere in the views"}, tmp_path, monkeypatch
    )
    assert out["success"] is True, out
    assert "code_locations" not in rs.vulnerability_reports[0]


@pytest.mark.asyncio
async def test_structured_snippets_are_redacted_before_filing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Recon's redactor is not importable standalone, so stand one in.
    monkeypatch.setattr(ex, "_REDACT_CACHED", True)
    monkeypatch.setattr(ex, "_REDACT_FN", lambda t: t.replace("LEAKEDSECRET99", "[REDACTED]"))
    loc = [{"file": "a.py", "start_line": 1, "end_line": 1, "snippet": "api_key=LEAKEDSECRET99"}]
    out, rs = await _promote(_exploited(code_locations=loc), {}, tmp_path, monkeypatch)
    assert out["success"] is True, out
    assert "LEAKEDSECRET99" not in json.dumps(rs.vulnerability_reports[0]["code_locations"])


@pytest.mark.asyncio
async def test_structured_locations_apply_to_a_plain_lead_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    loc = [{"file": "a.py", "start_line": 5, "end_line": 6}]
    args = {"status": "lead", "reason": "blocked", "code_locations": loc}
    out, rs = await _promote(args, {"vulnerable_code_location": "b.py:1"}, tmp_path, monkeypatch)
    assert out["success"] is True, out
    assert rs.vulnerability_reports[0]["code_locations"] == loc


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", [[{"snippet": "x"}], [{"file": "a.py", "start_line": 3}]])
async def test_unusable_structured_locations_are_refused_not_ignored(
    bad: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    item = {"vulnerable_code_location": "b.py:1"}
    out, rs = await _promote(_exploited(code_locations=bad), item, tmp_path, monkeypatch)
    assert out["success"] is False and out["retriable"] is True, out
    assert ex._queue["q-0001"]["status"] == "queued" and not rs.vulnerability_reports


@pytest.mark.asyncio
async def test_invalid_structured_locations_are_refused_and_the_item_stays_queued(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bad = [{"file": "../x.py", "start_line": 1, "end_line": 1}]
    out, rs = await _promote(_exploited(code_locations=bad), {}, tmp_path, monkeypatch)
    assert out["success"] is False, out
    assert ex._queue["q-0001"]["status"] == "queued" and not rs.vulnerability_reports


@pytest.mark.asyncio
async def test_a_plain_lead_verdict_and_the_boundary_drain_keep_the_location(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    item = {"vulnerable_code_location": "app/views.py:9"}
    out, rs = await _promote({"status": "lead", "reason": "blocked"}, item, tmp_path, monkeypatch)
    assert out["success"] is True, out
    assert rs.vulnerability_reports[0]["code_locations"][0]["start_line"] == 9
    set_global_report_state(rs)
    try:
        ex._queue["q-0002"] = {
            "id": "q-0002", "title": "T2", "guard_evidence": "g", "minimal_witness": "w",
            "confidence": "low", "endpoint": "/y", "status": "queued",
            "vulnerable_code_location": "app/other.py:3-4",
        }
        assert ex.drain_pending_to_leads("boundary") == 1
    finally:
        set_global_report_state(None)
    assert rs.vulnerability_reports[1]["code_locations"] == [
        {"file": "app/other.py", "start_line": 3, "end_line": 4}
    ]
