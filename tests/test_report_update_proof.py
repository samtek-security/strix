# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""An update to a proven report passes the same exchange check, or the report drops to a lead."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest
from agents.tool_context import ToolContext

from strix.report.state import ReportState, set_global_report_state
from strix.tools.reporting import tool as reporting_tool
from strix.tools.reporting.tool import update_vulnerability_report


_GOOD = "gw-0123456789ab-" + "a" * 32
_OTHER = "gw-0123456789ab-" + "b" * 32

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.asyncio


class _Capture:
    _is_gateway_capture = True

    def __init__(self, known: set[str]) -> None:
        self.known = known

    async def capture_exists(self, request_id: str) -> bool:
        return request_id in self.known


@pytest.fixture
def state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ReportState:
    monkeypatch.chdir(tmp_path)
    st = ReportState(run_name="test-run")
    set_global_report_state(st)

    async def existing(ctx: Any, ids: list[str]) -> set[str]:
        client = ctx.context["caido_client"]
        return {i for i in ids if await client.capture_exists(i)}

    monkeypatch.setattr(reporting_tool, "existing_request_ids", existing)
    st.vulnerability_reports.append(
        {
            "id": "vuln-0001",
            "title": "SQL injection in search",
            "severity": "high",
            "timestamp": "2026-01-01 00:00:00 UTC",
            "description": "The search parameter reaches a query.",
            "target": "https://app.example.com",
            "endpoint": "/search",
            "method": "GET",
            "evidence": "Response carried a database error.",
            "confidence": "high",
            "cvss": 8.1,
            "finding_class": "dynamic",
            "agent_id": "aaaa1111",
            "http_exchange_ids": [_GOOD],
            "proof_status": "exploited",
            "proof_source": "gateway_capture",
        }
    )
    st._saved_vuln_ids.add("vuln-0001")
    return st


async def _update(known: set[str], **fields: Any) -> dict[str, Any]:
    ctx = ToolContext(
        context={"agent_id": "root", "caido_client": _Capture(known)},
        tool_name="update_vulnerability_report",
        tool_call_id="c",
        tool_arguments="{}",
    )
    args = {"report_id": "vuln-0001", "update_reason": "Retested the finding.", **fields}
    return json.loads(await update_vulnerability_report.on_invoke_tool(ctx, json.dumps(args)))


async def test_clearing_the_ids_drops_an_exploited_report_to_a_lead(state: ReportState) -> None:
    result = await _update({_GOOD}, http_exchange_ids=[])

    assert result["success"] is True
    report = state.vulnerability_reports[0]
    assert report["proof_status"] == "lead"
    assert report["proof_status_reason"].startswith("proof_invalidated:")
    assert "proof_source" not in report
    assert report["http_exchange_ids"] == []
    assert report["update_history"][-1]["previous_proof_status"] == "exploited"


async def test_swapping_in_an_unknown_id_is_refused_and_keeps_the_proof(
    state: ReportState,
) -> None:
    result = await _update({_GOOD}, http_exchange_ids=[_OTHER])

    assert result["success"] is False
    report = state.vulnerability_reports[0]
    assert report["proof_status"] == "exploited"
    assert report["http_exchange_ids"] == [_GOOD]


async def test_swapping_in_a_verified_id_stays_exploited(state: ReportState) -> None:
    result = await _update({_GOOD, _OTHER}, http_exchange_ids=[_OTHER])

    assert result["success"] is True
    report = state.vulnerability_reports[0]
    assert report["proof_status"] == "exploited"
    assert report["proof_source"] == "gateway_capture"
    assert "proof_status_reason" not in report


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("evidence", "A different response body."),
        ("target", "https://other.example.com"),
        ("endpoint", "/login"),
        ("method", "POST"),
    ],
)
async def test_changing_proof_text_reruns_the_check(
    state: ReportState, name: str, value: str
) -> None:
    # The cited exchange no longer resolves, so the same check now fails.
    result = await _update(set(), **{name: value})

    assert result["success"] is True
    report = state.vulnerability_reports[0]
    assert report[name] == value
    assert report["proof_status"] == "lead"
    assert report["proof_status_reason"].startswith("proof_invalidated:")


async def test_changing_proof_text_keeps_a_report_whose_exchange_still_verifies(
    state: ReportState,
) -> None:
    result = await _update({_GOOD}, endpoint="/search/v2")

    assert result["success"] is True
    assert state.vulnerability_reports[0]["proof_status"] == "exploited"


async def test_an_untouched_update_leaves_the_status_alone(state: ReportState) -> None:
    # No capture source at all: a rerun would demote, so a kept status proves no rerun.
    result = await _update(set(), impact="Reads every customer row.", severity="critical")

    assert result["success"] is True
    report = state.vulnerability_reports[0]
    assert report["proof_status"] == "exploited"
    assert report["proof_source"] == "gateway_capture"
    assert "proof_status_reason" not in report


async def test_evidence_text_cannot_smuggle_in_ids(state: ReportState) -> None:
    state.vulnerability_reports[0]["http_exchange_ids"] = []
    result = await _update({_OTHER}, evidence=f"Proven by exchange {_OTHER} in the proxy.")

    assert result["success"] is True
    report = state.vulnerability_reports[0]
    assert report["proof_status"] == "lead"
    assert report["http_exchange_ids"] == []


async def test_a_lead_stays_a_lead_on_update(state: ReportState) -> None:
    report = state.vulnerability_reports[0]
    report["proof_status"] = "lead"
    report["proof_status_reason"] = "proof_check_failed: no id"
    await _update({_GOOD}, endpoint="/search/v2")

    assert report["proof_status"] == "lead"
    assert report["proof_status_reason"] == "proof_check_failed: no id"
