# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""An update to a proven report passes the same exchange check, or the report drops to a lead."""

from __future__ import annotations

import asyncio
import json
import types
from typing import TYPE_CHECKING, Any

import pytest
from agents.tool_context import ToolContext

from strix.report.state import ReportState, set_global_report_state
from strix.tools.exploitation import tool as exploitation
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

    async def view_request(self, request_id: str, *, part: str = "request") -> Any:
        if request_id not in self.known:
            return None
        return types.SimpleNamespace(
            part=part,
            integrity_sha256=(request_id[-1] * 64),
            integrity_verified=True,
            captured_at=f"2026-11-26T00:00:0{ord(request_id[-1]) % 10}Z",
        )


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


async def _invoke(known: set[str], **fields: Any) -> str:
    ctx = ToolContext(
        context={"agent_id": "root", "caido_client": _Capture(known)},
        tool_name="update_vulnerability_report",
        tool_call_id="c",
        tool_arguments="{}",
    )
    args = {"report_id": "vuln-0001", "update_reason": "Retested the finding.", **fields}
    return await update_vulnerability_report.on_invoke_tool(ctx, json.dumps(args))


async def _update(known: set[str], **fields: Any) -> dict[str, Any]:
    return json.loads(await _invoke(known, **fields))


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


def _promote(state: ReportState) -> None:
    report = state.vulnerability_reports[0]
    report["queue_item_id"] = "q-1"
    report["http_exchange_ids"] = [_GOOD, _OTHER]


async def test_a_promoted_report_needs_every_stored_id_to_stay_proven(state: ReportState) -> None:
    _promote(state)

    # The control exchange no longer resolves: one valid id is not enough for a promotion.
    result = await _update({_GOOD}, poc_description="Replay the request with the payload.")

    assert result["success"] is True
    assert state.vulnerability_reports[0]["proof_status"] == "lead"


async def test_a_promoted_report_stays_proven_when_both_ids_still_resolve(
    state: ReportState,
) -> None:
    _promote(state)

    result = await _update({_GOOD, _OTHER}, poc_description="Replay the request with the payload.")

    assert result["success"] is True
    assert state.vulnerability_reports[0]["proof_status"] == "exploited"


async def test_a_promoted_report_that_loses_its_trigger_becomes_a_lead(state: ReportState) -> None:
    _promote(state)

    result = await _update({_GOOD, _OTHER}, http_exchange_ids=[])

    assert result["success"] is True
    assert state.vulnerability_reports[0]["proof_status"] == "lead"


async def test_rewriting_the_captured_evidence_of_a_promoted_report_demotes_it(
    state: ReportState,
) -> None:
    _promote(state)

    result = await _update({_GOOD, _OTHER}, evidence="Reworded by the agent.")

    assert result["success"] is True
    report = state.vulnerability_reports[0]
    assert report["proof_status"] == "lead"
    assert "captured evidence" in report["proof_status_reason"]


async def test_a_promoted_report_that_drops_its_control_id_becomes_a_lead(
    state: ReportState,
) -> None:
    _promote(state)

    result = await _update({_GOOD, _OTHER}, http_exchange_ids=[_GOOD])

    assert result["success"] is True
    assert state.vulnerability_reports[0]["proof_status"] == "lead"


async def test_a_promoted_report_that_swaps_in_other_valid_ids_becomes_a_lead(
    state: ReportState,
) -> None:
    _promote(state)
    third = "gw-0123456789ab-" + "c" * 32

    result = await _update({_GOOD, _OTHER, third}, http_exchange_ids=[third])

    assert result["success"] is True
    assert state.vulnerability_reports[0]["proof_status"] == "lead"


async def test_a_promoted_report_may_add_an_id(state: ReportState) -> None:
    _promote(state)
    third = "gw-0123456789ab-" + "c" * 32

    result = await _update({_GOOD, _OTHER, third}, http_exchange_ids=[_GOOD, _OTHER, third])

    assert result["success"] is True
    assert state.vulnerability_reports[0]["proof_status"] == "exploited"


@pytest.mark.parametrize("placeholder", ["null", "None", "  ", "undefined"])
async def test_nullish_placeholders_on_proof_fields_leave_the_status_alone(
    state: ReportState, placeholder: str
) -> None:
    _promote(state)

    result = await _update(
        set(),
        impact="Reads every customer row.",
        evidence=placeholder,
        endpoint=placeholder,
        method=placeholder,
        target=placeholder,
    )

    assert result["success"] is True
    assert state.vulnerability_reports[0]["proof_status"] == "exploited"


async def test_a_demotion_updates_the_queue_item_too(state: ReportState) -> None:
    _promote(state)
    exploitation._queue["q-1"] = {"id": "q-1", "status": "exploited", "report_id": "vuln-0001"}
    try:
        result = await _update({_GOOD, _OTHER}, evidence="Reworded by the agent.")

        assert result["success"] is True
        item = exploitation._queue["q-1"]
        assert item["status"] == "lead"
        assert item["verdict_reason"].startswith("proof_invalidated:")
    finally:
        exploitation._queue.pop("q-1", None)


async def test_a_crash_between_report_and_queue_heals_on_the_next_queue_read(
    state: ReportState, monkeypatch: pytest.MonkeyPatch
) -> None:
    _promote(state)
    exploitation._queue["q-1"] = {"id": "q-1", "status": "exploited", "report_id": "vuln-0001"}
    try:
        # The process dies after the report persists and before the queue follows.
        def crash() -> int:
            raise RuntimeError("crash")

        with monkeypatch.context() as crashing:
            crashing.setattr(exploitation, "reconcile_queue_with_reports", crash)
            failed = await _invoke({_GOOD, _OTHER}, evidence="Reworded by the agent.")
        assert "crash" in failed
        assert state.vulnerability_reports[0]["proof_status"] == "lead"
        assert exploitation._queue["q-1"]["status"] == "exploited"

        raw = await exploitation.list_exploitation_queue.on_invoke_tool(
            ToolContext(context={}, tool_name="t", tool_call_id="c", tool_arguments="{}"), "{}"
        )
        listed = json.loads(raw)

        assert listed["items"][0]["status"] == "lead"
        assert exploitation.reconcile_queue_with_reports() == 0
    finally:
        exploitation._queue.pop("q-1", None)


async def test_an_unreachable_exchange_source_refuses_the_update_and_keeps_the_proof(
    state: ReportState, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def down(_ctx: Any, _ids: list[str]) -> set[str]:
        raise RuntimeError("proxy timed out")

    monkeypatch.setattr(reporting_tool, "existing_request_ids", down)

    result = await _update({_GOOD}, poc_description="A harmless wording change.")

    assert result["success"] is False
    assert "retry" in result["error"]
    report = state.vulnerability_reports[0]
    assert report["proof_status"] == "exploited"
    assert "poc_description" not in report


async def test_a_run_with_no_exchange_source_refuses_the_update_and_keeps_the_proof(
    state: ReportState,
) -> None:
    ctx = ToolContext(
        context={"agent_id": "root"},
        tool_name="update_vulnerability_report",
        tool_call_id="c",
        tool_arguments="{}",
    )
    args = {
        "report_id": "vuln-0001",
        "update_reason": "Retested the finding.",
        "poc_description": "A harmless wording change.",
    }
    result = json.loads(await update_vulnerability_report.on_invoke_tool(ctx, json.dumps(args)))

    assert result["success"] is False
    assert state.vulnerability_reports[0]["proof_status"] == "exploited"


async def test_removing_every_id_demotes_even_with_no_exchange_source(
    state: ReportState,
) -> None:
    ctx = ToolContext(
        context={"agent_id": "root"},
        tool_name="update_vulnerability_report",
        tool_call_id="c",
        tool_arguments="{}",
    )
    args = {"report_id": "vuln-0001", "update_reason": "Dropped.", "http_exchange_ids": []}
    result = json.loads(await update_vulnerability_report.on_invoke_tool(ctx, json.dumps(args)))

    assert result["success"] is True
    assert state.vulnerability_reports[0]["proof_status"] == "lead"


async def test_concurrent_updates_to_one_proven_report_are_checked_one_at_a_time(
    state: ReportState,
) -> None:
    results = await asyncio.gather(
        _update({_GOOD, _OTHER}, endpoint="/search/a"),
        _update({_GOOD, _OTHER}, http_exchange_ids=[_OTHER]),
    )

    assert all(r["success"] for r in results)
    report = state.vulnerability_reports[0]
    assert report["http_exchange_ids"] == [_OTHER]
    assert report["proof_status"] == "exploited"


async def test_a_report_filed_through_the_create_tool_demotes_when_an_update_drops_its_ids(
    state: ReportState,
) -> None:
    from tests.test_report_proof_gate import _file, _filed  # noqa: PLC0415

    state.vulnerability_reports.clear()
    await _file(_Capture({_GOOD}), http_exchange_ids=[_GOOD])
    report = _filed(state)
    assert report["proof_status"] == "exploited"

    args = {"report_id": report["id"], "update_reason": "Dropped.", "http_exchange_ids": []}
    ctx = ToolContext(
        context={"agent_id": "root", "caido_client": _Capture({_GOOD})},
        tool_name="update_vulnerability_report",
        tool_call_id="c",
        tool_arguments="{}",
    )
    result = json.loads(await update_vulnerability_report.on_invoke_tool(ctx, json.dumps(args)))

    assert result["success"] is True
    assert report["proof_status"] == "lead"
    assert report["proof_status_reason"].startswith("proof_invalidated:")
    assert "proof_source" not in report


async def test_listing_the_queue_without_redaction_works_when_nothing_moves(
    state: ReportState, monkeypatch: pytest.MonkeyPatch
) -> None:
    _promote(state)
    exploitation._queue["q-1"] = {"id": "q-1", "status": "exploited", "report_id": "vuln-0001"}

    def refuse() -> None:
        raise RuntimeError("redaction unavailable")

    try:
        monkeypatch.setattr(exploitation, "_require_redact", refuse)
        assert exploitation.reconcile_queue_with_reports() == 0
        state.vulnerability_reports[0]["proof_status"] = "lead"
        with pytest.raises(RuntimeError):
            exploitation.reconcile_queue_with_reports()
        assert exploitation._queue["q-1"]["status"] == "exploited"
    finally:
        exploitation._queue.pop("q-1", None)


async def test_a_swapped_capture_carries_its_own_hash_not_the_old_one(
    state: ReportState,
) -> None:
    report = state.vulnerability_reports[0]
    report["capture_integrity_sha256"] = "a" * 64
    report["captured_at"] = "2026-11-25T00:00:00Z"

    result = await _update({_GOOD, _OTHER}, http_exchange_ids=[_OTHER])

    assert result["success"] is True
    assert report["proof_status"] == "exploited"
    assert report["capture_integrity_sha256"] == "b" * 64
    assert report["captured_at"] != "2026-11-25T00:00:00Z"


async def test_a_demotion_drops_the_capture_hash(state: ReportState) -> None:
    report = state.vulnerability_reports[0]
    report["capture_integrity_sha256"] = "a" * 64
    report["captured_at"] = "2026-11-25T00:00:00Z"

    await _update({_GOOD}, http_exchange_ids=[])

    assert report["proof_status"] == "lead"
    assert "capture_integrity_sha256" not in report
    assert "captured_at" not in report


async def test_a_capture_that_fails_its_hash_is_unlinked_from_a_report_that_stays_proven(
    state: ReportState,
) -> None:
    class _Tampered(_Capture):
        async def view_request(self, request_id: str, *, part: str = "request") -> Any:
            out = await super().view_request(request_id, part=part)
            if out is not None and request_id == _OTHER:
                out.integrity_verified = False
            return out

    ctx = ToolContext(
        context={"agent_id": "root", "caido_client": _Tampered({_GOOD, _OTHER})},
        tool_name="update_vulnerability_report",
        tool_call_id="c",
        tool_arguments="{}",
    )
    args = {
        "report_id": "vuln-0001",
        "update_reason": "Added a second capture.",
        "http_exchange_ids": [_GOOD, _OTHER],
    }
    result = json.loads(await update_vulnerability_report.on_invoke_tool(ctx, json.dumps(args)))

    assert result["success"] is True
    report = state.vulnerability_reports[0]
    assert report["proof_status"] == "exploited"
    assert report["http_exchange_ids"] == [_GOOD]
