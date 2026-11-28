# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""A report filed directly is held to the proof bar ``promote_finding`` applies."""

from __future__ import annotations

import asyncio
import json
import types
from typing import TYPE_CHECKING, Any

import pytest
from agents.tool_context import ToolContext

from strix.report.state import ReportState, set_global_report_state
from strix.tools.exploitation import tool as exploitation
from strix.tools.exploitation.tool import NO_EXCHANGE_SOURCE_REASON, PROOF_FAILED_PREFIX
from strix.tools.reporting.tool import (
    _HTTP_EXCHANGE_UNVERIFIED_WARNING,
    create_vulnerability_report,
    update_vulnerability_report,
)


if TYPE_CHECKING:
    from pathlib import Path


_GOOD = "gw-0123456789ab-" + "a" * 32
_OTHER = "gw-0123456789ab-" + "b" * 32
_CVSS = {
    "attack_vector": "N",
    "attack_complexity": "L",
    "privileges_required": "N",
    "user_interaction": "N",
    "scope": "U",
    "confidentiality": "H",
    "integrity": "H",
    "availability": "H",
}


class _Capture:
    _is_gateway_capture = True

    def __init__(self, known: set[str], *, down: bool = False) -> None:
        self.known = known
        self.down = down

    async def capture_exists(self, request_id: str) -> bool:
        if self.down:
            raise TimeoutError("capture backend timed out")
        return request_id in self.known

    async def view_request(self, request_id: str, *, part: str = "request") -> Any:
        if request_id not in self.known:
            return None
        return types.SimpleNamespace(
            request=types.SimpleNamespace(raw=b"GET /a?id=1%27 HTTP/1.1\r\n\r\n"),
            response=types.SimpleNamespace(raw=b"HTTP/1.1 500\r\n\r\nSQL syntax error"),
            part=part,
            integrity_sha256="f" * 64,
            integrity_verified=True,
            captured_at="2026-11-26T10:00:00Z",
        )


def _ctx(client: Any, name: str = "create_vulnerability_report") -> Any:
    context = {"caido_client": client} if client is not None else {}
    return ToolContext(context=context, tool_name=name, tool_call_id="c1", tool_arguments="{}")


@pytest.fixture
def report_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ReportState:
    monkeypatch.chdir(tmp_path)
    state = ReportState(run_name="proof-gate")
    set_global_report_state(state)
    yield state
    set_global_report_state(None)


def _report_args(**over: Any) -> dict[str, Any]:
    args: dict[str, Any] = {
        "title": "SQL injection in id",
        "description": "id is concatenated into a query.",
        "impact": "Database read.",
        "target": "https://app.example.com",
        "technical_analysis": "Unparameterized query.",
        "poc_description": "Send id=1'.",
        "poc_script_code": "curl 'https://app.example.com/a?id=1%27'",
        "remediation_steps": "Parameterize the query.",
        "evidence": "Response carries a SQL syntax error.",
        "assumptions": "The error is not a decoy.",
        "counterevidence": "No WAF response seen.",
        "confidence": "high",
        "severity_change_conditions": "A read-only role lowers impact.",
        "fix_effort": "low",
        "cvss_breakdown": _CVSS,
        "endpoint": "/a",
        "method": "GET",
    }
    args.update(over)
    return args


async def _file(client: Any, **over: Any) -> dict[str, Any]:
    out = await create_vulnerability_report.on_invoke_tool(
        _ctx(client), json.dumps(_report_args(**over))
    )
    result = json.loads(out)
    assert result["success"] is True, result
    return result


def _filed(report_state: ReportState) -> dict[str, Any]:
    assert len(report_state.vulnerability_reports) == 1
    return report_state.vulnerability_reports[0]


@pytest.mark.asyncio
async def test_a_verified_exchange_files_as_exploited(report_state: ReportState) -> None:
    await _file(_Capture({_GOOD}), http_exchange_ids=[_GOOD])
    report = _filed(report_state)
    assert report["proof_status"] == "exploited"
    assert report["proof_source"] == "gateway_capture"
    assert report["http_exchange_ids"] == [_GOOD]
    assert "proof_status_reason" not in report


@pytest.mark.asyncio
async def test_one_verified_id_is_enough(report_state: ReportState) -> None:
    await _file(_Capture({_GOOD}), http_exchange_ids=[_OTHER, _GOOD])
    report = _filed(report_state)
    assert report["proof_status"] == "exploited"
    assert report["http_exchange_ids"] == [_GOOD]


@pytest.mark.asyncio
async def test_poc_text_without_an_exchange_id_is_a_lead(report_state: ReportState) -> None:
    await _file(_Capture({_GOOD}))
    report = _filed(report_state)
    assert report["proof_status"] == "lead"
    assert report["proof_status_reason"].startswith(PROOF_FAILED_PREFIX)
    assert "no exchange id was cited" in report["proof_status_reason"]


@pytest.mark.asyncio
async def test_an_unknown_exchange_id_files_a_lead_and_drops_the_id(
    report_state: ReportState,
) -> None:
    await _file(_Capture({_GOOD}), http_exchange_ids=[_OTHER])
    report = _filed(report_state)
    assert report["proof_status"] == "lead"
    assert "not found in the exchange source" in report["proof_status_reason"]
    assert "http_exchange_ids" not in report or not report["http_exchange_ids"]


@pytest.mark.asyncio
async def test_a_proxy_outage_keeps_the_id_but_never_validates(report_state: ReportState) -> None:
    result = await _file(_Capture({_GOOD}, down=True), http_exchange_ids=[_GOOD])
    report = _filed(report_state)
    assert report["proof_status"] == "lead"
    assert "could not be queried" in report["proof_status_reason"]
    assert report["http_exchange_ids"] == [_GOOD]
    assert result["warning"] == _HTTP_EXCHANGE_UNVERIFIED_WARNING


@pytest.mark.asyncio
async def test_no_exchange_source_files_a_lead_with_its_own_reason(
    report_state: ReportState,
) -> None:
    await _file(None, http_exchange_ids=[_GOOD])
    report = _filed(report_state)
    assert report["proof_status"] == "lead"
    assert report["proof_status_reason"] == NO_EXCHANGE_SOURCE_REASON
    assert "proof_source" not in report
    assert report["http_exchange_ids"] == [_GOOD]


@pytest.mark.asyncio
async def test_a_malformed_exchange_id_is_still_rejected(report_state: ReportState) -> None:
    out = await create_vulnerability_report.on_invoke_tool(
        _ctx(_Capture({_GOOD})), json.dumps(_report_args(http_exchange_ids=["not an id"]))
    )
    assert json.loads(out)["success"] is False
    assert report_state.vulnerability_reports == []


_PROMOTE_FIELDS = {
    "impact": "Database read.",
    "technical_analysis": "Unparameterized query.",
    "poc_script_code": "curl 'https://app.example.com/a?id=1%27'",
    "remediation_steps": "Parameterize the query.",
    "assumptions": "The error is not a decoy.",
    "counterevidence": "No WAF response seen.",
    "severity_change_conditions": "A read-only role lowers impact.",
    "fix_effort": "low",
    "cvss_breakdown": _CVSS,
    "target": "https://app.example.com",
    "endpoint": "/a",
    "method": "GET",
}


async def _promote(
    client: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    exchange_id: str | None,
    *,
    control_id: str | None = None,
) -> dict[str, Any]:
    monkeypatch.chdir(tmp_path)
    state = ReportState(run_name="parity-promote")
    set_global_report_state(state)
    exploitation.hydrate_queue_from_disk(tmp_path)
    exploitation._queue["q-0001"] = {
        "id": "q-0001",
        "title": "SQL injection in id",
        "guard_evidence": "id is concatenated into a query.",
        "minimal_witness": "id=1'",
        "confidence": "high",
        "endpoint": "/a",
        "status": "queued",
        "verdict_reason": None,
    }
    args = {
        "item_id": "q-0001",
        "status": "exploited",
        "request": "GET /a?id=1%27",
        "response": "HTTP 500 SQL syntax error",
        "caido_request_id": exchange_id,
        "control_request_id": control_id,
        **_PROMOTE_FIELDS,
    }
    ctx = _ctx(client, "promote_finding")
    try:
        await exploitation.promote_finding.on_invoke_tool(ctx, json.dumps(args))
        assert len(state.vulnerability_reports) == 1
        return state.vulnerability_reports[0]
    finally:
        set_global_report_state(None)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("client_factory", "exchange_id"),
    [
        (lambda: _Capture({_GOOD}), _GOOD),
        (lambda: _Capture({_GOOD}), _OTHER),
        (lambda: _Capture({_GOOD}), None),
        (lambda: _Capture({_GOOD}, down=True), _GOOD),
        (lambda: None, _GOOD),
    ],
    ids=["verified", "unknown-id", "no-id", "proxy-outage", "no-source"],
)
async def test_both_tools_reach_the_same_proof_status(
    client_factory: Any,
    exchange_id: str | None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    promoted = await _promote(client_factory(), tmp_path, monkeypatch, exchange_id)

    monkeypatch.chdir(tmp_path)
    state = ReportState(run_name="parity-direct")
    set_global_report_state(state)
    try:
        ids = [exchange_id] if exchange_id else None
        out = await create_vulnerability_report.on_invoke_tool(
            _ctx(client_factory()), json.dumps(_report_args(http_exchange_ids=ids))
        )
        assert json.loads(out)["success"] is True, out
        direct = state.vulnerability_reports[0]
    finally:
        set_global_report_state(None)

    def decision(report: dict[str, Any]) -> tuple[Any, Any, Any]:
        return (
            report["proof_status"],
            report.get("proof_status_reason"),
            report.get("proof_source"),
        )

    assert decision(direct) == decision(promoted)


@pytest.mark.asyncio
async def test_a_no_source_report_without_ids_stores_none(report_state: ReportState) -> None:
    await _file(None)
    report = _filed(report_state)
    assert report["proof_status"] == "lead"
    assert report["proof_status_reason"] == NO_EXCHANGE_SOURCE_REASON
    assert not report.get("http_exchange_ids")


_MARKER = "captured-only-marker-7f3a"


class _Marked(_Capture):
    async def view_request(self, request_id: str, *, part: str = "request") -> Any:
        result = await super().view_request(request_id, part=part)
        if result is not None:
            result.response.raw = f"HTTP/1.1 200\r\n\r\n{_MARKER}".encode()
        return result


@pytest.mark.asyncio
async def test_a_verified_filing_keeps_the_captured_pair_out_of_the_run_files(
    report_state: ReportState, tmp_path: Path
) -> None:
    await _file(_Marked({_GOOD}), http_exchange_ids=[_OTHER, _GOOD])
    report = _filed(report_state)
    pairs = report_state.proof_captures[report["id"]]
    assert list(pairs) == [_GOOD]
    assert _MARKER in pairs[_GOOD]["response"]
    assert pairs[_GOOD]["request"].startswith("GET /a")
    report_state.save_run_data()
    written = [p for p in tmp_path.rglob("*") if p.is_file()]
    assert any(p.name == "vulnerabilities.json" for p in written)
    assert not [p for p in written if _MARKER.encode() in p.read_bytes()]


@pytest.mark.asyncio
async def test_a_lead_keeps_no_capture(report_state: ReportState) -> None:
    await _file(_Marked({_GOOD}, down=True), http_exchange_ids=[_GOOD])
    assert _filed(report_state)["proof_status"] == "lead"
    assert report_state.proof_captures == {}


@pytest.mark.asyncio
async def test_a_promotion_keeps_only_its_control_exchange(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    states: list[ReportState] = []
    make = ReportState

    def tracked(*args: Any, **kwargs: Any) -> ReportState:
        states.append(make(*args, **kwargs))
        return states[-1]

    monkeypatch.setattr(f"{__name__}.ReportState", tracked)
    report = await _promote(
        _Marked({_GOOD, _OTHER}), tmp_path, monkeypatch, _GOOD, control_id=_OTHER
    )
    assert report["proof_status"] == "exploited"
    assert list(states[0].proof_captures[report["id"]]) == [_OTHER]


@pytest.mark.asyncio
async def test_captures_follow_updates_and_deletion(report_state: ReportState) -> None:
    client = _Marked({_GOOD, _OTHER})
    await _file(client, http_exchange_ids=[_GOOD])
    report_id = _filed(report_state)["id"]

    async def cite(ids: list[str]) -> None:
        out = await update_vulnerability_report.on_invoke_tool(
            _ctx(client, "update_vulnerability_report"),
            json.dumps(
                {"report_id": report_id, "update_reason": "baseline", "http_exchange_ids": ids}
            ),
        )
        assert json.loads(out)["success"] is True, out

    await cite([_GOOD, _OTHER])
    assert set(report_state.proof_captures[report_id]) == {_GOOD, _OTHER}
    await cite([_OTHER])
    assert set(report_state.proof_captures[report_id]) == {_OTHER}
    report_state.delete_vulnerability_report(report_id, delete_reason="withdrawn")
    assert report_state.proof_captures == {}


class _AlteredOnRefetch(_Marked):
    """Passes its integrity check for the proof decision, then fails it."""

    fetches = 0

    async def view_request(self, request_id: str, *, part: str = "request") -> Any:
        result = await super().view_request(request_id, part=part)
        self.fetches += 1
        result.integrity_verified = self.fetches == 1
        return result


@pytest.mark.asyncio
async def test_a_capture_that_fails_its_check_when_kept_is_left_out(
    report_state: ReportState,
) -> None:
    await _file(_AlteredOnRefetch({_GOOD}), http_exchange_ids=[_GOOD])
    assert _filed(report_state)["proof_status"] == "exploited"
    entry = report_state.proof_captures[_filed(report_state)["id"]][_GOOD]
    assert list(entry) == ["unavailable"]


@pytest.mark.asyncio
async def test_an_id_dropped_while_fetching_is_not_kept(report_state: ReportState) -> None:
    class _Dropped(_Marked):
        async def view_request(self, request_id: str, *, part: str = "request") -> Any:
            for report in report_state.vulnerability_reports:
                report["http_exchange_ids"] = [_OTHER]
            return await super().view_request(request_id, part=part)

    await _file(_Dropped({_GOOD}), http_exchange_ids=[_GOOD])
    assert report_state.proof_captures == {}


@pytest.mark.asyncio
async def test_a_hung_capture_fetch_hits_the_deadline_and_the_report_still_files(
    report_state: ReportState, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _HangsOnSecond(_Marked):
        async def view_request(self, request_id: str, *, part: str = "request") -> Any:
            # The proof check reads _OTHER once; the fetch that keeps its bytes never returns.
            if request_id == _OTHER:
                self.other_reads += 1
                if self.other_reads > 1:
                    await asyncio.Event().wait()
            return await super().view_request(request_id, part=part)

    client = _HangsOnSecond({_GOOD, _OTHER})
    client.other_reads = 0
    monkeypatch.setattr(exploitation, "CAPTURE_DEADLINE_SECONDS", 0.2)
    async with asyncio.timeout(5):
        await _file(client, http_exchange_ids=[_GOOD, _OTHER])
    report = _filed(report_state)
    assert report["proof_status"] == "exploited"
    pairs = report_state.proof_captures[report["id"]]
    assert _MARKER in pairs[_GOOD]["response"]
    assert list(pairs[_OTHER]) == ["unavailable"]
