# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""The retest signal fields: what the report tools accept, store and drop."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast

import pytest
from agents.tool_context import ToolContext

from strix.report.state import ReportState, get_global_report_state, set_global_report_state
from strix.tools.exploitation import tool as ex
from strix.tools.proxy import tools as proxy_tools
from strix.tools.reporting import tool as reporting_tool
from strix.tools.reporting.proof_signal import (
    UNOBSERVED_WARNING,
    UNTIMED_WARNING,
    normalize_auth_role,
    normalize_proof_signal,
    observed_proof_signal,
)
from strix.tools.reporting.tool import _do_create, _do_update, update_vulnerability_report
from tests.test_promotion_code_locations import _exploited, _promote


if TYPE_CHECKING:
    from pathlib import Path


_SECRET = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789"  # noqa: S105
_TIMING = {"delay_ms": 5000, "baseline_ms": 120, "tolerance_ms": 1000}
_SIGNAL = {"body_marker": "root:x:0:0"}


@pytest.fixture
def report_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ReportState:
    monkeypatch.chdir(tmp_path)
    state = ReportState(run_name="test-run")
    set_global_report_state(state)
    return state


async def _create(**extra: Any) -> dict[str, Any]:
    text = dict.fromkeys(
        (
            "title",
            "description",
            "impact",
            "target",
            "technical_analysis",
            "poc_description",
            "poc_script_code",
            "remediation_steps",
            "evidence",
            "assumptions",
            "counterevidence",
            "severity_change_conditions",
        ),
        "x",
    )
    extra.setdefault("proof_status", "exploited")
    extra.setdefault("http_exchange_ids", ["1"])
    return await _do_create(
        **text,
        confidence="high",
        fix_effort="low",
        cvss_breakdown={
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "U",
            "confidentiality": "H",
            "integrity": "N",
            "availability": "N",
        },
        endpoint="/download",
        method="GET",
        cve=None,
        cwe="CWE-22",
        code_locations=None,
        **extra,
    )


_RESPONSE = b"HTTP/1.1 200 OK\r\nX-Debug: full stack\r\n\r\nroot:x:0:0:root:/root"


def _capture(monkeypatch: pytest.MonkeyPatch, raw: bytes = _RESPONSE, roundtrip: int = 0) -> None:
    async def client(_ctx: Any) -> object:
        return object()

    async def call(_client: Any, _fn: Any) -> Any:
        return SimpleNamespace(response=SimpleNamespace(raw=raw, roundtrip_time=roundtrip))

    monkeypatch.setattr(proxy_tools, "resolve_proxy_client", client)
    monkeypatch.setattr(proxy_tools, "_call", call)


@pytest.mark.parametrize(
    ("signal", "roundtrip", "kept"),
    [
        (_SIGNAL, 0, True),
        ({"reflection": "root:/root"}, 0, True),
        ({"body_marker": "root:x:0:1"}, 0, False),
        ({"body_marker": "full stack"}, 0, False),
        ({"header": {"name": "x-debug", "contains": "stack"}}, 0, True),
        ({"header": {"name": "X-Debug"}}, 0, True),
        ({"header": {"name": "X-Other"}}, 0, False),
        ({"timing": _TIMING}, 5100, True),
        ({"timing": _TIMING}, 200, False),
        ({"body_marker": "root:x:0:0", "header": {"name": "X-Other"}}, 0, False),
    ],
)
async def test_a_signal_is_kept_only_when_the_capture_shows_it(
    monkeypatch: pytest.MonkeyPatch, signal: dict[str, Any], roundtrip: int, kept: bool
) -> None:
    _capture(monkeypatch, roundtrip=roundtrip)
    expected = (signal, None) if kept else (None, UNOBSERVED_WARNING)
    assert await observed_proof_signal(cast("Any", None), signal, "1") == expected


@pytest.mark.parametrize("intact", [True, False])
async def test_a_revised_signal_needs_an_intact_gateway_capture(
    report_state: ReportState, monkeypatch: pytest.MonkeyPatch, intact: bool
) -> None:
    capture_id = "gw-a-" + "0" * 32
    report_id = (await _create(http_exchange_ids=[capture_id]))["report_id"]
    _capture(monkeypatch)

    async def integrity(*_args: Any) -> tuple[str | None, str | None, bool]:
        return None, None, intact

    monkeypatch.setattr(ex, "_fetch_capture_integrity", integrity)
    ctx = ToolContext(
        context={}, tool_name="update_vulnerability_report", tool_call_id="c", tool_arguments="{}"
    )
    args = {"report_id": report_id, "update_reason": "r", "proof_signal": _SIGNAL}

    async def exists(*_args: Any) -> set[str]:
        return {capture_id}

    monkeypatch.setattr(reporting_tool, "existing_request_ids", exists)
    out = json.loads(await update_vulnerability_report.on_invoke_tool(ctx, json.dumps(args)))
    assert out["success"] is intact
    assert ("proof_signal" in report_state.vulnerability_reports[0]) is intact


async def test_timing_is_reported_uncheckable_without_a_response_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _capture(monkeypatch, roundtrip=0)
    result = await observed_proof_signal(cast("Any", None), {"timing": _TIMING}, "1")
    assert result == (None, UNTIMED_WARNING)


async def test_a_dropped_signal_leaves_no_key_for_a_retest_to_judge(
    report_state: ReportState, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The retest runs its signal oracle only when the key exists. Absent, not null or empty,
    # keeps the status rules, so a signal that was dropped can never mark a finding fixed.
    _capture(monkeypatch)
    signal, warning = await observed_proof_signal(
        cast("Any", None), {"body_marker": "never seen"}, "1"
    )
    assert warning
    await _create(proof_signal=signal, auth_role="member")
    stored = json.loads((report_state.get_run_dir() / "vulnerabilities.json").read_text())[0]
    assert "proof_signal" not in stored
    assert "authz_bypass" not in stored


@pytest.mark.parametrize(
    "change",
    [
        {"http_exchange_ids": ["2"]},
        {"http_exchange_ids": []},
        {"endpoint": "/other"},
        {"method": "POST"},
        {"poc_script_code": "y"},
        {"evidence": "y"},
    ],
)
async def test_a_signal_checked_before_another_revision_is_refused(
    report_state: ReportState, change: dict[str, Any]
) -> None:
    report_id = (await _create())["report_id"]
    checked = _checked(report_id)
    # Another revision lands between the capture check and this write.
    assert _update(report_id, **change)["success"]
    assert not _update(report_id, checked, proof_signal=_SIGNAL)["success"]
    assert "proof_signal" not in report_state.vulnerability_reports[0]


async def test_an_unchecked_signal_is_never_written(report_state: ReportState) -> None:
    report_id = (await _create(http_exchange_ids=None))["report_id"]
    result = _do_update(report_id=report_id, update_reason="r", fields={"proof_signal": _SIGNAL})
    assert not result["success"]
    assert "proof_signal" not in report_state.vulnerability_reports[0]


@pytest.mark.parametrize("field", [{"authz_bypass": False}, {"authz_bypass": True}])
async def test_a_lead_refuses_the_bypass_flag_either_way(
    report_state: ReportState, field: dict[str, bool]
) -> None:
    report_id = (await _create(proof_status="lead"))["report_id"]
    assert _update(report_id, **field)["rejected_fields"] == ["authz_bypass"]
    assert "authz_bypass" not in report_state.vulnerability_reports[0]


async def test_no_proving_exchange_keeps_no_signal() -> None:
    result = await observed_proof_signal(cast("Any", None), _SIGNAL, None)
    assert result == (None, UNOBSERVED_WARNING)


async def test_the_update_tool_refuses_a_signal_the_capture_lacks(
    report_state: ReportState, monkeypatch: pytest.MonkeyPatch
) -> None:
    report_id = (await _create(http_exchange_ids=["1"]))["report_id"]
    _capture(monkeypatch)
    ctx = ToolContext(
        context={}, tool_name="update_vulnerability_report", tool_call_id="c", tool_arguments="{}"
    )

    async def revise(marker: str) -> dict[str, Any]:
        args = {
            "report_id": report_id,
            "update_reason": "retested",
            "proof_signal": {"body_marker": marker},
        }
        return json.loads(await update_vulnerability_report.on_invoke_tool(ctx, json.dumps(args)))

    assert not (await revise("never seen"))["success"]
    assert "proof_signal" not in report_state.vulnerability_reports[0]
    assert (await revise("root:x:0:0"))["success"]
    assert report_state.vulnerability_reports[0]["proof_signal"] == _SIGNAL


def _checked(report_id: str) -> tuple[str, int]:
    state = get_global_report_state()
    assert state is not None
    report = next(r for r in state.vulnerability_reports if r["id"] == report_id)
    return "1", len(report.get("update_history") or [])


def _update(
    report_id: str, checked: tuple[str, int] | None = None, **fields: Any
) -> dict[str, Any]:
    return _do_update(
        report_id=report_id,
        update_reason="retested",
        fields=fields,
        signal_checked_against=checked or _checked(report_id),
    )


@pytest.mark.parametrize(
    "signal",
    [
        _SIGNAL,
        {"reflection": "<img src=x onerror=1>"},
        {"header": {"name": "X-Debug"}},
        {"header": {"name": "X-Debug", "contains": "stack"}},
        {"timing": _TIMING},
        {"body_marker": "uid=0", "timing": _TIMING},
    ],
)
def test_usable_signals_are_kept(signal: dict[str, Any]) -> None:
    assert normalize_proof_signal(signal) == (signal, [])


@pytest.mark.parametrize(
    "signal",
    [
        "root:x:0:0",
        {"status": 200},
        {"body_marker": ""},
        {"body_marker": "a" * 513},
        {"body_marker": _SECRET},
        {"header": {"name": "bad name"}},
        {"header": {"name": "X-Debug", "value": "stack"}},
        {"header": {"name": "Authorization", "contains": _SECRET.split(": ")[1]}},
        {"timing": {"delay_ms": 5000}},
        {"timing": {**_TIMING, "tolerance_ms": 2500}},
        {"timing": {**_TIMING, "delay_ms": 14000}},
        {"timing": {**_TIMING, "baseline_ms": True}},
        {"body_marker": "ok", "reflection": ""},
    ],
)
def test_unusable_signals_are_refused(signal: Any) -> None:
    stored, errors = normalize_proof_signal(signal)
    assert stored is None
    assert errors


def test_omitted_values_are_not_errors() -> None:
    assert normalize_proof_signal({}) == (None, [])
    assert normalize_auth_role("  ") == (None, [])
    assert normalize_auth_role(" member ") == ("member", [])
    assert normalize_auth_role(_SECRET)[1]


async def test_report_carries_the_signal_only_when_given(report_state: ReportState) -> None:
    await _create(proof_signal=_SIGNAL, auth_role="member", authz_bypass=True)
    report = report_state.vulnerability_reports[0]
    assert (report["proof_signal"], report["auth_role"], report["authz_bypass"]) == (
        _SIGNAL,
        "member",
        True,
    )
    run_dir = report_state.get_run_dir()
    assert json.loads((run_dir / "vulnerabilities.json").read_text())[0]["proof_signal"] == _SIGNAL


async def test_report_without_a_signal_has_no_replay_keys(report_state: ReportState) -> None:
    await _create(authz_bypass=False)
    report = report_state.vulnerability_reports[0]
    assert not {"proof_signal", "auth_role", "authz_bypass"} & set(report)


async def test_secret_signal_files_nothing(report_state: ReportState) -> None:
    result = await _create(proof_signal={"body_marker": _SECRET})
    assert not result["success"]
    assert not report_state.vulnerability_reports


@pytest.mark.parametrize(
    "change",
    [
        {"target": "https://other.test"},
        {"endpoint": "/other"},
        {"method": "POST"},
        {"poc_description": "y"},
        {"poc_script_code": "y"},
        {"evidence": "y"},
        {"http_exchange_ids": ["2"]},
        {"http_exchange_ids": []},
    ],
)
async def test_revising_the_proof_drops_what_described_it(
    report_state: ReportState, change: dict[str, Any]
) -> None:
    created = await _create(
        proof_signal=_SIGNAL, auth_role="member", authz_bypass=True, http_exchange_ids=["1"]
    )
    assert _update(created["report_id"], **change)["success"]
    report = report_state.vulnerability_reports[0]
    assert not {"proof_signal", "authz_bypass"} & set(report)
    assert report["auth_role"] == "member"


async def test_attaching_a_baseline_exchange_keeps_the_signal(report_state: ReportState) -> None:
    created = await _create(proof_signal=_SIGNAL, http_exchange_ids=["1"])
    assert _update(created["report_id"], http_exchange_ids=["1", "2"])["success"]
    assert report_state.vulnerability_reports[0]["proof_signal"] == _SIGNAL


async def test_a_lead_never_carries_replay_fields(report_state: ReportState) -> None:
    created = await _create(
        proof_status="lead", proof_signal=_SIGNAL, auth_role="member", authz_bypass=True
    )
    report = report_state.vulnerability_reports[0]
    assert not {"proof_signal", "auth_role", "authz_bypass"} & set(report)
    result = _update(created["report_id"], proof_signal=_SIGNAL)
    assert result["rejected_fields"] == ["proof_signal"]
    assert "proof_signal" not in report_state.vulnerability_reports[0]


async def test_restating_the_signal_with_a_new_proof_keeps_it(report_state: ReportState) -> None:
    report_id = (await _create(proof_signal=_SIGNAL))["report_id"]
    assert _update(report_id, poc_script_code="y", proof_signal=_SIGNAL)["success"]
    assert report_state.vulnerability_reports[0]["proof_signal"] == _SIGNAL


async def test_a_merge_keeping_the_same_poc_still_drops_the_old_signal(
    report_state: ReportState,
) -> None:
    report_id = (await _create(proof_signal=_SIGNAL, authz_bypass=True))["report_id"]
    report_state.merge_proof_into_report(report_id, {"evidence": "captured"})
    assert not {"proof_signal", "authz_bypass"} & set(report_state.vulnerability_reports[0])


async def test_update_replaces_and_validates_the_fields(report_state: ReportState) -> None:
    report_id = (await _create(authz_bypass=True))["report_id"]
    assert not _update(report_id, proof_signal={"body_marker": _SECRET})["success"]
    assert _update(report_id, proof_signal={"timing": _TIMING}, authz_bypass=False)["success"]
    report = report_state.vulnerability_reports[0]
    assert report["proof_signal"] == {"timing": _TIMING}
    assert report["authz_bypass"] is False


async def test_a_merged_proof_replaces_the_old_replay_fields(report_state: ReportState) -> None:
    report_id = (await _create(proof_signal=_SIGNAL, auth_role="member"))["report_id"]
    report_state.merge_proof_into_report(
        report_id,
        {"proof_status": "exploited", "poc_script_code": "stronger", "auth_role": "admin"},
    )
    report = report_state.vulnerability_reports[0]
    assert "proof_signal" not in report
    assert report["auth_role"] == "admin"
    assert report["update_history"][-1]["replaced"]["proof_signal"] == _SIGNAL


async def test_promotion_carries_the_signal_onto_the_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def verified(*_args: Any, **_kwargs: Any) -> tuple[Any, ...]:
        return ["1"], "exploited", None, "caido", None, None

    monkeypatch.setattr(ex, "assess_proof_with_integrity", verified)
    _capture(monkeypatch)
    args = _exploited(
        proof_signal=_SIGNAL, auth_role="member", authz_bypass=True, caido_request_id="1"
    )
    out, rs = await _promote(args, {}, tmp_path, monkeypatch)
    assert out["success"], out
    report = rs.vulnerability_reports[0]
    assert (report["proof_signal"], report["auth_role"], report["authz_bypass"]) == (
        _SIGNAL,
        "member",
        True,
    )


async def test_promotion_with_a_secret_signal_leaves_the_item_queued(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args = _exploited(proof_signal={"body_marker": _SECRET})
    out, rs = await _promote(args, {}, tmp_path, monkeypatch)
    assert not out["success"]
    assert not rs.vulnerability_reports
