# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""A promotion that could not reach the exchange source is retried; a definitive failure is not."""

from __future__ import annotations

import json
import time
import types
from typing import TYPE_CHECKING, Any

import pytest
from agents.tool_context import ToolContext

from strix.report.state import ReportState, set_global_report_state
from strix.tools.exploitation import tool as ex


if TYPE_CHECKING:
    from collections.abc import Iterator
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
_FIELDS = {
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


class _Capture:
    _is_gateway_capture = True

    def __init__(self) -> None:
        self.known = {_GOOD}
        self.down = False
        self.fetch_down = False

    async def capture_exists(self, request_id: str) -> bool:
        if self.down:
            raise TimeoutError("capture backend timed out")
        return request_id in self.known

    async def view_request(self, request_id: str, *, part: str = "request") -> Any:
        if self.fetch_down:
            raise TimeoutError("capture fetch timed out")
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


@pytest.fixture
def state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[ReportState]:
    monkeypatch.chdir(tmp_path)
    report_state = ReportState(run_name="promote-retry")
    set_global_report_state(report_state)
    ex.hydrate_queue_from_disk(tmp_path)
    ex._queue["q-0001"] = {
        "id": "q-0001",
        "title": "SQL injection in id",
        "guard_evidence": "id is concatenated into a query.",
        "minimal_witness": "id=1'",
        "confidence": "high",
        "endpoint": "/a",
        "status": "queued",
        "verdict_reason": None,
    }
    yield report_state
    set_global_report_state(None)


async def _promote(client: _Capture, exchange_id: str = _GOOD, **over: Any) -> dict[str, Any]:
    ctx = ToolContext(
        context={"caido_client": client},
        tool_name="promote_finding",
        tool_call_id="c1",
        tool_arguments="{}",
    )
    args = {
        "item_id": "q-0001",
        "status": "exploited",
        "request": "GET /a?id=1%27",
        "response": "HTTP 500 SQL syntax error",
        "caido_request_id": exchange_id,
        **_FIELDS,
        **over,
    }
    return json.loads(await ex.promote_finding.on_invoke_tool(ctx, json.dumps(args)))


def _due() -> None:
    ex._queue["q-0001"]["next_eligible"] = 0


@pytest.mark.asyncio
async def test_a_transient_failure_keeps_the_item_queued_then_succeeds(
    state: ReportState,
) -> None:
    client = _Capture()
    client.down = True
    first = await _promote(client)
    assert first["success"] is False
    assert first["transient"] is True
    assert first["retriable"] is True
    item = ex._queue["q-0001"]
    assert item["status"] == "queued"
    assert item["attempts"] == 1
    assert "could not be queried" in item["last_reason"]
    assert item["next_eligible"] > 0
    assert state.vulnerability_reports == []

    client.down = False
    _due()
    second = await _promote(client)
    assert second["success"] is True
    assert second["verdict"] == "exploited"
    assert state.vulnerability_reports[0]["proof_status"] == "exploited"


@pytest.mark.asyncio
@pytest.mark.usefixtures("state")
async def test_the_backoff_is_enforced_without_spending_an_attempt() -> None:
    client = _Capture()
    client.down = True
    await _promote(client)
    early = await _promote(client)
    assert early["transient"] is True
    assert early["retry_after_seconds"] > 0
    assert ex._queue["q-0001"]["attempts"] == 1


@pytest.mark.asyncio
async def test_the_cap_resolves_as_a_lead_with_verification_unavailable(
    state: ReportState,
) -> None:
    client = _Capture()
    client.down = True
    for _ in range(ex.MAX_VERIFY_ATTEMPTS - 1):
        assert (await _promote(client))["success"] is False
        _due()
    last = await _promote(client)
    assert last["success"] is True
    assert last["verdict"] == "lead"
    item = ex._queue["q-0001"]
    assert item["status"] == "lead"
    assert item["verdict_reason"].startswith(ex.VERIFICATION_UNAVAILABLE_REASON)
    report = state.vulnerability_reports[0]
    assert report["proof_status"] == "lead"
    assert report["proof_status_reason"].startswith(ex.VERIFICATION_UNAVAILABLE_REASON)
    assert report["http_exchange_ids"] == [_GOOD]
    assert report["queue_item_id"] == "q-0001"


@pytest.mark.asyncio
@pytest.mark.usefixtures("state")
async def test_a_definitive_failure_resolves_as_a_lead_at_once() -> None:
    result = await _promote(_Capture(), exchange_id=_OTHER)
    assert result["success"] is True
    assert result["verdict"] == "lead"
    item = ex._queue["q-0001"]
    assert item["status"] == "lead"
    assert "attempts" not in item
    assert "not found in the exchange source" in item["verdict_reason"]


def test_failures_are_classified() -> None:
    assert ex.proof_failure_kind(None) is None
    assert (
        ex.proof_failure_kind(f"{ex.PROOF_FAILED_PREFIX} {ex._SOURCE_UNREACHABLE}") == "transient"
    )
    assert ex.proof_failure_kind(f"{ex.PROOF_FAILED_PREFIX} {ex._CAPTURE_UNFETCHED}") == "transient"
    assert ex.proof_failure_kind(f"{ex.PROOF_FAILED_PREFIX} an id was not found") == "definitive"
    assert ex.proof_failure_kind(ex.NO_EXCHANGE_SOURCE_REASON) == "definitive"


@pytest.mark.asyncio
async def test_the_boundary_drain_resolves_a_retrying_item_as_unavailable(
    state: ReportState,
) -> None:
    client = _Capture()
    client.down = True
    await _promote(client)
    assert ex.drain_pending_to_leads("run ended") == 1
    item = ex._queue["q-0001"]
    assert item["status"] == "lead"
    assert item["verdict_reason"].startswith(ex.VERIFICATION_UNAVAILABLE_REASON)
    report = state.vulnerability_reports[0]
    assert report["proof_status"] == "lead"
    assert report["proof_status_reason"].startswith(ex.VERIFICATION_UNAVAILABLE_REASON)
    assert report["http_exchange_ids"] == [_GOOD]
    assert report["queue_item_id"] == "q-0001"


@pytest.mark.asyncio
@pytest.mark.usefixtures("state")
async def test_retry_state_survives_a_restart(tmp_path: Path) -> None:
    client = _Capture()
    client.down = True
    await _promote(client)
    ex.hydrate_queue_from_disk(tmp_path)
    item = ex._queue["q-0001"]
    assert item["status"] == "queued"
    assert item["attempts"] == 1
    assert item["next_eligible"] > 0


@pytest.mark.asyncio
async def test_an_id_only_promotion_retries_when_the_capture_cannot_be_fetched(
    state: ReportState,
) -> None:
    client = _Capture()
    client.fetch_down = True
    blank = {"request": "", "response": ""}
    first = await _promote(client, **blank)
    assert first["transient"] is True
    assert ex._queue["q-0001"]["attempts"] == 1
    assert ex._queue["q-0001"]["status"] == "queued"

    for _ in range(ex.MAX_VERIFY_ATTEMPTS - 2):
        _due()
        assert (await _promote(client, **blank))["transient"] is True
    _due()
    last = await _promote(client, **blank)
    assert last["verdict"] == "lead"
    assert ex._queue["q-0001"]["verdict_reason"].startswith(ex.VERIFICATION_UNAVAILABLE_REASON)
    report = state.vulnerability_reports[0]
    assert report["proof_status"] == "lead"
    assert report["proof_status_reason"].startswith(ex.VERIFICATION_UNAVAILABLE_REASON)


@pytest.mark.asyncio
async def test_an_id_only_promotion_with_an_unknown_id_is_not_retried(
    state: ReportState,
) -> None:
    client = _Capture()
    result = await _promote(client, exchange_id=_OTHER, request="", response="")
    assert result["success"] is False
    assert "transient" not in result
    assert "attempts" not in ex._queue["q-0001"]
    assert state.vulnerability_reports == []


@pytest.mark.asyncio
async def test_a_verified_proof_clears_retry_state_even_if_filing_then_fails(
    state: ReportState,
) -> None:
    client = _Capture()
    client.down = True
    await _promote(client)
    client.down = False
    _due()
    failed = await _promote(client, cwe="not-a-cwe")
    assert failed["success"] is False
    item = ex._queue["q-0001"]
    assert item["status"] == "queued"
    assert not {"attempts", "last_reason", "next_eligible"} & item.keys()
    assert ex.drain_pending_to_leads("run ended") == 1
    assert not ex._queue["q-0001"]["verdict_reason"].startswith(ex.VERIFICATION_UNAVAILABLE_REASON)
    assert state.vulnerability_reports


@pytest.mark.asyncio
@pytest.mark.usefixtures("state")
async def test_cleared_retry_state_is_persisted_before_a_filing_failure(
    tmp_path: Path,
) -> None:
    client = _Capture()
    client.down = True
    await _promote(client)
    client.down = False
    _due()
    assert (await _promote(client, cwe="not-a-cwe"))["success"] is False
    ex.hydrate_queue_from_disk(tmp_path)
    assert not {"attempts", "last_reason", "next_eligible"} & ex._queue["q-0001"].keys()


@pytest.mark.asyncio
@pytest.mark.usefixtures("state")
async def test_a_definitive_id_only_result_clears_earlier_retries() -> None:
    client = _Capture()
    client.fetch_down = True
    blank = {"request": "", "response": ""}
    await _promote(client, **blank)
    assert ex._queue["q-0001"]["attempts"] == 1
    client.fetch_down = False
    client.known = set()
    _due()
    result = await _promote(client, **blank)
    assert result["success"] is False
    assert "attempts" not in ex._queue["q-0001"]


@pytest.mark.asyncio
@pytest.mark.usefixtures("state")
async def test_a_field_error_after_the_capture_recovers_clears_retry_state() -> None:
    client = _Capture()
    client.fetch_down = True
    blank = {"request": "", "response": ""}
    await _promote(client, **blank)
    assert ex._queue["q-0001"]["attempts"] == 1
    client.fetch_down = False
    _due()
    result = await _promote(client, impact="")
    assert result["success"] is False
    assert "attempts" not in ex._queue["q-0001"]


@pytest.mark.asyncio
async def test_a_capped_lead_is_redacted_and_its_attempts_persisted(
    state: ReportState, tmp_path: Path
) -> None:
    ex._queue["q-0001"]["minimal_witness"] = "Authorization: Bearer abc123def456ghi789jkl"
    client = _Capture()
    client.fetch_down = True
    blank = {"request": "", "response": ""}
    for _ in range(ex.MAX_VERIFY_ATTEMPTS - 1):
        await _promote(client, **blank)
        _due()
    await _promote(client, **blank)
    assert "abc123def456ghi789jkl" not in json.dumps(state.vulnerability_reports)
    ex.hydrate_queue_from_disk(tmp_path)
    assert ex._queue["q-0001"]["attempts"] == ex.MAX_VERIFY_ATTEMPTS


@pytest.mark.asyncio
async def test_a_capped_id_only_lead_keeps_the_control_id_and_never_resolves_unfiled(
    state: ReportState,
) -> None:
    client = _Capture()
    client.known.add(_OTHER)
    client.fetch_down = True
    blank = {"request": "", "response": "", "control_request_id": _OTHER}
    for _ in range(ex.MAX_VERIFY_ATTEMPTS - 1):
        await _promote(client, **blank)
        _due()
    await _promote(client, **blank)
    assert state.vulnerability_reports[0]["http_exchange_ids"] == [_GOOD, _OTHER]


@pytest.mark.asyncio
async def test_a_capped_lead_without_report_state_stays_queued(tmp_path: Path) -> None:
    set_global_report_state(None)
    ex.hydrate_queue_from_disk(tmp_path)
    ex._queue["q-0001"] = {
        "id": "q-0001",
        "title": "t",
        "guard_evidence": "g",
        "minimal_witness": "w",
        "confidence": "high",
        "endpoint": "/a",
        "status": "queued",
        "verdict_reason": None,
        "attempts": ex.MAX_VERIFY_ATTEMPTS - 1,
    }
    client = _Capture()
    client.fetch_down = True
    result = await _promote(client, request="", response="")
    assert result["success"] is False
    assert ex._queue["q-0001"]["status"] == "queued"


@pytest.mark.asyncio
async def test_a_retry_after_a_filed_report_resolves_to_it_and_files_no_second(
    state: ReportState,
) -> None:
    client = _Capture()
    client.fetch_down = True
    await _promote(client, request="", response="")
    _due()
    client.fetch_down = False
    filed = await _promote(client)
    assert filed["verdict"] == "exploited"

    # A crash after the report persisted but before the queue write leaves the item queued,
    # with the earlier attempt still on it.
    ex._queue["q-0001"].update(status="queued", attempts=1, next_eligible=time.time() + 60)
    ex._queue["q-0001"].pop("report_id")
    again = await _promote(client)

    assert again["resumed"] is True
    assert again["verdict"] == "exploited"
    assert again["report_id"] == filed["report_id"]
    assert [r["id"] for r in state.vulnerability_reports] == [filed["report_id"]]
    assert ex._queue["q-0001"]["status"] == "exploited"


class _IntegrityTimesOut(_Capture):
    """The raw capture reads fine; the later integrity read of the same record times out."""

    def __init__(self) -> None:
        super().__init__()
        self.reads = 0
        self.integrity_down = True

    async def view_request(self, request_id: str, *, part: str = "request") -> Any:
        self.reads += 1
        if self.integrity_down and self.reads % 2 == 0:
            raise TimeoutError("capture integrity fetch timed out")
        return await super().view_request(request_id, part=part)


@pytest.mark.asyncio
async def test_an_integrity_fetch_failure_is_retried_not_filed(state: ReportState) -> None:
    client = _IntegrityTimesOut()
    first = await _promote(client)
    assert first["transient"] is True
    assert ex._queue["q-0001"]["status"] == "queued"
    assert ex._queue["q-0001"]["cited_ids"] == [_GOOD]
    assert state.vulnerability_reports == []

    _due()
    client.integrity_down = False
    assert (await _promote(client))["verdict"] == "exploited"


@pytest.mark.asyncio
async def test_a_capture_that_fails_its_hash_is_not_retried(state: ReportState) -> None:
    class _Tampered(_Capture):
        async def view_request(self, request_id: str, *, part: str = "request") -> Any:
            record = await super().view_request(request_id, part=part)
            record.integrity_verified = False
            return record

    result = await _promote(_Tampered())
    assert result["verdict"] == "lead"
    assert "http_exchange_ids" not in state.vulnerability_reports[0]


@pytest.mark.asyncio
async def test_a_direct_report_keeps_its_ids_when_the_integrity_fetch_fails() -> None:
    class _Unreadable(_Capture):
        async def view_request(self, request_id: str, *, part: str = "request") -> Any:
            raise TimeoutError("capture integrity fetch timed out")

    ctx = ToolContext(
        context={"caido_client": _Unreadable()},
        tool_name="create_vulnerability_report",
        tool_call_id="c1",
        tool_arguments="{}",
    )
    ids, status, reason, *_ = await ex.assess_proof_with_integrity(ctx, [_GOOD], require_all=False)

    assert (ids, status) == ([_GOOD], "lead")
    assert ex.proof_failure_kind(reason) == "transient"
