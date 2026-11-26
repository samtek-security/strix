# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""Tests for the ask/approve/reject-and-resume path in strix.core.execution."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any

import pytest

from strix.core.execution import (
    _dedup_key,
    _resolve_interruptions,
    _wait_for_human_decision,
)
from strix.core.interception import (
    APPROVAL_GATEWAY_KEY,
    ASK_DEADLINE_AT_KEY,
    ASK_TIMEOUT_SECONDS_KEY,
    INTERCEPTION_RULES_KEY,
    InterceptionDecision,
    InterceptionRule,
    register_custom_payload_field,
)


@dataclass
class _FakeApprovalItem:
    tool_name: str
    raw_item: dict[str, Any]


@dataclass
class _FakeRunState:
    approved: list[Any] = field(default_factory=list)
    rejected: list[tuple[Any, str | None]] = field(default_factory=list)

    def approve(self, item: Any, always_approve: bool = False) -> None:  # noqa: ARG002
        self.approved.append(item)

    def reject(
        self,
        item: Any,
        always_reject: bool = False,  # noqa: ARG002
        *,
        rejection_message: str | None = None,
    ) -> None:
        self.rejected.append((item, rejection_message))


@dataclass
class _FakeInterruptedStream:
    interruptions: list[_FakeApprovalItem]
    _state: _FakeRunState = field(default_factory=_FakeRunState)

    def to_state(self) -> _FakeRunState:
        return self._state


class _ScriptedGateway:
    """An ApprovalGateway whose poll() answers from a fixed script of statuses."""

    def __init__(self, statuses: list[str]) -> None:
        self._statuses = list(statuses)
        self.requests: list[dict[str, Any]] = []
        self.polls = 0

    async def request(
        self,
        *,
        dedup_key: str,
        tool_name: str,
        tool_input_summary: str,
        rule_id: str,
        rule_description: str,
        ttl_seconds: float,
    ) -> str:
        self.requests.append(
            {
                "dedup_key": dedup_key,
                "tool_name": tool_name,
                "tool_input_summary": tool_input_summary,
                "rule_id": rule_id,
                "rule_description": rule_description,
                "ttl_seconds": ttl_seconds,
            }
        )
        return "approval-1"

    async def poll(self, approval_id: str) -> str:  # noqa: ARG002
        self.polls += 1
        if self._statuses:
            return self._statuses.pop(0)
        return "pending"


def _ask_rule(pattern: str = "exec_command") -> InterceptionRule:
    return InterceptionRule(
        id="ask-1", field="tool_name", pattern=pattern, action="ask", description="risky"
    )


def _item(
    tool_name: str = "exec_command", arguments: str = '{"cmd":"rm -rf /"}'
) -> _FakeApprovalItem:
    return _FakeApprovalItem(tool_name=tool_name, raw_item={"arguments": arguments})


def test_dedup_key_is_deterministic_and_input_sensitive() -> None:
    a = _dedup_key("exec_command", '{"cmd":"ls"}')
    b = _dedup_key("exec_command", '{"cmd":"ls"}')
    c = _dedup_key("exec_command", '{"cmd":"pwd"}')
    assert a == b
    assert a != c


@pytest.mark.asyncio
async def test_approved_decision_resumes_with_approve() -> None:
    gateway = _ScriptedGateway(["approved"])
    context = {
        INTERCEPTION_RULES_KEY: [_ask_rule()],
        APPROVAL_GATEWAY_KEY: gateway,
        ASK_TIMEOUT_SECONDS_KEY: 5.0,
    }
    item = _item()
    stream = _FakeInterruptedStream(interruptions=[item])

    state = await _resolve_interruptions(stream, context=context, report=None)

    assert state.approved == [item]
    assert state.rejected == []
    assert gateway.requests[0]["rule_id"] == "ask-1"
    assert gateway.requests[0]["tool_name"] == "exec_command"


@pytest.mark.asyncio
async def test_denied_decision_resumes_with_reject() -> None:
    gateway = _ScriptedGateway(["denied"])
    context = {
        INTERCEPTION_RULES_KEY: [_ask_rule()],
        APPROVAL_GATEWAY_KEY: gateway,
    }
    item = _item()
    stream = _FakeInterruptedStream(interruptions=[item])

    state = await _resolve_interruptions(stream, context=context, report=None)

    assert state.approved == []
    assert len(state.rejected) == 1
    rejected_item, message = state.rejected[0]
    assert rejected_item is item
    assert "ask-1" in (message or "")


@pytest.mark.asyncio
async def test_unexplained_pause_defaults_to_deny() -> None:
    """No rule matches and/or no gateway configured: reject, never guess allow."""
    context: dict[str, Any] = {}
    item = _item()
    stream = _FakeInterruptedStream(interruptions=[item])

    state = await _resolve_interruptions(stream, context=context, report=None)

    assert state.approved == []
    assert len(state.rejected) == 1
    assert state.rejected[0][0] is item


@pytest.mark.asyncio
async def test_empty_interruptions_is_a_no_op() -> None:
    context = {INTERCEPTION_RULES_KEY: [_ask_rule()], APPROVAL_GATEWAY_KEY: _ScriptedGateway([])}
    stream = _FakeInterruptedStream(interruptions=[])

    state = await _resolve_interruptions(stream, context=context, report=None)

    assert state.approved == []
    assert state.rejected == []


@pytest.mark.asyncio
async def test_wait_for_human_decision_times_out_and_pings_report() -> None:
    """A tiny, real timeout: the deadline check runs before any sleep, so this
    settles in well under a second with no need to fake the clock."""
    gateway = _ScriptedGateway([])  # never answers
    decision = InterceptionDecision(rule=_ask_rule(), action="ask")
    pings: list[str] = []

    outcome = await asyncio.wait_for(
        _wait_for_human_decision(
            gateway,
            decision=decision,
            tool_name="exec_command",
            input_text='{"cmd":"rm -rf /"}',
            timeout=0.01,
            report=pings.append,
        ),
        timeout=5,
    )

    assert outcome == "denied"
    assert gateway.polls >= 1
    assert any("exec_command" in p for p in pings)


@pytest.mark.asyncio
@pytest.mark.parametrize("budget", [0, 0.0, -5])
async def test_no_budget_left_denies_at_once_without_opening_an_approval(budget: float) -> None:
    gateway = _ScriptedGateway(["approved"])  # would approve, if it were ever asked
    context = {
        INTERCEPTION_RULES_KEY: [_ask_rule()],
        APPROVAL_GATEWAY_KEY: gateway,
        ASK_TIMEOUT_SECONDS_KEY: budget,
    }
    item = _item()
    stream = _FakeInterruptedStream(interruptions=[item])

    state = await asyncio.wait_for(
        _resolve_interruptions(stream, context=context, report=None), timeout=2
    )

    assert state.approved == []
    assert [rejected for rejected, _ in state.rejected] == [item]
    assert gateway.requests == []
    assert gateway.polls == 0


@pytest.mark.asyncio
async def test_resume_matches_the_same_rule_the_wrapper_matched() -> None:
    """The wrapper pauses on the parsed arguments; the resume path sees the raw
    string. A differently spaced/ordered encoding must still reach the gateway."""
    gateway = _ScriptedGateway(["approved"])
    rule = InterceptionRule(
        id="ask-rm", field="tool_input", pattern='"cmd": "rm -rf', action="ask", description="risky"
    )
    context = {
        INTERCEPTION_RULES_KEY: [rule],
        APPROVAL_GATEWAY_KEY: gateway,
        ASK_TIMEOUT_SECONDS_KEY: 5.0,
    }
    item = _item(arguments='{ "b": 1,\n "cmd": "rm -rf /x" }')
    stream = _FakeInterruptedStream(interruptions=[item])

    state = await _resolve_interruptions(stream, context=context, report=None)

    assert state.approved == [item]
    assert gateway.requests and gateway.requests[0]["rule_id"] == "ask-rm"


@pytest.mark.asyncio
async def test_native_custom_tool_input_is_read_from_the_input_field() -> None:
    gateway = _ScriptedGateway(["denied"])
    rule = InterceptionRule(id="ask-patch", field="tool_input", pattern="/etc/", action="ask")
    context = {INTERCEPTION_RULES_KEY: [rule], APPROVAL_GATEWAY_KEY: gateway}
    item = _FakeApprovalItem(
        tool_name="apply_patch", raw_item={"input": "*** Update File: /etc/hosts"}
    )
    stream = _FakeInterruptedStream(interruptions=[item])

    state = await _resolve_interruptions(stream, context=context, report=None)

    assert len(state.rejected) == 1
    assert "ask-patch" in (state.rejected[0][1] or "")
    assert gateway.requests[0]["rule_id"] == "ask-patch"


@pytest.mark.asyncio
async def test_each_ask_measures_the_deadline_when_it_asks(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two interruptions in one stream: the clock moves past the deadline between
    them, so the first may wait and the second must deny at once, with no request."""
    clock = {"now": 1_000.0}
    monkeypatch.setattr("strix.core.execution.time.time", lambda: clock["now"])
    gateway = _ScriptedGateway(["approved"])
    context = {
        INTERCEPTION_RULES_KEY: [_ask_rule()],
        APPROVAL_GATEWAY_KEY: gateway,
        ASK_TIMEOUT_SECONDS_KEY: 300.0,
        ASK_DEADLINE_AT_KEY: 1_100.0,  # 100 s left for the first ask
    }
    first, second = _item(arguments='{"cmd":"a"}'), _item(arguments='{"cmd":"b"}')

    real_poll = gateway.poll

    async def poll_then_move_clock(approval_id: str) -> str:
        status = await real_poll(approval_id)
        clock["now"] = 1_200.0  # the engagement's budget is now spent
        return status

    gateway.poll = poll_then_move_clock  # type: ignore[method-assign]
    stream = _FakeInterruptedStream(interruptions=[first, second])

    state = await _resolve_interruptions(stream, context=context, report=None)

    assert state.approved == [first]
    assert [item for item, _ in state.rejected] == [second]
    assert len(gateway.requests) == 1, "the second ask must not open an approval"
    assert gateway.requests[0]["ttl_seconds"] == pytest.approx(100.0)


@pytest.mark.asyncio
async def test_a_deadline_already_passed_denies_without_asking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("strix.core.execution.time.time", lambda: 5_000.0)
    gateway = _ScriptedGateway(["approved"])
    context = {
        INTERCEPTION_RULES_KEY: [_ask_rule()],
        APPROVAL_GATEWAY_KEY: gateway,
        ASK_DEADLINE_AT_KEY: 4_000.0,
    }
    item = _item()
    state = await _resolve_interruptions(
        _FakeInterruptedStream(interruptions=[item]), context=context, report=None
    )
    assert state.approved == [] and [i for i, _ in state.rejected] == [item]
    assert gateway.requests == []


class _StalledGateway(_ScriptedGateway):
    """request() or poll() never returns: the I/O itself outlasts the deadline."""

    def __init__(self, *, stall: str) -> None:
        super().__init__(["approved"])
        self._stall = stall

    async def request(self, **kwargs: Any) -> str:
        if self._stall == "request":
            await asyncio.sleep(3600)
        return await super().request(**kwargs)

    async def poll(self, approval_id: str) -> str:
        if self._stall == "poll":
            await asyncio.sleep(3600)
        return await super().poll(approval_id)


@pytest.mark.asyncio
@pytest.mark.parametrize("stall", ["request", "poll"])
async def test_a_stalled_gateway_call_cannot_hold_the_run_past_the_deadline(stall: str) -> None:
    gateway = _StalledGateway(stall=stall)
    decision = InterceptionDecision(rule=_ask_rule(), action="ask")
    outcome = await asyncio.wait_for(
        _wait_for_human_decision(
            gateway,
            decision=decision,
            tool_name="exec_command",
            input_text="{}",
            timeout=0.2,
            report=None,
        ),
        timeout=5,  # the stall is an hour: only the ask's own deadline can end this
    )
    assert outcome == "denied"


@pytest.mark.asyncio
async def test_an_approval_read_after_the_deadline_is_denied_not_honored() -> None:
    """The poll itself returns late, with "approved": the deadline is rechecked
    immediately before honoring it."""

    class LateApproval(_ScriptedGateway):
        async def poll(self, approval_id: str) -> str:  # noqa: ARG002
            await asyncio.sleep(0.15)  # still inside wait_for's window, past the deadline below
            return "approved"

    gateway = LateApproval([])
    decision = InterceptionDecision(rule=_ask_rule(), action="ask")
    outcome = await _wait_for_human_decision(
        gateway,
        decision=decision,
        tool_name="exec_command",
        input_text="{}",
        timeout=0.1,
        report=None,
    )
    assert outcome == "denied"


@pytest.mark.asyncio
async def test_a_json_looking_custom_tool_payload_is_matched_verbatim() -> None:
    """A native custom tool's input is opaque text. A rule written against that
    exact text must match it even though it parses as JSON and would canonicalize
    differently."""
    payload = '{"action":"delete",  "id": 1}'  # two spaces: canonical form would change it
    gateway = _ScriptedGateway(["denied"])
    rule = InterceptionRule(
        id="deny-delete", field="tool_input", pattern='"action":"delete",  "id"', action="ask"
    )
    context = {INTERCEPTION_RULES_KEY: [rule], APPROVAL_GATEWAY_KEY: gateway}
    item = _FakeApprovalItem(tool_name="custom_tool", raw_item={"input": payload})

    state = await _resolve_interruptions(
        _FakeInterruptedStream(interruptions=[item]), context=context, report=None
    )

    assert gateway.requests and gateway.requests[0]["rule_id"] == "deny-delete"
    assert [rejected for rejected, _ in state.rejected] == [item]


@pytest.mark.asyncio
async def test_identical_parallel_calls_are_asked_once() -> None:
    gateway = _ScriptedGateway(["approved", "denied"])
    context = {
        INTERCEPTION_RULES_KEY: [_ask_rule()],
        APPROVAL_GATEWAY_KEY: gateway,
        ASK_TIMEOUT_SECONDS_KEY: 5.0,
    }
    # Same call, formatted differently: still one ask, one decision for both.
    first = _item(arguments='{"cmd":"rm -rf /x"}')
    second = _item(arguments='{ "cmd": "rm -rf /x" }')
    other = _item(arguments='{"cmd":"ls"}')

    state = await _resolve_interruptions(
        _FakeInterruptedStream(interruptions=[first, second, other]), context=context, report=None
    )

    assert len(gateway.requests) == 2, "one ask per distinct call, not per call"
    assert first in state.approved and second in state.approved
    assert [item for item, _ in state.rejected] == [other]


@pytest.mark.asyncio
async def test_a_gateway_timeout_before_the_deadline_is_retried_not_treated_as_expiry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The gateway's own TimeoutError (an HTTP client timeout) is a transient poll
    failure: the ask goes on to the next poll and can still be approved."""

    monkeypatch.setattr("strix.core.execution._ASK_POLL_INTERVAL_S", 0.01)

    class FlakyThenApproved(_ScriptedGateway):
        async def poll(self, approval_id: str) -> str:  # noqa: ARG002
            self.polls += 1
            if self.polls == 1:
                raise TimeoutError("client timed out")
            return "approved"

    gateway = FlakyThenApproved([])
    decision = InterceptionDecision(rule=_ask_rule(), action="ask")
    outcome = await _wait_for_human_decision(
        gateway,
        decision=decision,
        tool_name="exec_command",
        input_text="{}",
        timeout=30,
        report=None,
    )
    assert outcome == "approved"
    assert gateway.polls == 2


@pytest.mark.asyncio
async def test_resume_unwraps_a_converted_custom_tool_payload() -> None:
    register_custom_payload_field("apply_patch", "patch")
    gateway = _ScriptedGateway(["denied"])
    payload = "*** Begin Patch\n*** Update File: /etc/hosts"
    rule = InterceptionRule(
        id="ask-etc", field="tool_input", pattern=r"\A\*\*\* Begin Patch", action="ask", regex=True
    )
    context = {INTERCEPTION_RULES_KEY: [rule], APPROVAL_GATEWAY_KEY: gateway}
    item = _FakeApprovalItem(
        tool_name="apply_patch", raw_item={"arguments": json.dumps({"patch": payload})}
    )
    state = await _resolve_interruptions(
        _FakeInterruptedStream(interruptions=[item]), context=context, report=None
    )
    assert gateway.requests and gateway.requests[0]["rule_id"] == "ask-etc"
    assert [rejected for rejected, _ in state.rejected] == [item]


@pytest.mark.asyncio
async def test_an_opaque_input_with_a_lone_surrogate_does_not_abort_the_scan() -> None:
    gateway = _ScriptedGateway(["denied"])
    rule = InterceptionRule(id="ask-all", field="tool_name", pattern="custom", action="ask")
    context = {INTERCEPTION_RULES_KEY: [rule], APPROVAL_GATEWAY_KEY: gateway}
    item = _FakeApprovalItem(tool_name="custom_tool", raw_item={"input": "bad \ud800 text"})

    state = await _resolve_interruptions(
        _FakeInterruptedStream(interruptions=[item]), context=context, report=None
    )

    assert [rejected for rejected, _ in state.rejected] == [item]
    assert gateway.requests
    gateway.requests[0]["tool_input_summary"].encode("utf-8")  # transport-safe
