"""Tests for the ask/approve/reject-and-resume path in strix.core.execution."""

from __future__ import annotations

import asyncio
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
    ASK_TIMEOUT_SECONDS_KEY,
    INTERCEPTION_RULES_KEY,
    InterceptionDecision,
    InterceptionRule,
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
        self, item: Any, always_reject: bool = False, *, rejection_message: str | None = None
    ) -> None:  # noqa: ARG002
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


def _item(tool_name: str = "exec_command", arguments: str = '{"cmd":"rm -rf /"}') -> _FakeApprovalItem:
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
