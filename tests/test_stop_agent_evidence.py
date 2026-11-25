"""Tests for stop_agent returning a stopped agent's own evidence.

A stop is documented as resumable, but a non-interactive root never resumes a
stopped validator to ask what it found — so the evidence has to come back on
the stop itself, or it is gone. See strix.core.agents.AgentCoordinator's
join_stopped/session_items and strix.tools.agents_graph.tools.stop_agent.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, cast

import pytest
from agents.tool_context import ToolContext

from strix.core.agents import AgentCoordinator
from strix.tools.agents_graph import tools as agents_graph_tools
from strix.tools.agents_graph.tools import stop_agent


class FakeSession:
    """Minimal in-memory Session, enough for stop_agent's evidence capture."""

    session_id = "fake"
    session_settings = None

    def __init__(self, items: list[Any]) -> None:
        self._items = list(items)

    async def get_items(self, limit: int | None = None) -> list[Any]:
        return list(self._items) if limit is None else list(self._items[-limit:])

    async def add_items(self, items: list[Any]) -> None:
        self._items.extend(items)


class ExplodingSession(FakeSession):
    async def get_items(self, _limit: int | None = None) -> list[Any]:
        raise RuntimeError("session store unavailable")


async def _graph() -> AgentCoordinator:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "Validator", parent_id="root")
    await coordinator.attach_runtime("root", resumable=False)
    await coordinator.attach_runtime("child", resumable=False)
    return coordinator


async def _call(
    tool: Any, coordinator: AgentCoordinator, agent_id: str, args: dict[str, Any]
) -> dict[str, Any]:
    ctx = ToolContext(
        context={"coordinator": coordinator, "agent_id": agent_id},
        tool_name=tool.name,
        tool_call_id="call-1",
        tool_arguments="{}",
    )
    raw: str = await tool.on_invoke_tool(ctx, json.dumps(args))
    return cast("dict[str, Any]", json.loads(raw))


# --- AgentCoordinator.join_stopped -----------------------------------------------


@pytest.mark.asyncio
async def test_join_stopped_with_no_task_returns_settled() -> None:
    coordinator = await _graph()
    assert await coordinator.join_stopped("child", timeout=1.0) is True


@pytest.mark.asyncio
async def test_join_stopped_waits_for_a_task_that_finishes_in_time() -> None:
    coordinator = await _graph()
    released = asyncio.Event()

    async def _turn() -> None:
        await released.wait()

    task = asyncio.create_task(_turn())
    await coordinator.attach_runtime("child", task=task)
    released.set()

    assert await coordinator.join_stopped("child", timeout=1.0) is True
    assert task.done()


@pytest.mark.asyncio
async def test_join_stopped_times_out_without_cancelling_the_task() -> None:
    coordinator = await _graph()
    released = asyncio.Event()

    async def _turn() -> None:
        await released.wait()

    task = asyncio.create_task(_turn())
    await coordinator.attach_runtime("child", task=task)

    assert await coordinator.join_stopped("child", timeout=0.05) is False
    assert not task.done()

    released.set()
    await task


# --- AgentCoordinator.session_items ----------------------------------------------


@pytest.mark.asyncio
async def test_session_items_with_no_session_returns_empty() -> None:
    coordinator = await _graph()
    assert await coordinator.session_items("child") == []


@pytest.mark.asyncio
async def test_session_items_reads_back_what_was_captured() -> None:
    coordinator = await _graph()
    session = FakeSession([{"role": "assistant", "content": "confirmed CWE-22 via %2500"}])
    await coordinator.attach_runtime("child", session=session)

    items = await coordinator.session_items("child")

    assert items == [{"role": "assistant", "content": "confirmed CWE-22 via %2500"}]


@pytest.mark.asyncio
async def test_session_items_swallows_a_broken_session_store() -> None:
    coordinator = await _graph()
    await coordinator.attach_runtime("child", session=ExplodingSession([]))

    assert await coordinator.session_items("child") == []


# --- stop_agent --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stop_agent_returns_the_target_evidence_directly() -> None:
    coordinator = await _graph()
    session = FakeSession(
        [
            {"role": "assistant", "content": "GET /ftp/package.json%2500.bak -> 200"},
            {"role": "assistant", "content": "filter bypass confirmed, CWE-22"},
        ]
    )
    await coordinator.attach_runtime("child", session=session)

    result = await _call(
        stop_agent,
        coordinator,
        "root",
        {"target_agent_id": "child", "cascade": False, "reason": "budget wind-down"},
    )

    assert result["success"] is True
    assert result["stopped_agents"] == [
        {
            "agent_id": "child",
            "name": "Validator",
            "evidence_settled": True,
            "evidence": [
                {"role": "assistant", "content": "GET /ftp/package.json%2500.bak -> 200"},
                {"role": "assistant", "content": "filter bypass confirmed, CWE-22"},
            ],
        }
    ]
    assert "evidence" in result["note"]


@pytest.mark.asyncio
async def test_stop_agent_cascade_returns_evidence_for_every_descendant() -> None:
    coordinator = await _graph()
    await coordinator.register("grandchild", "Validator-2", parent_id="child")
    await coordinator.attach_runtime("grandchild", resumable=False)
    await coordinator.attach_runtime(
        "child", session=FakeSession([{"role": "assistant", "content": "lead A"}])
    )
    await coordinator.attach_runtime(
        "grandchild", session=FakeSession([{"role": "assistant", "content": "lead B"}])
    )

    result = await _call(
        stop_agent,
        coordinator,
        "root",
        {"target_agent_id": "child", "cascade": True},
    )

    by_agent = {entry["agent_id"]: entry for entry in result["stopped_agents"]}
    assert set(by_agent) == {"child", "grandchild"}
    assert by_agent["child"]["evidence"] == [{"role": "assistant", "content": "lead A"}]
    assert by_agent["grandchild"]["evidence"] == [{"role": "assistant", "content": "lead B"}]
    assert all(entry["evidence_settled"] for entry in result["stopped_agents"])


@pytest.mark.asyncio
async def test_stop_agent_flags_evidence_as_unsettled_on_a_slow_turn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(agents_graph_tools, "_STOP_AGENT_EVIDENCE_BUDGET_S", 0.05)
    coordinator = await _graph()
    session = FakeSession([{"role": "assistant", "content": "lead captured before the stall"}])
    await coordinator.attach_runtime("child", session=session)
    released = asyncio.Event()

    async def _turn() -> None:
        await released.wait()

    task = asyncio.create_task(_turn())
    await coordinator.attach_runtime("child", task=task)

    result = await _call(
        stop_agent,
        coordinator,
        "root",
        {"target_agent_id": "child", "cascade": False},
    )

    entry = result["stopped_agents"][0]
    assert entry["evidence_settled"] is False
    # Still returns whatever had already landed in the session, rather than nothing.
    assert entry["evidence"] == [{"role": "assistant", "content": "lead captured before the stall"}]

    released.set()
    await task
