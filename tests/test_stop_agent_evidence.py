"""Tests for stop_agent returning a stopped agent's own evidence.

A stop is documented as resumable, but a non-interactive root never resumes a
stopped validator to ask what it found — so the evidence has to come back on
the stop itself, or it is gone. See strix.core.agents.AgentCoordinator's
join_stopped/session_items/is_ancestor and
strix.tools.agents_graph.tools.stop_agent.
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


class FakeStream:
    """Stands in for RunResultStreaming where only .cancel() is exercised."""

    def cancel(self, mode: str = "after_turn") -> None:
        del mode


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


# --- AgentCoordinator.is_ancestor -------------------------------------------------


@pytest.mark.asyncio
async def test_is_ancestor_true_for_parent_and_grandparent() -> None:
    coordinator = await _graph()
    await coordinator.register("grandchild", "Validator-2", parent_id="child")

    assert await coordinator.is_ancestor("root", "child") is True
    assert await coordinator.is_ancestor("root", "grandchild") is True
    assert await coordinator.is_ancestor("child", "grandchild") is True


@pytest.mark.asyncio
async def test_is_ancestor_false_for_peers_and_descendants() -> None:
    coordinator = await _graph()

    assert await coordinator.is_ancestor("child", "root") is False
    assert await coordinator.is_ancestor("child", "child") is False
    assert await coordinator.is_ancestor("unknown", "child") is False


# --- AgentCoordinator.try_claim_next_cycle ----------------------------------------


@pytest.mark.asyncio
async def test_try_claim_next_cycle_succeeds_while_running() -> None:
    coordinator = await _graph()
    await coordinator.mark_turn_settled("child")

    assert await coordinator.try_claim_next_cycle("child") is True
    assert coordinator.runtimes["child"].turn_settled.is_set() is False


@pytest.mark.asyncio
async def test_try_claim_next_cycle_fails_once_stopped() -> None:
    """The exact race round 6 flagged: a status check and a later,
    separate mark_turn_unsettled call leave a gap a stop can land in.
    try_claim_next_cycle checks and clears under one lock acquisition, so
    there is no such gap - a stop that landed before this call is seen."""
    coordinator = await _graph()
    await coordinator.mark_turn_settled("child")
    await coordinator.request_stop("child")

    assert await coordinator.try_claim_next_cycle("child") is False
    # Already-settled evidence from the stop is left alone - nothing here
    # should make it look like a new cycle is about to write over it.
    assert coordinator.runtimes["child"].turn_settled.is_set() is True


# --- AgentCoordinator.join_stopped -----------------------------------------------


@pytest.mark.asyncio
async def test_join_stopped_with_no_cycle_in_flight_returns_settled() -> None:
    coordinator = await _graph()
    assert await coordinator.join_stopped("child", timeout=1.0) is True


@pytest.mark.asyncio
async def test_join_stopped_is_not_satisfied_by_detach_stream_alone() -> None:
    """detach_stream fires before a retry's own write (salvage, compaction);
    only mark_turn_settled means the turn is truly done writing."""
    coordinator = await _graph()
    stream = object()
    await coordinator.attach_stream("child", stream)
    await coordinator.detach_stream("child", stream)

    assert await coordinator.join_stopped("child", timeout=0.05) is False


@pytest.mark.asyncio
async def test_join_stopped_waits_for_mark_turn_settled() -> None:
    coordinator = await _graph()
    stream = object()
    await coordinator.attach_stream("child", stream)

    async def _finish_turn() -> None:
        await asyncio.sleep(0.01)
        await coordinator.detach_stream("child", stream)
        await coordinator.mark_turn_settled("child")

    task = asyncio.create_task(_finish_turn())
    assert await coordinator.join_stopped("child", timeout=1.0) is True
    await task


@pytest.mark.asyncio
async def test_join_stopped_times_out_while_a_turn_is_still_running() -> None:
    coordinator = await _graph()
    await coordinator.attach_stream("child", object())

    assert await coordinator.join_stopped("child", timeout=0.05) is False


@pytest.mark.asyncio
async def test_join_stopped_does_not_wait_on_an_interactive_agents_idle_task() -> None:
    """An interactive agent's background task parks in wait_for_message after a
    stop rather than exiting, so it must never be the thing we wait on."""
    coordinator = await _graph()
    never_resolves = asyncio.Event()
    task = asyncio.create_task(never_resolves.wait())
    await coordinator.attach_runtime("child", task=task, resumable=True)

    assert await coordinator.join_stopped("child", timeout=0.2) is True

    never_resolves.set()
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
async def test_session_items_returns_none_on_a_broken_session_store() -> None:
    """None, not [], so a caller can tell "unreadable" apart from "empty"."""
    coordinator = await _graph()
    await coordinator.attach_runtime("child", session=ExplodingSession([]))

    assert await coordinator.session_items("child") is None


# --- stop_agent --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stop_agent_returns_the_target_evidence_directly() -> None:
    coordinator = await _graph()
    session = FakeSession(
        [
            {
                "type": "function_call",
                "call_id": "call-1",
                "name": "http_request",
                "arguments": '{"url": "/ftp/package.json%2500.bak"}',
            },
            {
                "type": "function_call_output",
                "call_id": "call-1",
                "output": "HTTP/1.1 200 OK",
            },
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
            "evidence_writes_final": True,
            "evidence_complete": True,
            "evidence": [
                {
                    "type": "function_call",
                    "call_id": "call-1",
                    "name": "http_request",
                    "arguments": '{"url": "/ftp/package.json%2500.bak"}',
                },
                {"type": "function_call_output", "call_id": "call-1", "output": "HTTP/1.1 200 OK"},
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
    await coordinator.attach_stream("child", FakeStream())  # a turn is still in flight

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


@pytest.mark.asyncio
async def test_stop_agent_flags_an_unreadable_session_with_evidence_error() -> None:
    coordinator = await _graph()
    await coordinator.attach_runtime("child", session=ExplodingSession([]))

    result = await _call(
        stop_agent,
        coordinator,
        "root",
        {"target_agent_id": "child", "cascade": False},
    )

    entry = result["stopped_agents"][0]
    assert entry["evidence"] == []
    assert "evidence_error" in entry
    assert "evidence" in result["note"]


@pytest.mark.asyncio
async def test_stop_agent_withholds_evidence_from_a_non_ancestor() -> None:
    coordinator = await _graph()
    await coordinator.register("sibling", "Validator-2", parent_id="root")
    await coordinator.attach_runtime("sibling", resumable=False)
    await coordinator.attach_runtime(
        "child",
        session=FakeSession([{"role": "assistant", "content": "a scan credential lives here"}]),
    )

    result = await _call(
        stop_agent,
        coordinator,
        "sibling",
        {"target_agent_id": "child", "cascade": False},
    )

    assert result["success"] is True
    entry = result["stopped_agents"][0]
    assert entry == {
        "agent_id": "child",
        "name": "Validator",
        "evidence_settled": None,
        "evidence_writes_final": False,
        "evidence_complete": False,
    }
    assert "evidence" not in entry
    assert "withheld" in result["note"]


# --- bounding: item count, byte size, and call/output pairing --------------------


def test_bound_evidence_preserves_custom_tool_call_evidence() -> None:
    items = [
        {
            "type": "custom_tool_call",
            "call_id": "call-1",
            "name": "apply_patch",
            "input": "*** Update File: exploit.py\n+confirmed",
        },
        {"type": "custom_tool_call_output", "call_id": "call-1", "output": "patch applied"},
    ]

    payload, truncated = agents_graph_tools._bound_evidence(items, max_items=60)

    assert truncated is False
    assert payload == [
        {
            "type": "custom_tool_call",
            "call_id": "call-1",
            "name": "apply_patch",
            "input": "*** Update File: exploit.py\n+confirmed",
        },
        {"type": "custom_tool_call_output", "call_id": "call-1", "output": "patch applied"},
    ]


def test_bound_evidence_extends_past_the_cap_to_keep_a_split_pair() -> None:
    items = [
        {"role": "assistant", "content": "setting up"},
        {"type": "function_call", "call_id": "cut-off", "name": "http_request", "arguments": "{}"},
        {"type": "function_call_output", "call_id": "cut-off", "output": "200 OK"},
        {"role": "assistant", "content": "kept"},
    ]

    # A naive tail slice of max_items=2 would keep [the output, the trailing
    # message] and orphan the output from its call. The call is well within
    # _PAIR_EXTENSION_LIMIT, so it's pulled in instead of dropped - at the
    # cost of the unrelated leading message, which is legitimately cut.
    payload, truncated = agents_graph_tools._bound_evidence(items, max_items=2)

    assert truncated is True
    assert payload == [
        {"type": "function_call", "call_id": "cut-off", "name": "http_request", "arguments": "{}"},
        {"type": "function_call_output", "call_id": "cut-off", "output": "200 OK"},
        {"role": "assistant", "content": "kept"},
    ]


def test_bound_evidence_extends_to_keep_interleaved_parallel_calls_paired() -> None:
    # Parallel tool calls can persist as call A, call B, output A, output B -
    # not call A, output A, call B, output B. A naive "check only the first
    # kept item" filter misses output A here: it isn't first, call B is.
    items = [
        {
            "type": "function_call",
            "call_id": "a",
            "name": "http_request",
            "arguments": "{}",
        },
        {"type": "function_call", "call_id": "b", "name": "http_request", "arguments": "{}"},
        {"type": "function_call_output", "call_id": "a", "output": "200 OK (a)"},
        {"type": "function_call_output", "call_id": "b", "output": "200 OK (b)"},
    ]

    # A naive tail slice of max_items=3 would keep [call B, output A,
    # output B] and orphan output A. Both calls are within
    # _PAIR_EXTENSION_LIMIT, so both pairs survive intact instead.
    payload, truncated = agents_graph_tools._bound_evidence(items, max_items=3)

    assert truncated is False
    assert payload == items


def test_bound_evidence_drops_an_output_whose_call_is_beyond_the_extension_limit() -> None:
    # A turn wide enough that its call is further back than
    # _PAIR_EXTENSION_LIMIT * max_items allows recovering - the safety net
    # (_drop_orphaned_outputs) still applies rather than returning a
    # dangling call_id with no tool name or arguments.
    items: list[Any] = [
        {"type": "function_call", "call_id": "too-far", "name": "http_request", "arguments": "{}"}
    ]
    items += [{"role": "assistant", "content": f"filler {i}"} for i in range(10)]
    items.append({"type": "function_call_output", "call_id": "too-far", "output": "200 OK"})

    payload, truncated = agents_graph_tools._bound_evidence(items, max_items=2)

    assert truncated is True
    # The output itself is dropped (its call is out of reach) - what's left
    # is whichever filler messages fell inside the extension limit.
    assert all(item.get("type") != "function_call_output" for item in payload)
    assert payload


def test_fit_evidence_to_byte_cap_trims_the_largest_entry_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    small = [{"role": "assistant", "content": "short lead"}]
    large: list[Any] = []
    for i in range(10):
        large.append(
            {"type": "function_call", "call_id": f"c{i}", "name": "http_request", "arguments": "{}"}
        )
        large.append({"type": "function_call_output", "call_id": f"c{i}", "output": "x" * 200})

    stopped_agents = [
        {"agent_id": "a", "name": "A", "evidence_settled": True, "evidence": list(small)},
        {"agent_id": "b", "name": "B", "evidence_settled": True, "evidence": list(large)},
    ]
    result = {"success": True, "stopped_agents": stopped_agents}

    class _Context:
        tool_output_max_bytes = 1024

    class _Settings:
        context = _Context()

    monkeypatch.setattr(agents_graph_tools, "load_settings", _Settings)

    agents_graph_tools._fit_evidence_to_byte_cap(
        result, stopped_agents, {"a": len(small), "b": len(large)}
    )

    cap = 1024 - agents_graph_tools._RESULT_BYTE_CAP_MARGIN
    assert agents_graph_tools._result_byte_size(result) <= cap
    # The small entry is untouched; the large one took the cut.
    assert stopped_agents[0]["evidence"] == small
    assert len(stopped_agents[1]["evidence"]) < len(large)
    assert stopped_agents[1]["evidence_truncated"] is True
    assert stopped_agents[1]["evidence_total_items"] == len(large)


def test_fit_evidence_to_byte_cap_compacts_note_and_reason_once_evidence_is_gone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stopped_agents = [
        {"agent_id": "a", "name": "Validator", "evidence_settled": True, "evidence": []}
    ]
    result = {
        "success": True,
        "reason": "y" * 2000,
        "note": "n" * 2000,
        "stopped_agents": stopped_agents,
    }

    class _Context:
        tool_output_max_bytes = 1024

    class _Settings:
        context = _Context()

    monkeypatch.setattr(agents_graph_tools, "load_settings", _Settings)

    agents_graph_tools._fit_evidence_to_byte_cap(result, stopped_agents, {})

    cap = max(1024 - agents_graph_tools._RESULT_BYTE_CAP_MARGIN, 512)
    assert agents_graph_tools._result_byte_size(result) <= cap
    assert len(result["note"]) < 2000
    assert len(result["reason"]) < 2000


def test_fit_evidence_to_byte_cap_drops_entries_as_a_last_resort(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Enough agents that even their bare id/name/evidence_settled skeleton
    exceeds an aggressively small configured cap - compacting note/reason
    and truncating names isn't enough, so whole entries get dropped, marked
    plainly, rather than handing back an oversized response."""
    stopped_agents = [
        {"agent_id": str(i), "name": "x" * 200, "evidence_settled": True, "evidence": []}
        for i in range(10)
    ]
    result = {"success": True, "reason": "", "note": "n", "stopped_agents": stopped_agents}

    class _Context:
        tool_output_max_bytes = 1024

    class _Settings:
        context = _Context()

    monkeypatch.setattr(agents_graph_tools, "load_settings", _Settings)

    agents_graph_tools._fit_evidence_to_byte_cap(result, stopped_agents, {})

    cap = max(1024 - agents_graph_tools._RESULT_BYTE_CAP_MARGIN, 512)
    assert agents_graph_tools._result_byte_size(result) <= cap
    assert len(stopped_agents) < 10
    assert result["stopped_agents_truncated"] is True
    assert result["stopped_agents_total"] == 10
    # agent_id is left alone even under this last-resort trim.
    assert all(len(e["agent_id"]) <= 2 for e in stopped_agents)


@pytest.mark.asyncio
async def test_stop_agent_preserves_custom_tool_call_evidence() -> None:
    coordinator = await _graph()
    await coordinator.attach_runtime(
        "child",
        session=FakeSession(
            [
                {
                    "type": "custom_tool_call",
                    "call_id": "patch-1",
                    "name": "apply_patch",
                    "input": "*** Update File: exploit.py\n+leaked_key = 'sk-ant-...'",
                },
                {
                    "type": "custom_tool_call_output",
                    "call_id": "patch-1",
                    "output": "applied",
                },
            ]
        ),
    )

    result = await _call(
        stop_agent,
        coordinator,
        "root",
        {"target_agent_id": "child", "cascade": False},
    )

    entry = result["stopped_agents"][0]
    assert entry["evidence"] == [
        {
            "type": "custom_tool_call",
            "call_id": "patch-1",
            "name": "apply_patch",
            "input": "*** Update File: exploit.py\n+leaked_key = 'sk-ant-...'",
        },
        {"type": "custom_tool_call_output", "call_id": "patch-1", "output": "applied"},
    ]


@pytest.mark.asyncio
async def test_stop_agent_result_stays_under_a_small_configured_byte_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Context:
        tool_output_max_bytes = 1024

    class _Settings:
        context = _Context()

    monkeypatch.setattr(agents_graph_tools, "load_settings", _Settings)

    coordinator = await _graph()
    items: list[Any] = []
    for i in range(10):
        items.append(
            {"type": "function_call", "call_id": f"c{i}", "name": "http_request", "arguments": "{}"}
        )
        items.append({"type": "function_call_output", "call_id": f"c{i}", "output": "x" * 200})
    await coordinator.attach_runtime("child", session=FakeSession(items))

    result = await _call(
        stop_agent,
        coordinator,
        "root",
        {"target_agent_id": "child", "cascade": False},
    )

    # _call already round-tripped this through json.dumps/json.loads, so a
    # non-JSON preview from the generic wrapper would have failed there - the
    # assertion is really that stop_agent produced one on its own, not that.
    assert result["success"] is True
    entry = result["stopped_agents"][0]
    assert entry["evidence_truncated"] is True


# --- evidence_writes_final / evidence_complete ------------------------------------


@pytest.mark.asyncio
async def test_non_interactive_settled_target_is_final_and_complete() -> None:
    coordinator = await _graph()
    await coordinator.attach_runtime("child", session=FakeSession([{"role": "assistant"}]))

    result = await _call(
        stop_agent, coordinator, "root", {"target_agent_id": "child", "cascade": False}
    )

    entry = result["stopped_agents"][0]
    assert entry["evidence_settled"] is True
    assert entry["evidence_writes_final"] is True
    assert entry["evidence_complete"] is True


@pytest.mark.asyncio
async def test_interactive_settled_target_is_not_final() -> None:
    coordinator = await _graph()
    await coordinator.attach_runtime(
        "child", session=FakeSession([{"role": "assistant"}]), resumable=True
    )

    result = await _call(
        stop_agent, coordinator, "root", {"target_agent_id": "child", "cascade": False}
    )

    entry = result["stopped_agents"][0]
    assert entry["evidence_settled"] is True
    assert entry["evidence_writes_final"] is False
    assert entry["evidence_complete"] is True


@pytest.mark.asyncio
async def test_unsettled_non_interactive_target_is_not_final(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    coordinator = await _graph()
    await coordinator.attach_runtime("child", session=FakeSession([{"role": "assistant"}]))
    await coordinator.mark_turn_unsettled("child")
    monkeypatch.setattr(agents_graph_tools, "_STOP_AGENT_EVIDENCE_BUDGET_S", 0.01)

    result = await _call(
        stop_agent, coordinator, "root", {"target_agent_id": "child", "cascade": False}
    )

    entry = result["stopped_agents"][0]
    assert entry["evidence_settled"] is False
    assert entry["evidence_writes_final"] is False


@pytest.mark.asyncio
async def test_item_truncated_evidence_is_incomplete() -> None:
    coordinator = await _graph()
    items = [{"role": "assistant", "content": f"m{i}"} for i in range(100)]
    await coordinator.attach_runtime("child", session=FakeSession(items))

    result = await _call(
        stop_agent, coordinator, "root", {"target_agent_id": "child", "cascade": False}
    )

    entry = result["stopped_agents"][0]
    assert entry["evidence_truncated"] is True
    assert entry["evidence_writes_final"] is True
    assert entry["evidence_complete"] is False


@pytest.mark.asyncio
async def test_byte_capped_evidence_is_incomplete(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Context:
        tool_output_max_bytes = 1024

    class _Settings:
        context = _Context()

    monkeypatch.setattr(agents_graph_tools, "load_settings", _Settings)
    coordinator = await _graph()
    items: list[Any] = []
    for i in range(10):
        items.append(
            {"type": "function_call", "call_id": f"c{i}", "name": "http_request", "arguments": "{}"}
        )
        items.append({"type": "function_call_output", "call_id": f"c{i}", "output": "x" * 200})
    await coordinator.attach_runtime("child", session=FakeSession(items))

    result = await _call(
        stop_agent, coordinator, "root", {"target_agent_id": "child", "cascade": False}
    )

    assert result["stopped_agents"][0]["evidence_complete"] is False


@pytest.mark.asyncio
async def test_unreadable_session_is_incomplete() -> None:
    coordinator = await _graph()
    await coordinator.attach_runtime("child", session=ExplodingSession([]))

    result = await _call(
        stop_agent, coordinator, "root", {"target_agent_id": "child", "cascade": False}
    )

    entry = result["stopped_agents"][0]
    assert entry["evidence_writes_final"] is True
    assert entry["evidence_complete"] is False


@pytest.mark.asyncio
async def test_withheld_evidence_is_neither_final_nor_complete() -> None:
    coordinator = await _graph()
    await coordinator.register("peer", "Peer", parent_id="root")
    await coordinator.attach_runtime("peer", resumable=False)

    result = await _call(
        stop_agent, coordinator, "child", {"target_agent_id": "peer", "cascade": False}
    )

    entry = result["stopped_agents"][0]
    assert entry["evidence_writes_final"] is False
    assert entry["evidence_complete"] is False


def test_omitted_agents_are_listed_by_id_with_both_flags_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stopped_agents = [
        {
            "agent_id": f"id{i}",
            "name": "x" * 200,
            "evidence_settled": True,
            "evidence_writes_final": True,
            "evidence_complete": True,
            "evidence": [],
        }
        for i in range(10)
    ]
    result = {"success": True, "reason": "", "note": "n", "stopped_agents": stopped_agents}

    class _Context:
        tool_output_max_bytes = 1024

    class _Settings:
        context = _Context()

    monkeypatch.setattr(agents_graph_tools, "load_settings", _Settings)

    agents_graph_tools._fit_evidence_to_byte_cap(result, stopped_agents, {})

    kept = [e["agent_id"] for e in stopped_agents]
    omitted = result["stopped_agents_omitted"]
    assert result["stopped_agents_truncated"] is True
    assert omitted["agent_ids"] == [f"id{i}" for i in range(len(kept), 10)]
    assert omitted["evidence_writes_final"] is False
    assert omitted["evidence_complete"] is False


def test_stop_agent_docstring_explains_the_interactive_case() -> None:
    doc = stop_agent.description
    assert "evidence_writes_final" in doc
    assert "evidence_complete" in doc
    assert "woken" in doc
