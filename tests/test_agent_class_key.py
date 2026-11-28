# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""A child spawned for a vulnerability class files every report under that class."""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any, cast

import pytest
from agents.tool_context import ToolContext

from strix.core import execution
from strix.core.agents import AgentCoordinator
from strix.report.state import ReportState, set_global_report_state
from strix.tools.agents_graph.tools import create_agent
from strix.tools.exploitation import tool as exploitation


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


@pytest.fixture
def report_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[ReportState]:
    monkeypatch.chdir(tmp_path)

    async def _idle(**_: Any) -> None:
        return None

    monkeypatch.setattr(execution, "run_agent_loop", _idle)
    state = ReportState(run_name="test-run")
    set_global_report_state(state)
    yield state
    set_global_report_state(None)


async def _spawn(
    coordinator: AgentCoordinator, tmp_path: Path, parent_id: str, **extra: Any
) -> str:
    result = await execution.spawn_child_agent(
        coordinator=coordinator,
        factory=lambda **_: None,
        agents_db_path=tmp_path / "agents.db",
        sessions_to_close=[],
        run_config=cast("Any", None),
        max_turns=1,
        interactive=False,
        parent_ctx={"agent_id": parent_id},
        name="specialist",
        task="test it",
        skills=[],
        parent_history=[],
        **extra,
    )
    task = coordinator.runtimes[result["agent_id"]].task
    assert task is not None
    await asyncio.wait_for(task, 5)
    return cast("str", result["agent_id"])


def _filed(state: ReportState, agent_id: str | None) -> dict[str, Any]:
    report_id = state.add_vulnerability_report(title="t", severity="low", agent_id=agent_id)
    return next(r for r in state.vulnerability_reports if r["id"] == report_id)


@pytest.mark.asyncio
async def test_reports_carry_the_class_of_the_agent_that_filed_them(
    report_state: ReportState, tmp_path: Path
) -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    sqli = await _spawn(coordinator, tmp_path, "root", class_key="sqli")
    grandchild = await _spawn(coordinator, tmp_path, sqli)
    unkeyed = await _spawn(coordinator, tmp_path, "root")

    assert _filed(report_state, sqli)["class_key"] == "sqli"
    assert _filed(report_state, grandchild)["class_key"] == "sqli"
    for agent_id in (unkeyed, "root", None):
        assert "class_key" not in _filed(report_state, agent_id)
    snapshot = await coordinator.snapshot()
    assert snapshot["metadata"][sqli]["class_key"] == "sqli"


def test_a_keyed_specialists_proof_merge_attributes_an_unkeyed_report(
    report_state: ReportState,
) -> None:
    report_state.agent_class_keys.update({"specialist": "sqli", "other": "xss"})
    report_id = report_state.add_vulnerability_report(title="t", severity="low", agent_id="root")
    for agent_id, proof in (("specialist", "proof one"), ("other", "proof two")):
        merged = report_state.merge_proof_into_report(
            report_id, {"poc_script_code": proof}, merged_by_agent_id=agent_id
        )
        assert merged is not None
        # the first keyed merge names the class; a later one does not move it
        assert merged["class_key"] == "sqli"


@pytest.mark.asyncio
async def test_a_queued_candidate_keeps_its_class_through_promotion_by_the_root(
    report_state: ReportState, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(exploitation, "_queue", {})
    monkeypatch.setattr(exploitation, "_persist", lambda: None)
    report_state.agent_class_keys["specialist"] = "sqli"
    updates: list[dict[str, Any]] = []
    report_state.vulnerability_updated_callback = updates.append

    async def _invoke(tool: Any, agent_id: str, args: dict[str, Any]) -> dict[str, Any]:
        ctx = ToolContext(
            context={"agent_id": agent_id},
            tool_name=tool.name,
            tool_call_id="call-1",
            tool_arguments="{}",
        )
        return cast("dict[str, Any]", json.loads(await tool.on_invoke_tool(ctx, json.dumps(args))))

    queued = await _invoke(
        exploitation.queue_finding,
        "specialist",
        {
            "title": "login",
            "vuln_class": "SQL injection",
            "guard_evidence": "no bind",
            "minimal_witness": "quote",
            "confidence": "high",
        },
    )
    promoted = await _invoke(
        exploitation.promote_finding,
        "root",
        {"item_id": queued["item_id"], "status": "lead", "reason": "blocked"},
    )

    report = next(r for r in report_state.vulnerability_reports if r["id"] == promoted["report_id"])
    assert report["class_key"] == "sqli"
    assert [u["class_key"] for u in updates] == ["sqli"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("given", "passed"), [(" SQLi ", "sqli"), ("path-traversal", "path-traversal"), (None, None)]
)
async def test_create_agent_normalizes_the_class_key(given: str | None, passed: str | None) -> None:
    seen: dict[str, Any] = {}

    async def _spawner(**kwargs: Any) -> dict[str, Any]:
        seen.update(kwargs)
        return {"success": True, "agent_id": "child"}

    result = await _create(_spawner, given)

    assert result["success"] is True
    assert seen.get("class_key") == passed


@pytest.mark.asyncio
async def test_create_agent_rejects_a_key_that_is_not_a_slug() -> None:
    async def _spawner(**_: Any) -> dict[str, Any]:
        raise AssertionError("must not spawn")

    result = await _create(_spawner, "SQL injection in /login")

    assert result["success"] is False
    assert "class_key" in result["error"]


async def _create(spawner: Any, class_key: str | None) -> dict[str, Any]:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    ctx = ToolContext(
        context={"coordinator": coordinator, "agent_id": "root", "spawn_child_agent": spawner},
        tool_name=create_agent.name,
        tool_call_id="call-1",
        tool_arguments="{}",
    )
    args = {"name": "n", "task": "t", "class_key": class_key}
    return cast(
        "dict[str, Any]", json.loads(await create_agent.on_invoke_tool(ctx, json.dumps(args)))
    )
