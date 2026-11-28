"""A scan-wide stop that lands before finish_scan completes is the run's exit reason."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest
from agents.tool_context import ToolContext

from strix.core.agents import AgentCoordinator
from strix.report.state import ReportState, set_global_report_state
from strix.tools.finish.tool import finish_scan


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


_ARGS = json.dumps(
    {
        "executive_summary": "Summary.",
        "methodology": "Method.",
        "technical_analysis": "Analysis.",
        "recommendations": "Fix.",
    }
)


@pytest.fixture
def report_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[ReportState]:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    state = ReportState("finish-exit-reason")
    set_global_report_state(state)
    yield state
    set_global_report_state(None)


async def _finish(coordinator: AgentCoordinator) -> dict[str, Any]:
    context = {"coordinator": coordinator, "agent_id": "root", "parent_id": None}
    ctx = ToolContext(
        context=context, tool_name="finish_scan", tool_call_id="call-1", tool_arguments=_ARGS
    )
    result: dict[str, Any] = json.loads(await finish_scan.on_invoke_tool(ctx, _ARGS))
    return result


async def _coordinator() -> AgentCoordinator:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "root", None)
    return coordinator


def _recorded_reason(state: ReportState) -> str:
    coverage = json.loads((state.get_run_dir() / "coverage.json").read_text())
    reason: str = coverage["completeness"]["exit_reason"]
    return reason


@pytest.mark.parametrize("reason", ["budget_exceeded", "elapsed_budget"])
async def test_a_stop_before_finish_scan_completes_is_the_exit_reason(
    report_state: ReportState, reason: str
) -> None:
    coordinator = await _coordinator()
    await coordinator.trigger_budget_stop(reason)

    assert (await _finish(coordinator))["scan_completed"]

    assert report_state.scan_ended_exit_reason == reason
    assert _recorded_reason(report_state) == reason


async def test_a_finish_that_completes_before_the_stop_keeps_finished_by_tool(
    report_state: ReportState,
) -> None:
    coordinator = await _coordinator()

    assert (await _finish(coordinator))["scan_completed"]
    await coordinator.trigger_budget_stop("elapsed_budget")

    assert report_state.scan_ended_exit_reason == "finished_by_tool"
