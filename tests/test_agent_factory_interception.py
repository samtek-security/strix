"""Tests for the interception (allow/deny/ask) wiring in the agent factory."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, cast

import pytest
from agents.tool import CustomTool, FunctionTool

from strix.agents import factory
from strix.core.interception import INTERCEPTION_RULES_KEY, InterceptionRule


def _tool(name: str = "exec_command") -> FunctionTool:
    async def invoke(_ctx: Any, raw_input: str) -> str:  # noqa: ARG001
        return "ran:" + raw_input

    return FunctionTool(
        name=name,
        description="test tool",
        params_json_schema={"type": "object", "properties": {"cmd": {"type": "string"}}},
        on_invoke_tool=invoke,
    )


def _custom_tool(name: str = "apply_patch") -> CustomTool:
    async def invoke(_ctx: Any, raw_input: str) -> str:  # noqa: ARG001
        return "ran:" + raw_input

    return CustomTool(name=name, description="test custom tool", on_invoke_tool=invoke)


def _ctx(rules: list[InterceptionRule] | None) -> Any:
    return SimpleNamespace(context={INTERCEPTION_RULES_KEY: rules or []})


def _deny_rule(pattern: str = "exec_command") -> InterceptionRule:
    return InterceptionRule(
        id="deny-1", field="tool_name", pattern=pattern, action="deny", description="blocked"
    )


def _ask_rule(pattern: str = "exec_command") -> InterceptionRule:
    return InterceptionRule(id="ask-1", field="tool_name", pattern=pattern, action="ask")


@pytest.mark.asyncio
async def test_function_tool_no_rules_runs_normally() -> None:
    wrapped = factory._with_function_tool_interception(_tool())
    result = await wrapped.on_invoke_tool(_ctx(None), json.dumps({"cmd": "ls"}))
    assert result == 'ran:{"cmd": "ls"}'


@pytest.mark.asyncio
async def test_function_tool_deny_short_circuits_without_running() -> None:
    wrapped = factory._with_function_tool_interception(_tool())
    result = await wrapped.on_invoke_tool(_ctx([_deny_rule()]), json.dumps({"cmd": "rm -rf /"}))
    assert "deny-1" in cast("str", result)
    assert "blocked" in cast("str", result)
    assert not cast("str", result).startswith("ran:")


@pytest.mark.asyncio
async def test_function_tool_deny_needs_approval_is_false() -> None:
    wrapped = factory._with_function_tool_interception(_tool())
    needs = wrapped.needs_approval
    assert callable(needs)
    assert await needs(_ctx([_deny_rule()]), {"cmd": "rm -rf /"}, "call-1") is False


@pytest.mark.asyncio
async def test_function_tool_ask_sets_needs_approval_true() -> None:
    wrapped = factory._with_function_tool_interception(_tool())
    needs = wrapped.needs_approval
    assert callable(needs)
    assert await needs(_ctx([_ask_rule()]), {"cmd": "ls"}, "call-1") is True
    # A non-matching call on the same (shared, process-wide) tool object still runs.
    assert await needs(_ctx([_ask_rule(pattern="never_matches")]), {"cmd": "ls"}, "call-1") is False


@pytest.mark.asyncio
async def test_function_tool_allow_runs_normally() -> None:
    wrapped = factory._with_function_tool_interception(_tool())
    allow_rule = InterceptionRule(id="allow-1", field="tool_name", pattern="exec_command", action="allow")
    result = await wrapped.on_invoke_tool(_ctx([allow_rule]), json.dumps({"cmd": "ls"}))
    assert result == 'ran:{"cmd": "ls"}'


@pytest.mark.asyncio
async def test_different_scans_see_their_own_rules_on_the_same_shared_tool_object() -> None:
    """Tool singletons are process-wide; rules are per-scan context, not per-tool."""
    wrapped = factory._with_function_tool_interception(_tool())
    denied = await wrapped.on_invoke_tool(_ctx([_deny_rule()]), json.dumps({"cmd": "x"}))
    allowed = await wrapped.on_invoke_tool(_ctx(None), json.dumps({"cmd": "x"}))
    assert cast("str", denied).startswith("Denied")
    assert allowed == 'ran:{"cmd": "x"}'


@pytest.mark.asyncio
async def test_wrapping_is_idempotent() -> None:
    tool = _tool()
    once = factory._with_function_tool_interception(tool)
    twice = factory._with_function_tool_interception(once)
    assert once is twice
    result = await twice.on_invoke_tool(_ctx([_deny_rule()]), json.dumps({"cmd": "x"}))
    assert cast("str", result).startswith("Denied")


@pytest.mark.asyncio
async def test_custom_tool_deny_and_ask() -> None:
    wrapped = factory._with_custom_tool_interception(_custom_tool())
    denied = await wrapped.on_invoke_tool(_ctx([_deny_rule("apply_patch")]), "the patch text")
    assert cast("str", denied).startswith("Denied")

    needs = wrapped.needs_approval
    assert callable(needs)
    assert await needs(_ctx([_ask_rule("apply_patch")]), "the patch text", "call-1") is True


@pytest.mark.asyncio
async def test_custom_tool_as_function_tool_is_intercepted() -> None:
    """The chat-completions conversion path (apply_patch et al.) also gets interception."""
    wrapped = factory._custom_tool_as_function_tool(_custom_tool())
    denied = await wrapped.on_invoke_tool(
        _ctx([_deny_rule("apply_patch")]), json.dumps({"patch": "the patch text"})
    )
    assert cast("str", denied).startswith("Denied")
