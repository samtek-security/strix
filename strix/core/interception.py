# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""Tool-call interception: allow/deny/ask rules evaluated at the tool boundary.

Generic and vendor-neutral, like the rest of ``strix.core``: a caller that never
supplies rules (``run_strix_scan``'s default) gets today's behaviour unchanged.
Recon supplies rules compiled from an engagement's signed RoE and an
:class:`ApprovalGateway` that talks to its control plane; this module knows
nothing about either.

Rules are evaluated in list order; the first match wins. No match is an
implicit allow, matching every tool's behaviour before this module existed.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import TYPE_CHECKING, Literal, Protocol


if TYPE_CHECKING:
    from collections.abc import Sequence


logger = logging.getLogger(__name__)

InterceptionField = Literal["tool_name", "tool_input"]
InterceptionAction = Literal["allow", "deny", "ask"]


@dataclass(frozen=True)
class InterceptionRule:
    """One allow/deny/ask rule, matched against a tool's name or its JSON arguments."""

    id: str
    field: InterceptionField
    pattern: str
    action: InterceptionAction
    regex: bool = False
    description: str = ""


@dataclass(frozen=True)
class InterceptionDecision:
    """The rule that matched a tool call, and the action it carries."""

    rule: InterceptionRule
    action: InterceptionAction


@lru_cache(maxsize=256)
def _compiled(pattern: str) -> re.Pattern[str] | None:
    try:
        # re.ASCII: \d \s \w \b mean the ASCII classes, as in Go's RE2, which is what
        # the control plane validated the pattern against.
        return re.compile(pattern, re.ASCII)
    except re.error:
        logger.warning("interception rule pattern does not compile as regex: %r", pattern)
        return None


def canonical_tool_input(value: object) -> str:
    """One text form of a tool call's input, whichever path produced it.

    The deny check sees the raw argument string, the ask check sees the parsed
    arguments, and the resume path sees the raw string again. Matching each of
    those directly lets whitespace, key order or unicode escapes make a rule fire
    in one place and not another, so every path goes through this first. JSON is
    re-encoded with sorted keys; anything that is not JSON (a custom tool's
    free-text payload) is returned unchanged.
    """
    parsed = value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except ValueError:
            return value
        if not isinstance(parsed, (dict, list)):
            return value
    elif not isinstance(value, (dict, list)):
        return str(value)
    # Sorted keys, default separators: the form the tool wrapper always matched
    # against, so a pattern written for it (`"command": "rm -rf`) keeps matching.
    text = json.dumps(parsed, ensure_ascii=False, sort_keys=True)
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        # A JSON-escaped lone surrogate decodes to text that cannot be encoded
        # (the dedup key and the broker body both encode it). Re-escape it.
        text = json.dumps(parsed, ensure_ascii=True, sort_keys=True)
    return text


# Native custom tools (apply_patch, ...) are offered to chat-completions routes as
# function tools taking one JSON field that wraps the real payload. A rule written
# against the tool's input means the payload, not the wrapper. The converted tool
# carries that field's name on itself, so the identity travels with the tool object
# and never with a process-wide name table that another scan's same-named tool could
# share.
PAYLOAD_FIELD_ATTR = "_strix_payload_field"


def payload_field_of(tool: object) -> str | None:
    """The payload field a converted custom tool carries, or None for any other tool."""
    field = getattr(tool, PAYLOAD_FIELD_ATTR, None)
    return field if isinstance(field, str) else None


def call_input(
    tool_name: str,  # noqa: ARG001 - kept so callers read as (tool, arguments)
    arguments: object,
    *,
    payload_field: str | None = None,
) -> tuple[str, bool]:
    """The text a rule should match for one call, and whether it is opaque.

    ``arguments`` is a function call's JSON string or parsed dict. For a custom
    tool converted to a function tool (``payload_field`` names its wrapper field)
    it is that field's text, verbatim, which is exactly what the converted tool
    executes (it ignores any other argument); for every other function tool it is
    the canonical JSON arguments.
    """
    if payload_field is not None:
        parsed = arguments
        if isinstance(arguments, str):
            try:
                parsed = json.loads(arguments)
            except ValueError:
                parsed = None
        if isinstance(parsed, dict) and isinstance(parsed.get(payload_field), str):
            return parsed[payload_field], True
    return canonical_tool_input(arguments), False


def _rule_matches(rule: InterceptionRule, tool_name: str, tool_input_text: str) -> bool:
    haystack = tool_name if rule.field == "tool_name" else tool_input_text
    if not rule.regex:
        return rule.pattern in haystack
    compiled = _compiled(rule.pattern)
    return compiled is not None and compiled.search(haystack) is not None


def evaluate(
    rules: Sequence[InterceptionRule] | None,
    tool_name: str,
    tool_input_text: str,
    *,
    verbatim: bool = False,
) -> InterceptionDecision | None:
    """Return the first matching rule's decision, or ``None`` for an implicit allow.

    Function-tool arguments are JSON and are matched in their canonical form.
    ``verbatim=True`` is for a native custom tool's payload, which is opaque text
    even when it happens to parse as JSON: a rule written against that exact text
    must see that exact text.
    """
    if not rules:
        return None
    if not verbatim:
        tool_input_text = canonical_tool_input(tool_input_text)
    for rule in rules:
        if _rule_matches(rule, tool_name, tool_input_text):
            return InterceptionDecision(rule=rule, action=rule.action)
    return None


ApprovalStatus = Literal["pending", "approved", "denied"]


class ApprovalGateway(Protocol):
    """Recon-specific transport for an "ask" rule's human round trip.

    ``request`` creates or joins a pending approval for ``dedup_key`` (concurrent
    calls to the same target collapse into the request that is already open) and
    returns its id. ``poll`` reads the current status; the caller is responsible
    for the wait loop, its own timeout, and keeping the host's keepalive mechanism
    (a Temporal heartbeat, for Recon) alive across it.
    """

    async def request(
        self,
        *,
        dedup_key: str,
        tool_name: str,
        tool_input_summary: str,
        rule_id: str,
        rule_description: str,
        ttl_seconds: float,
    ) -> str: ...

    async def poll(self, approval_id: str) -> ApprovalStatus: ...


# Context keys a caller populates on the ``context: dict`` passed to
# ``Runner.run_streamed`` (and therefore ``run_strix_scan``/``run_recon_scan``) to
# opt into interception. Absent keys mean "no rules configured": every tool call
# allows, exactly like before this module existed.
INTERCEPTION_RULES_KEY = "interception_rules"
APPROVAL_GATEWAY_KEY = "approval_gateway"
ASK_TIMEOUT_SECONDS_KEY = "ask_timeout_seconds"
# Absolute epoch second past which no ask may still be waiting (the engagement's
# elapsed-budget deadline less a closeout margin). Read per ask, not once per run:
# an ask late in a run, or several concurrent ones, must each see what is left now.
ASK_DEADLINE_AT_KEY = "ask_deadline_at"

DEFAULT_ASK_TIMEOUT_SECONDS = 300.0


def rules_from_context(context: dict[str, object] | None) -> Sequence[InterceptionRule] | None:
    if not context:
        return None
    rules = context.get(INTERCEPTION_RULES_KEY)
    return rules if isinstance(rules, (list, tuple)) else None


def gateway_from_context(context: dict[str, object] | None) -> ApprovalGateway | None:
    if not context:
        return None
    gateway = context.get(APPROVAL_GATEWAY_KEY)
    return gateway if gateway is not None else None


def ask_timeout_from_context(context: dict[str, object] | None) -> float:
    """Seconds an "ask" may wait. Absent or non-numeric means the default; a
    number is taken as given, floored at 0, because 0 is meaningful: the caller
    has no budget left, so the ask must deny at once instead of waiting."""
    if not context:
        return DEFAULT_ASK_TIMEOUT_SECONDS
    value = context.get(ASK_TIMEOUT_SECONDS_KEY)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return DEFAULT_ASK_TIMEOUT_SECONDS
    return max(0.0, float(value))


def ask_deadline_at_from_context(context: dict[str, object] | None) -> float | None:
    if not context:
        return None
    value = context.get(ASK_DEADLINE_AT_KEY)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)
