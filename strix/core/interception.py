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
        return re.compile(pattern)
    except re.error:
        logger.warning("interception rule pattern does not compile as regex: %r", pattern)
        return None


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
) -> InterceptionDecision | None:
    """Return the first matching rule's decision, or ``None`` for an implicit allow."""
    if not rules:
        return None
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
    if not context:
        return DEFAULT_ASK_TIMEOUT_SECONDS
    value = context.get(ASK_TIMEOUT_SECONDS_KEY)
    return float(value) if isinstance(value, (int, float)) and value > 0 else (
        DEFAULT_ASK_TIMEOUT_SECONDS
    )
