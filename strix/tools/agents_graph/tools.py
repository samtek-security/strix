# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""Multi-agent graph tools backed by AgentCoordinator."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections import Counter
from datetime import UTC, datetime
from typing import Any, Literal, get_args

from agents import RunContextWrapper, function_tool

from strix.config import load_settings
from strix.core.agents import ACTIVE_STATUSES, Status, coordinator_from_context
from strix.core.execution import notify_parent_on_terminal
from strix.core.hooks import LLM_TURN_KEY
from strix.report.state import get_global_report_state
from strix.skills import validate_requested_skills
from strix.tools.output_store import bound_text


logger = logging.getLogger(__name__)


def _ctx(ctx: RunContextWrapper) -> dict[str, Any]:
    return ctx.context if isinstance(ctx.context, dict) else {}


def _filed_reports_by(agent_id: str) -> list[dict[str, Any]]:
    """Vulnerability reports the agent actually filed, from report state.

    The narrative ``findings`` an agent hands to ``agent_finish`` is prose; a
    parent that wants to act on a child's work needs the report ids. Read them
    from the report state rather than trusting the child's description.
    """
    state = get_global_report_state()
    if state is None:
        return []
    filed: list[dict[str, Any]] = []
    seen: set[str] = set()
    for report in state.get_existing_vulnerabilities():
        if report.get("agent_id") != agent_id:
            continue
        report_id = str(report.get("id") or "")
        if not report_id or report_id in seen:
            continue
        seen.add(report_id)
        filed.append(report)
    return filed


def _render_filed_report(report: dict[str, Any]) -> str:
    line = f"- {report.get('id')}"
    severity = report.get("severity")
    if severity:
        line += f" [{str(severity).upper()}]"
    title = report.get("title")
    if title:
        line += f" {title}"
    return line


def _render_completion_report(
    *,
    agent_name: str,
    agent_id: str,
    task: str,
    success: bool,
    result_summary: str,
    findings: list[str],
    recommendations: list[str],
    open_items: list[str],
    filed_reports: list[dict[str, Any]] | None = None,
) -> str:
    """Render a child's completion report as plain structured text.

    Goes into the parent's SDK session with coordinator-added sender
    metadata, so this body just carries the contents. No XML — no
    escaping concerns, no parser ambiguity.
    """
    status = "SUCCESS" if success else "FAILED"
    completion_time = datetime.now(UTC).isoformat()

    lines: list[str] = [
        f"== Completion report from {agent_name} ({agent_id}) ==",
        f"Status: {status}",
        f"Time: {completion_time}",
    ]
    if task:
        lines.append(f"Task: {task}")
    lines.append("")
    lines.append("Summary:")
    lines.append(result_summary or "(none)")
    if findings:
        lines.append("")
        lines.append("Findings:")
        lines.extend(f"- {f}" for f in findings)
    lines.append("")
    lines.append("Vulnerability reports filed by this agent (authoritative; use these ids):")
    if filed_reports:
        lines.extend(_render_filed_report(r) for r in filed_reports)
    else:
        lines.append("- (none)")
    lines.append("")
    lines.append("Open items (unresolved, need follow-up):")
    if open_items:
        lines.extend(f"- {o}" for o in open_items)
    else:
        lines.append("- (none)")
    if recommendations:
        lines.append("")
        lines.append("Recommendations:")
        lines.extend(f"- {r}" for r in recommendations)
    return "\n".join(lines)


@function_tool(timeout=30)
async def view_agent_graph(ctx: RunContextWrapper) -> str:
    """Print the multi-agent tree — every agent, its parent, its status.

    Use before spawning a new agent (don't duplicate work — check whether
    something specialized for that task already exists) and any time you
    want a snapshot of who's still ``running`` / ``waiting`` /
    ``completed`` / ``crashed`` / ``stopped``. Output is an indented
    bullet list with status in brackets; the agent that called this tool
    is marked ``← you``.
    """
    inner = _ctx(ctx)
    coordinator = coordinator_from_context(inner)
    me = inner.get("agent_id")
    if coordinator is None:
        return json.dumps(
            {"success": False, "error": "Agent coordinator not initialized in context"},
            ensure_ascii=False,
            default=str,
        )

    parent_of, statuses, names, _ = await coordinator.graph_snapshot()

    lines: list[str] = []

    def render(aid: str, depth: int) -> None:
        status = statuses.get(aid, "?")
        marker = "  ← you" if aid == me else ""
        lines.append(f"{'  ' * depth}- {names.get(aid, aid)} ({aid}) [{status}]{marker}")
        for child, p in parent_of.items():
            if p == aid:
                render(child, depth + 1)

    roots = [aid for aid, parent in parent_of.items() if parent is None]
    for root in roots:
        render(root, 0)

    counts = Counter(statuses.values())
    summary: dict[str, int] = {"total": len(parent_of)}
    for status_name in get_args(Status):
        summary[status_name] = counts.get(status_name, 0)
    return json.dumps(
        {
            "success": True,
            "graph_structure": "\n".join(lines) or "(no agents)",
            "summary": summary,
        },
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def send_message_to_agent(
    ctx: RunContextWrapper,
    target_agent_id: str,
    message: str,
    message_type: Literal["query", "instruction", "information"] = "information",
    priority: Literal["low", "normal", "high", "urgent"] = "normal",
) -> str:
    """Send a message to another agent's inbox — sparingly.

    Inter-agent messages are appended to the target's SDK session and
    interrupt any active target turn so the next run cycle sees them.
    Use only when essential:

    - Sharing a discovered finding/credential another agent needs.
    - Asking a specialist a focused question.
    - Coordinating who covers what (avoid overlap).
    - Telling a child to wrap up or change course.

    **Don't** use for routine "hello/status" pings, for context the
    target already has (children inherit parent history), or when
    parent/child completion via ``agent_finish`` already covers the
    flow. In interactive runs a message wakes the target regardless of
    status, so a follow-up can restart a completed/stopped/failed agent.
    In non-interactive runs a finished agent is gone for good: the call
    fails with the target's status, and you should read its filed
    reports (``list_reports``) or spawn a new agent instead of waiting.

    Args:
        target_agent_id: Recipient's 8-char id.
        message: The full message body. Be specific — include payloads,
            URLs, or what you want them to do, not just headlines.
        message_type: ``query`` (you want a reply), ``instruction``
            (you're directing them), ``information`` (FYI, no reply
            expected). Default ``information``.
        priority: ``low`` / ``normal`` / ``high`` / ``urgent``.
    """
    inner = _ctx(ctx)
    coordinator = coordinator_from_context(inner)
    me = inner.get("agent_id")
    if coordinator is None or me is None:
        return json.dumps(
            {"success": False, "error": "Agent coordinator or agent_id missing in context"},
            ensure_ascii=False,
            default=str,
        )
    if target_agent_id == me:
        return json.dumps(
            {
                "success": False,
                "error": (
                    "Cannot send a message to yourself; use `think` to record a "
                    "private note, or `agent_finish` / `finish_scan` to terminate"
                ),
            },
            ensure_ascii=False,
            default=str,
        )

    msg_id = f"msg_{uuid.uuid4().hex[:8]}"
    delivered = await coordinator.send(
        target_agent_id,
        {
            "id": msg_id,
            "from": me,
            "content": message,
            "type": message_type,
            "priority": priority,
        },
    )
    if not delivered:
        _, status = await coordinator.reachability(target_agent_id)
        if status is None:
            error = f"Target agent '{target_agent_id}' not found"
        else:
            error = (
                f"Target agent '{target_agent_id}' is '{status}' and cannot be woken in "
                "this run; it will never read this message. Its filed reports are in "
                "list_reports / get_report. Do not wait_for_agents on it - spawn a new "
                "agent if more work is needed."
            )
        return json.dumps(
            {
                "success": False,
                "error": error,
                "target_agent_id": target_agent_id,
                "target_status": status,
                "delivery_status": "not_delivered",
            },
            ensure_ascii=False,
            default=str,
        )
    return json.dumps(
        {
            "success": True,
            "message_id": msg_id,
            "target_agent_id": target_agent_id,
            "delivery_status": "delivered",
        },
        ensure_ascii=False,
        default=str,
    )


_CALL_ITEM_TYPES = ("function_call", "custom_tool_call")
_OUTPUT_ITEM_TYPES = ("function_call_output", "custom_tool_call_output")


def _session_items_payload(items: list[Any]) -> list[dict[str, Any]]:
    payload: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            payload.append({"content": str(item)})
            continue
        item_type = item.get("type")
        if item_type in _CALL_ITEM_TYPES:
            # A tool call's own request — e.g. the HTTP request a proxy/terminal
            # tool sent, or a Responses-mode apply_patch call. role/content are
            # absent on this item type; name/arguments (or input, for a custom
            # tool call) carry what happened instead. call_id is the only link
            # to its output, which matters once a turn has more than one call
            # in flight.
            call_entry = {
                "type": item_type,
                "call_id": item.get("call_id"),
                "name": item.get("name"),
            }
            if item_type == "function_call":
                call_entry["arguments"] = item.get("arguments")
            else:
                call_entry["input"] = item.get("input")
            payload.append(call_entry)
        elif item_type in _OUTPUT_ITEM_TYPES:
            # The matching result — e.g. the response body that proved an
            # exploit. This is usually where confirmed evidence actually lives.
            payload.append(
                {
                    "type": item_type,
                    "call_id": item.get("call_id"),
                    "output": item.get("output"),
                }
            )
        else:
            payload.append({"role": item.get("role"), "content": item.get("content")})
    return payload


def _drop_orphaned_outputs(items: list[Any]) -> list[Any]:
    """Drop every function_call_output/custom_tool_call_output whose
    matching call isn't in this list (truncation cut it, or it's not
    adjacent — parallel calls can persist as call A, call B, output A,
    output B, so a cut can orphan one without being at either end). An
    orphaned output has no tool name or arguments, just a dangling call_id
    and a result nobody can trace back to what produced it."""
    call_ids = {
        item.get("call_id")
        for item in items
        if isinstance(item, dict) and item.get("type") in _CALL_ITEM_TYPES
    }
    return [
        item
        for item in items
        if not (
            isinstance(item, dict)
            and item.get("type") in _OUTPUT_ITEM_TYPES
            and item.get("call_id") not in call_ids
        )
    ]


_PAIR_EXTENSION_LIMIT = 3  # multiplier on max_items while still pairing calls to outputs


def _bound_evidence(items: list[Any], *, max_items: int) -> tuple[list[dict[str, Any]], bool]:
    """Bound one agent's evidence by item count, keeping call/output pairs
    together. Byte-bounding the complete response happens separately, once
    every agent's evidence is assembled — see ``_fit_evidence_to_byte_cap``.
    Returns the bounded payload and whether anything was cut.

    A parallel-tool-call turn can persist as a whole block of calls followed
    by a whole block of outputs, not call-output pairs one after another. A
    plain tail slice of such a turn can land entirely inside the output
    block, with every one of its calls just outside the cut - leaving
    nothing but orphaned outputs, which a naive drop then empties out
    completely even though the turn's evidence is real and substantial.
    Walking backward and extending past ``max_items`` while a call is still
    owed (bounded by ``_PAIR_EXTENSION_LIMIT`` so one pathologically wide
    turn can't swallow unbounded history) keeps that evidence instead.
    """
    total = len(items)
    if total <= max_items:
        return _session_items_payload(list(items)), False

    hard_ceiling = max_items * _PAIR_EXTENSION_LIMIT
    needed_call_ids: set[Any] = set()
    kept_reversed: list[Any] = []
    for item in reversed(items):
        if len(kept_reversed) >= hard_ceiling:
            break
        if len(kept_reversed) >= max_items and not needed_call_ids:
            break
        kept_reversed.append(item)
        if isinstance(item, dict):
            item_type = item.get("type")
            if item_type in _OUTPUT_ITEM_TYPES:
                needed_call_ids.add(item.get("call_id"))
            elif item_type in _CALL_ITEM_TYPES:
                needed_call_ids.discard(item.get("call_id"))

    bounded = list(reversed(kept_reversed))
    bounded = _drop_orphaned_outputs(bounded)
    truncated = len(bounded) < total
    return _session_items_payload(bounded), truncated


def _result_byte_size(result: dict[str, Any]) -> int:
    return len(json.dumps(result, ensure_ascii=False, default=str).encode("utf-8"))


_RESULT_BYTE_CAP_MARGIN = 256


def _fit_evidence_to_byte_cap(
    result: dict[str, Any],
    stopped_agents: list[dict[str, Any]],
    total_items_by_agent: dict[str, int],
) -> None:
    """Shrink stopped_agents' evidence in place until the whole stop_agent
    result fits the tool-output byte cap every tool's result is bound to.

    Each agent's evidence is already item-count-bounded, but that bounds
    item count, not bytes — one agent's evidence, or several added
    together, can still be the one thing that pushes the complete response
    over the cap the generic per-tool-result wrapper enforces. Missing this
    means that wrapper replaces the whole response with a non-JSON
    head/tail preview, which would hide evidence in the middle rather than
    say plainly how much was cut. Trims from whichever entry currently
    holds the most evidence, so one huge session doesn't starve the rest.
    """
    cap = max(load_settings().context.tool_output_max_bytes - _RESULT_BYTE_CAP_MARGIN, 512)
    while _result_byte_size(result) > cap:
        candidates = [e for e in stopped_agents if e.get("evidence")]
        if not candidates:
            break
        target = max(candidates, key=lambda e: len(json.dumps(e["evidence"], default=str)))
        target["evidence"] = _drop_orphaned_outputs(target["evidence"][1:])
        target["evidence_truncated"] = True
        target["evidence_complete"] = False
        target["evidence_total_items"] = total_items_by_agent.get(
            target["agent_id"], len(target["evidence"])
        )
    overage = _result_byte_size(result) - cap
    if overage <= 0:
        return
    # Every agent's evidence is already gone and the response is still over
    # the cap: a long reason/note, or enough agents' own id/name fields, is
    # what's left. Compact the free-text fields we control instead of
    # handing back an oversized response for the generic wrapper to turn
    # into a non-JSON preview anyway.
    for key in ("note", "reason"):
        text = result.get(key)
        if not isinstance(text, str) or not text:
            continue
        budget = max(len(text.encode("utf-8")) - overage - 64, 32)
        result[key] = bound_text(text, max_lines=20, max_bytes=budget)
        overage = _result_byte_size(result) - cap
        if overage <= 0:
            return
    # Still over: a long name on one entry, or many entries' names added
    # together in a large cascade. agent_id is left alone — it is the one
    # field a caller needs to act on the result (view_agent_graph,
    # send_message_to_agent, another stop_agent) — but name is informational.
    for name_limit in (60, 20):
        for entry in stopped_agents:
            name = entry.get("name")
            if isinstance(name, str) and len(name) > name_limit:
                entry["name"] = name[: name_limit - 1] + "…"
        if _result_byte_size(result) <= cap:
            return
    # Still over: enough agents in one cascade that even their bare
    # agent_id/name/evidence_settled skeleton exceeds an aggressively small
    # configured cap. Nothing left to compact without losing which agent an
    # entry is about, so drop whole entries from the end - reporting that
    # plainly - rather than returning an oversized response for the generic
    # wrapper to hide everyone's status in a non-JSON preview. The markers
    # themselves cost bytes too, so they go on before the loop measures
    # against cap, not after it decides cap is already met.
    _drop_entries_to_cap(result, stopped_agents, cap)


def _drop_entries_to_cap(
    result: dict[str, Any], stopped_agents: list[dict[str, Any]], cap: int
) -> None:
    """Last resort for ``_fit_evidence_to_byte_cap``: drop whole entries and
    report which ones, with both finality flags false for them."""
    original_count = len(stopped_agents)
    result["stopped_agents_truncated"] = True
    result["stopped_agents_total"] = original_count
    omitted_ids: list[str] = []
    result["stopped_agents_omitted"] = {
        "agent_ids": omitted_ids,
        "evidence_writes_final": False,
        "evidence_complete": False,
    }
    while len(stopped_agents) > 1 and _result_byte_size(result) > cap:
        omitted_ids.insert(0, stopped_agents.pop()["agent_id"])
    # Many omitted agents can push their bare ids past the cap too. Keep the
    # count exact and cut the id list instead, saying so.
    omitted_info = result["stopped_agents_omitted"]
    omitted_info["count"] = len(omitted_ids)
    while omitted_ids and _result_byte_size(result) > cap:
        omitted_ids.pop()
        omitted_info["agent_ids_truncated"] = True
    if len(stopped_agents) == original_count:
        del result["stopped_agents_truncated"]
        del result["stopped_agents_total"]
        del result["stopped_agents_omitted"]


_WAIT_DEFAULT_TIMEOUT_S = 300
# Enforced by the SDK around the whole tool call, so it caps an oversized
# ``timeout_seconds`` the model asks for. One second of headroom lets the
# tool's own timeout fire first and return a clean result.
_WAIT_HARD_CEILING_S = _WAIT_DEFAULT_TIMEOUT_S + 1
_WAITED_TURN_KEY = "waited_llm_turn"


@function_tool(timeout=_WAIT_HARD_CEILING_S)
async def wait_for_agents(  # noqa: PLR0911
    ctx: RunContextWrapper,
    reason: str = "Waiting for messages from other agents",
    timeout_seconds: int = _WAIT_DEFAULT_TIMEOUT_S,
) -> str:
    """Pause until another AGENT messages you (or the timeout elapses).

    Use when you have nothing useful to do until a child or peer
    responds — typically after spawning subagents and you want their
    completion reports. You resume the instant any message arrives, so
    size ``timeout_seconds`` to the work you're awaiting.

    **Issue exactly one wait, then stop and react to what it returns.**
    This call blocks and resumes on its own; it is not a poll you repeat.
    Do not write out a wait/check loop ahead of time — a second wait in
    the same turn returns immediately without waiting.

    **This tool is only for waiting on other agents.** Two things it is
    NOT for:

    - **Waiting for the user.** Write your reply as plain text, then call
      ``wait_for_user`` to hand control back.
    - **Waiting for a long-running command.** This tool does not watch
      processes at all — it sleeps until a *message* arrives, so it
      burns the full timeout even if your command finished a second
      later. Poll the process instead: ``exec_command`` returns a
      session/process id, and ``write_stdin`` with ``chars=""`` returns
      as soon as there is new output or the process exits.

    **Critical caveats:**

    - **Never** call this if you have no agents left to hear from —
      that just strands you until the timeout. Call ``finish_scan``
      (root) or ``agent_finish`` (subagent) instead.
    - If you're waiting on an agent that **isn't your child**, message
      it first asking it to ping you when done — otherwise it has no
      reason to send to your inbox and you'll wait the full timeout.
    - Children update the parent automatically via ``agent_finish``
      → no extra coordination needed.

    Args:
        reason: One-line note shown in graph snapshots while you're
            waiting (helps a human or sibling agent debug who's stuck
            on what).
        timeout_seconds: Max seconds to wait (default 300, and values above
            that are cut short by a hard ceiling). This is only
            a cap — the tool returns the INSTANT a message arrives, so a
            larger value never makes you wait longer when the reply does
            come. Right-size it to what you're waiting on: a short wait
            (e.g. 10-60s) for a quick ack or a small/fast subtask, and a
            longer one (e.g. ~100-200s) only for genuinely long-running
            work (deep recon, exploitation, a full sub-scan). The cap only
            bites when the expected message never arrives — so an oversized
            timeout on a trivial wait just strands you idle until it
            elapses. On timeout the tool returns and you decide whether to
            keep working or wait again.
    """
    inner = _ctx(ctx)
    coordinator = coordinator_from_context(inner)
    me = inner.get("agent_id")
    interactive = bool(inner.get("interactive", False))
    if coordinator is None or me is None:
        return json.dumps(
            {"success": False, "error": "Agent coordinator or agent_id missing in context"},
            ensure_ascii=False,
            default=str,
        )

    turn = inner.get(LLM_TURN_KEY)
    if turn is not None and inner.get(_WAITED_TURN_KEY) == turn:
        return json.dumps(
            {
                "success": True,
                "wait_outcome": "already_waited",
                "reason": reason,
                "note": (
                    "You already waited in this turn. A single wait_for_agents blocks and "
                    "resumes on its own, so queueing more waits only strands you — issue one "
                    "wait, then react to what it returns."
                ),
            },
            ensure_ascii=False,
            default=str,
        )
    inner[_WAITED_TURN_KEY] = turn

    async with coordinator._lock:
        stopped = coordinator.statuses.get(me) == "stopped"
    if stopped:
        return json.dumps(
            {
                "success": True,
                "wait_outcome": "stopped",
                "reason": reason,
                "note": "Wait ended because this agent is stopped.",
            },
            ensure_ascii=False,
            default=str,
        )

    pending, items = await coordinator.consume_pending(me, include_items=True)
    if pending > 0:
        await coordinator.mark_running(me)
        return json.dumps(
            {
                "success": True,
                "wait_outcome": "message_arrived",
                "pending_messages": pending,
                "messages": _session_items_payload(items),
                "reason": reason,
            },
            ensure_ascii=False,
            default=str,
        )

    if interactive:
        await coordinator.park_waiting(me, wait_kind="agents")
        return json.dumps(
            {
                "success": True,
                "wait_outcome": "waiting",
                "reason": reason,
                "note": "Agent parked; execution will resume when a message arrives.",
            },
            ensure_ascii=False,
            default=str,
        )

    # Non-interactive agents cannot be woken once terminal, so with nobody
    # running or waiting there is no message left to wait for.
    if not await coordinator.active_agents_except(me):
        _, statuses, names, _ = await coordinator.graph_snapshot()
        return json.dumps(
            {
                "success": True,
                "wait_outcome": "no_active_agents",
                "reason": reason,
                "agents": [
                    {"agent_id": aid, "name": names.get(aid, aid), "status": status}
                    for aid, status in statuses.items()
                    if aid != me
                ],
                "note": (
                    "No other agent is running or waiting, so no message can arrive. "
                    "Finished agents' results are in list_reports / get_report and their "
                    "completion reports are already in your history. Continue your own "
                    "work, spawn a new agent, or finish."
                ),
            },
            ensure_ascii=False,
            default=str,
        )

    await coordinator.park_waiting(me, wait_kind="agents")
    try:
        await asyncio.wait_for(coordinator.wait_for_message(me), timeout_seconds)
    except TimeoutError:
        await coordinator.mark_running(me)
        return json.dumps(
            {
                "success": True,
                "wait_outcome": "timeout",
                "timeout_seconds": timeout_seconds,
                "reason": reason,
                "note": "No messages within timeout — continue work or call agent_finish.",
            },
            ensure_ascii=False,
            default=str,
        )

    async with coordinator._lock:
        stopped = coordinator.statuses.get(me) == "stopped"
    if stopped:
        return json.dumps(
            {
                "success": True,
                "wait_outcome": "stopped",
                "reason": reason,
                "note": "Wait ended because this agent is stopped.",
            },
            ensure_ascii=False,
            default=str,
        )

    pending, items = await coordinator.consume_pending(me, include_items=True)
    await coordinator.mark_running(me)

    return json.dumps(
        {
            "success": True,
            "wait_outcome": "message_arrived",
            "pending_messages": pending,
            "messages": _session_items_payload(items),
            "reason": reason,
        },
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=120)
async def create_agent(
    ctx: RunContextWrapper,
    name: str,
    task: str,
    inherit_context: bool = True,
    skills: list[str] | None = None,
) -> str:
    """Spawn a specialist child agent to run in parallel.

    Decompose complex pentests by handing focused subtasks to dedicated
    children. The child runs asynchronously — the parent continues
    immediately and can ``wait_for_agents`` later (or just keep
    working in parallel). When the child calls ``agent_finish``, its
    completion report lands in the parent's inbox.

    **Before spawning, call ``view_agent_graph``** to confirm no
    existing agent already covers this scope — duplicate specialists
    waste turns and create coordination headaches.

    **Specialization principles:**

    - Most agents need at least one ``skill`` to be useful.
    - Aim for **1-3 related skills** per agent. Up to 5 only when the
      task genuinely spans them.
    - One skill = most focused (e.g., XSS-only). Five skills = upper
      bound.
    - Match the ``name`` to the focus (``XSS Specialist``,
      ``SQLi Validator``, ``Auth Specialist``).

    **When to spawn vs do it yourself:**

    - Spawn when the subtask is large, parallelizable, or needs
      different specialization than what you're already doing.
    - Don't spawn for trivial one-shot probes — just run the tool
      yourself.

    Args:
        name: Human-readable child name (used in graph views and
            ``send_message_to_agent`` flows).
        task: Specific objective. Be concrete — what to test, what
            success looks like, any constraints. Name the target the
            child should call ``get_threat_model`` on, and any shared
            state it should build on rather than rediscover — what
            recon already mapped, which surfaces are already covered.
            A child that is not told what is already known repeats it.
        inherit_context: Default ``True``. The child receives the
            parent's input history as background; only set ``False``
            when starting a clean-slate task.
        skills: List of skill names (e.g. ``["xss", "sql_injection"]``).
            Max 5; prefer 1-3.
    """
    inner = _ctx(ctx)
    coordinator = coordinator_from_context(inner)
    parent_id = inner.get("agent_id")
    spawner = inner.get("spawn_child_agent")

    if coordinator is None or parent_id is None:
        return json.dumps(
            {"success": False, "error": "Agent coordinator or agent_id missing in context"},
            ensure_ascii=False,
            default=str,
        )
    if not callable(spawner):
        return json.dumps(
            {
                "success": False,
                "error": "Scan runner did not provide a child-agent spawner in context",
            },
            ensure_ascii=False,
            default=str,
        )

    skill_list = list(skills or [])
    skill_error = validate_requested_skills(skill_list)
    if skill_error:
        return json.dumps(
            {"success": False, "error": skill_error, "agent_id": None},
            ensure_ascii=False,
            default=str,
        )

    parent_history = list(ctx.turn_input) if inherit_context and ctx.turn_input else []
    try:
        result = await spawner(
            parent_ctx=inner,
            name=name,
            task=task,
            skills=skill_list,
            parent_history=parent_history,
        )
    except Exception as e:
        logger.exception("create_agent: scan runner failed to spawn child '%s'", name)
        return json.dumps(
            {"success": False, "error": f"child spawn failed: {e!s}"},
            ensure_ascii=False,
            default=str,
        )

    logger.info(
        "create_agent: spawned %s (%s) parent=%s skills=%d task_len=%d",
        result.get("agent_id"),
        name,
        parent_id or "-",
        len(skill_list),
        len(task or ""),
    )

    return json.dumps(
        result,
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def agent_finish(
    ctx: RunContextWrapper,
    result_summary: str,
    findings: list[str] | None = None,
    open_items: list[str] | None = None,
    success: bool = True,
    report_to_parent: bool = True,
    final_recommendations: list[str] | None = None,
) -> str:
    """Subagent termination — post a completion report to the parent.

    **Subagents only.** Root agents must call ``finish_scan`` instead;
    this tool refuses to run for root agents. Calling this:

    1. Marks the subagent as ``completed``.
    2. Posts a structured completion report to the parent's inbox
       (when ``report_to_parent`` is true).
    3. Stops this subagent's execution.

    **Vulnerability findings must already be filed via
    ``create_vulnerability_report`` (or ``create_dependency_report``
    for known-CVE dependency/supply-chain findings) before calling
    this.** The ``findings`` field here is for narrative summary only
    — it does not register vulns in the scan report.

    Write the summary as if the parent has no idea what you were
    doing: what did you test, what did you find/confirm/rule out,
    what's still open.

    **Close out honestly.** Before calling this, anything you could
    neither confirm nor rule out belongs in ``open_items`` — an
    unresolved candidate handed up to the parent is useful, a silently
    dropped one is a missed vulnerability. Reporting nothing and
    listing no open items asserts the area is clean; only say that if
    you mean it.

    Args:
        result_summary: What you accomplished and discovered. Concrete
            and specific (URLs, parameters, payloads that worked).
        findings: Optional bullet list of confirmed observations. For
            credit-bearing vulnerabilities, file
            ``create_vulnerability_report`` first (or
            ``create_dependency_report`` for dependency CVEs); this is
            for narrative.
        open_items: Candidates you could NOT confirm and could NOT rule
            out with a named control, plus anything you ran out of time
            or access to test. State the specific gap (e.g. "password
            reset token entropy — could not obtain a second account to
            compare tokens"). Pass an empty list only when nothing is
            genuinely left open.
        success: Whether the assigned subtask was completed
            successfully. Default ``True``.
        report_to_parent: Whether to deliver the completion report to
            the parent's inbox. Default ``True``.
        final_recommendations: Optional next-step suggestions for the
            parent (e.g., "prioritize testing X", "spawn an agent to
            cover Y").
    """
    inner = _ctx(ctx)
    coordinator = coordinator_from_context(inner)
    me = inner.get("agent_id")
    if coordinator is None or me is None:
        return json.dumps(
            {"success": False, "error": "Agent coordinator or agent_id missing in context"},
            ensure_ascii=False,
            default=str,
        )

    parent_id = inner.get("parent_id")
    if parent_id is None:
        return json.dumps(
            {
                "success": False,
                "error": (
                    "agent_finish is for subagents. Root/main agents must call "
                    f"{coordinator.root_finish_tool} instead"
                ),
            },
            ensure_ascii=False,
            default=str,
        )

    filed_reports = _filed_reports_by(me)
    filed_report_ids = [str(r.get("id")) for r in filed_reports]

    parent_notified = False
    if report_to_parent and await coordinator.claim_parent_notice(me):
        async with coordinator._lock:
            agent_name = coordinator.names.get(me, me)
        report = _render_completion_report(
            agent_name=agent_name,
            agent_id=me,
            task=str(inner.get("task", "")),
            success=success,
            result_summary=result_summary,
            findings=list(findings or []),
            recommendations=list(final_recommendations or []),
            open_items=list(open_items or []),
            filed_reports=filed_reports,
        )
        await coordinator.send(
            parent_id,
            {
                "id": f"report_{uuid.uuid4().hex[:8]}",
                "from": me,
                "content": report,
                "type": "completion",
                "priority": "high",
                "filed_report_ids": filed_report_ids,
            },
        )
        parent_notified = True

    await coordinator.set_status(me, "completed")
    if not parent_notified:
        # Silence here would leave a parent waiting on a report that is never coming.
        await notify_parent_on_terminal(coordinator, me, "completed")

    logger.info(
        "agent_finish: %s success=%s findings=%d filed_reports=%d parent_notified=%s",
        me,
        success,
        len(findings or []),
        len(filed_report_ids),
        parent_notified,
    )

    return json.dumps(
        {
            "success": True,
            "agent_completed": True,
            "parent_notified": parent_notified,
            "agent_id": me,
            "summary": result_summary,
            "filed_report_ids": filed_report_ids,
            "findings_count": len(findings or []),
            "open_items_count": len(open_items or []),
            "has_recommendations": bool(final_recommendations),
        },
        ensure_ascii=False,
        default=str,
    )


_STOP_AGENT_TIMEOUT_S = 30
# Headroom under the tool's own timeout, split across every agent the cascade
# stops, so joining them one by one can never itself trip that outer timeout.
_STOP_AGENT_EVIDENCE_BUDGET_S = 20.0
# A long-lived validator's full session, or a cascade of several, can run
# well past what fits in the parent model's own input limit. Keep the most
# recent items per agent - that's where a just-confirmed lead lives - and say
# so plainly rather than silently dropping the rest.
_EVIDENCE_MAX_ITEMS_PER_AGENT = 60


@function_tool(timeout=_STOP_AGENT_TIMEOUT_S)
async def stop_agent(
    ctx: RunContextWrapper,
    target_agent_id: str,
    cascade: bool = True,
    reason: str = "",
) -> str:
    """Gracefully stop a running agent (and optionally its descendants).

    Uses the SDK's ``RunResultStreaming.cancel(mode="after_turn")`` so the
    target's current turn finishes — including saving items to its
    session — before the run loop honors the cancel. The agent's
    interactive outer loop parks as ``stopped``; later user/peer
    messages can wake it again.

    When you are the target's parent (or an ancestor further up), the
    result also carries each stopped agent's session items directly,
    under ``evidence`` — whatever it had already captured (confirmed
    requests, responses, PoC output) before you stopped it. Use that
    evidence to file or drop the lead yourself; do not re-derive the same
    work from scratch. ``evidence_settled: false`` on an entry means its
    turn was still finishing when this call gave up waiting, so its
    evidence may be incomplete — treat it as partial, not missing. An
    ``evidence_error`` key means the session itself could not be read;
    treat that as "unknown", not "nothing found". ``evidence_truncated: true``
    means only the most recent items are included here
    (``evidence_total_items`` has the real count) — a lead confirmed earlier
    in a long session may not appear. Stopping a peer or an ancestor is
    still allowed, but their evidence is withheld since their
    session is not yours to read.

    Two flags say whether the evidence is final. ``evidence_writes_final``
    is true only when the turn settled and the target cannot be woken into
    another one. An interactive target can be woken and start a brand new
    turn after it reports ``stopped`` — that is by design
    (``send_message_to_agent``'s docstring covers it) — so its flag stays
    false even when ``evidence_settled`` is true. ``evidence_complete`` is
    true only when the returned evidence was fully read: not truncated, not
    unreadable, not withheld and not cut by the byte limit. File a finding
    as final only when both flags are true; otherwise file what came back
    and mark it possibly incomplete. When ``stopped_agents_truncated`` is
    set, the agents that did not fit are listed by id under
    ``stopped_agents_omitted`` with both flags false for all of them; if
    even the id list does not fit, ``agent_ids_truncated`` is true and
    ``count`` still gives the number omitted.

    Use sparingly. Prefer ``send_message_to_agent`` (asking the agent
    to wrap up) for soft-stop scenarios. Reach for ``stop_agent`` when
    a child has gone off-track and won't self-correct.

    Args:
        target_agent_id: The 8-char id from ``view_agent_graph`` /
            ``create_agent``. Cannot stop yourself.
        cascade: If ``True`` (default), also stop every descendant of
            ``target_agent_id`` leaves-first. ``False`` stops only the
            target.
        reason: Optional human-readable reason for the stop, surfaced
            in logs and telemetry.
    """
    inner = _ctx(ctx)
    coordinator = coordinator_from_context(inner)
    me = inner.get("agent_id")
    if coordinator is None or me is None:
        return json.dumps(
            {"success": False, "error": "Agent coordinator or agent_id missing in context"},
            ensure_ascii=False,
            default=str,
        )
    if target_agent_id == me:
        return json.dumps(
            {
                "success": False,
                "error": "Cannot stop yourself; call agent_finish or finish_scan instead",
            },
            ensure_ascii=False,
            default=str,
        )
    _, statuses, names, _ = await coordinator.graph_snapshot()
    if target_agent_id not in statuses:
        return json.dumps(
            {"success": False, "error": f"Unknown agent_id: {target_agent_id}"},
            ensure_ascii=False,
            default=str,
        )

    current_status = statuses[target_agent_id]
    if current_status not in ACTIVE_STATUSES:
        return json.dumps(
            {
                "success": False,
                "error": (
                    f"Agent {target_agent_id} is already '{current_status}'; "
                    "stop_agent only acts on running/waiting/paused agents — use "
                    "view_agent_graph to find still-active descendants and "
                    "stop them individually, or send_message_to_agent if you "
                    "want to wake this one with new instructions"
                ),
                "target_agent_id": target_agent_id,
                "current_status": current_status,
            },
            ensure_ascii=False,
            default=str,
        )

    if cascade:
        stopped = await coordinator.cancel_descendants_graceful(target_agent_id)
    else:
        await coordinator.request_stop(target_agent_id)
        stopped = [target_agent_id]

    # The stopper knows what it just did; anyone else waiting on those agents does not.
    async with coordinator._lock:
        orphaned = [aid for aid in stopped if coordinator.parent_of.get(aid) not in (None, me)]
    for aid in orphaned:
        await notify_parent_on_terminal(coordinator, aid, "stopped")

    # Capture each stopped agent's own evidence now, while we have the only
    # handle on it. A stop is resumable in principle, but a non-interactive
    # root never resumes a stopped validator to ask for what it found — so if
    # we don't hand the evidence back here, it is gone.
    #
    # Only the target's own ancestors get the evidence: a session can carry
    # scan credentials or unrelated target data, and nothing stops a leaf
    # from naming a peer or the root as target_agent_id. cascade only ever
    # stops target_agent_id and its descendants, so one ancestry check on the
    # target covers every agent in ``stopped``.
    may_read_evidence = me is not None and await coordinator.is_ancestor(me, target_agent_id)
    join_timeout = _STOP_AGENT_EVIDENCE_BUDGET_S / max(len(stopped), 1)
    evidence: list[dict[str, Any]] = []
    total_items_by_agent: dict[str, int] = {}
    for aid in stopped:
        if not may_read_evidence:
            evidence.append(
                {
                    "agent_id": aid,
                    "name": names.get(aid, aid),
                    "evidence_settled": None,
                    "evidence_writes_final": False,
                    "evidence_complete": False,
                }
            )
            continue
        settled = await coordinator.join_stopped(aid, join_timeout)
        writes_final = settled and not await coordinator.is_resumable(aid)
        items = await coordinator.session_items(aid)
        if items is None:
            evidence.append(
                {
                    "agent_id": aid,
                    "name": names.get(aid, aid),
                    "evidence_settled": settled,
                    "evidence_writes_final": writes_final,
                    "evidence_complete": False,
                    "evidence": [],
                    "evidence_error": (
                        "failed to read this agent's session; evidence may exist but "
                        "could not be retrieved — do not treat this as 'nothing found'"
                    ),
                }
            )
            continue
        total_items_by_agent[aid] = len(items)
        bounded_payload, truncated = _bound_evidence(items, max_items=_EVIDENCE_MAX_ITEMS_PER_AGENT)
        entry: dict[str, Any] = {
            "agent_id": aid,
            "name": names.get(aid, aid),
            "evidence_settled": settled,
            "evidence_writes_final": writes_final,
            "evidence_complete": not truncated,
            "evidence": bounded_payload,
        }
        if truncated:
            entry["evidence_truncated"] = True
            entry["evidence_total_items"] = total_items_by_agent[aid]
        evidence.append(entry)

    logger.info(
        "stop_agent: target=%s cascade=%s reason=%r",
        target_agent_id,
        cascade,
        reason,
    )
    note = "Cancellation is graceful — current turn completes first. "
    note += (
        (
            "Each stopped agent's already-captured evidence is in "
            "'evidence' below; use it directly instead of re-deriving it."
        )
        if may_read_evidence
        else (
            "You are not this agent's parent (or an ancestor further up), so "
            "its session evidence is withheld here — ask its parent, or use "
            "list_reports for what it already filed."
        )
    )
    result = {
        "success": True,
        "target_agent_id": target_agent_id,
        "cascade": cascade,
        "reason": reason,
        "note": note,
        "stopped_agents": evidence,
    }
    _fit_evidence_to_byte_cap(result, evidence, total_items_by_agent)
    return json.dumps(
        result,
        ensure_ascii=False,
        default=str,
    )
