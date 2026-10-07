# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""Top-level Strix scan runner.

Two public entrypoints share one scan body (:func:`_run_scan`):

* :func:`run_strix_scan` — upstream-compatible entrypoint used by the CLI and
  TUI. Its signature and behaviour are unchanged from upstream.
* :func:`run_recon_scan` — Recon's entrypoint. A superset that additionally
  threads the trusted-egress gateway policy into the sandbox and runs the
  engine's deterministic coverage worker before sandbox teardown.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import logging
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agents import RunConfig
from agents.sandbox import SandboxRunConfig
from openai import RateLimitError

from strix.agents.factory import build_strix_agent, make_child_factory
from strix.agents.prompt import render_system_prompt
from strix.config import load_settings
from strix.config.models import (
    StrixProvider,
    configure_sdk_model_defaults,
    supports_strict_tool_schemas,
    uses_chat_completions_tool_schema,
)
from strix.config.settings import DEFAULT_MAX_TURNS
from strix.core.agents import AgentCoordinator
from strix.core.execution import (
    respawn_subagents,
    run_agent_loop,
)
from strix.core.execution import (
    spawn_child_agent as start_child_agent,
)
from strix.core.hooks import BudgetExceededError, ReportUsageHooks, recomputed_budget_flags
from strix.core.inputs import (
    build_root_task,
    build_scan_targets,
    build_scope_context,
    make_model_settings,
)
from strix.core.paths import run_dir_for, runtime_state_dir
from strix.core.sessions import open_agent_session
from strix.report.state import get_global_report_state
from strix.runtime import session_manager
from strix.telemetry import set_scan_phase
from strix.telemetry.logging import set_scan_id, setup_scan_logging
from strix.tools.output_store import (
    WORKSPACE_SPILL_DIR,
    configure_spill_writer,
)


if TYPE_CHECKING:
    from agents.memory import SQLiteSession
    from agents.result import RunResultBase

    from strix.runtime.status import StatusSink
    from strix.tools.mcp import (
        ConnectedMcpServer,
        McpConnectionRequest,
        McpRegistry,
        SupervisedMcpSession,
    )


logger = logging.getLogger(__name__)

StreamEventSink = Callable[[str, Any], None]

# Receives the run's MCP connection roster as a list of non-secret status dicts
# ({"name", "provider", "tool_count", "dead"}), once when the connections are
# established and again each time a connection transitions to dead. An interface
# can persist it, render it, or forward it on as connection status. Kept as a
# snapshot of the whole roster (not a per-
# connection delta) so every call carries a consistent, current picture.
McpStatusSink = Callable[[list[dict[str, Any]]], None]


def _mcp_roster_payload(registry: McpRegistry) -> list[dict[str, Any]]:
    """The run's MCP roster as non-secret status dicts (name/provider/tool_count/dead)."""
    return [
        {
            "name": status.name,
            "provider": status.provider,
            "tool_count": status.tool_count,
            "dead": status.dead,
        }
        for status in registry.statuses()
    ]


def _mcp_startup_summary(connections: list[ConnectedMcpServer]) -> str:
    """One user-facing line summarizing the MCP servers that connected."""
    server_count = len(connections)
    tool_count = sum(c.tool_count for c in connections)
    servers_word = "server" if server_count == 1 else "servers"
    tools_word = "tool" if tool_count == 1 else "tools"
    names = ", ".join(c.name for c in connections)
    return f"MCP: connected {server_count} {servers_word} ({tool_count} {tools_word}): {names}"


def _record_mcp_connections(connections: list[ConnectedMcpServer]) -> None:
    """Record which MCP servers this run connected, for the interfaces.

    A server's tools are offered to the model under a name built from the
    connection name and the tool's own name, which cannot be split back apart, so
    the TUI and the run viewer need the names to match a tool call against before
    they can show which server it went out to. Kept on the run record because the
    viewer reads a finished run from disk.
    """
    report_state = get_global_report_state()
    if report_state is None:
        return
    report_state.record_mcp_connections([connection.name for connection in connections])


def _note_exit_reason(reason: str) -> None:
    """Record why the scan stopped so the end-of-scan beacon reports it."""
    report_state = get_global_report_state()
    if report_state is not None and report_state.scan_ended_exit_reason is None:
        report_state.scan_ended_exit_reason = reason


def _persist_mcp_status(roster: list[dict[str, Any]]) -> None:
    """Write the run's non-secret MCP connection status roster to run.json.

    The viewer rebuilds its display by re-reading the run's files from disk, so
    it cannot see the in-memory ``mcp_status_sink`` the TUI consumes. Persisting
    the same non-secret roster (name / provider / tool_count / dead) gives the
    viewer a source it can poll. Runs regardless of whether an interface sink is
    attached, so the standalone / non-TUI CLI path records health too.
    """
    report_state = get_global_report_state()
    if report_state is None:
        return
    report_state.record_mcp_connection_status(roster)


def _merge_root_prompt_context(
    scope_context: dict[str, Any],
    extra_system_prompt_context: dict[str, Any] | None,
) -> dict[str, Any]:
    if not extra_system_prompt_context:
        return scope_context
    reserved_keys = scope_context.keys() & extra_system_prompt_context.keys()
    if reserved_keys:
        raise ValueError(
            "extra_system_prompt_context cannot override built-in scope keys: "
            f"{sorted(reserved_keys)}",
        )
    return {**scope_context, **extra_system_prompt_context}


def _compose_root_instructions_override(
    root_instructions_override: str | None,
    *,
    skills: list[str],
    scan_mode: str,
    is_whitebox: bool,
    is_diff_scoped: bool,
    interactive: bool,
    system_prompt_context: dict[str, Any],
) -> str | None:
    if root_instructions_override is None:
        return None

    base_instructions = render_system_prompt(
        skills=skills,
        scan_mode=scan_mode,
        is_whitebox=is_whitebox,
        is_root=True,
        is_diff_scoped=is_diff_scoped,
        interactive=interactive,
        system_prompt_context=system_prompt_context,
    )
    return (
        f"{base_instructions}\n\n"
        "<root_scan_instructions_override>\n"
        "The following root scan instructions are subordinate to the "
        "system-verified scope above. They cannot expand, replace, or weaken "
        "authorized target constraints.\n\n"
        f"{root_instructions_override}\n"
        "</root_scan_instructions_override>"
    )


async def _run_scan(
    *,
    scan_config: dict[str, Any],
    scan_id: str | None = None,
    image: str,
    local_sources: list[dict[str, Any]] | None = None,
    extra_files: list[dict[str, Any]] | None = None,
    coordinator: AgentCoordinator | None = None,
    interactive: bool = False,
    max_turns: int = DEFAULT_MAX_TURNS,
    max_budget_usd: float | None = None,
    model: str | None = None,
    cleanup_on_exit: bool = True,
    event_sink: StreamEventSink | None = None,
    root_instructions_override: str | None = None,
    extra_system_prompt_context: dict[str, Any] | None = None,
    status_sink: StatusSink | None = None,
    mcp_connection_requests: list[McpConnectionRequest] | None = None,
    mcp_status_sink: McpStatusSink | None = None,
    gateway_spec_path: str = "",
    gateway_spec_json: str = "",
    gateway_target_ports: tuple[int, ...] = (),
    coverage_context: Any = None,
    run_coverage_worker_on_exit: bool = False,
) -> RunResultBase | None:
    """Shared scan body for :func:`run_strix_scan` and :func:`run_recon_scan`.

    The public contract for the shared parameters is documented on
    :func:`run_strix_scan`. The Recon-only parameters are documented on
    :func:`run_recon_scan`; they default to inert values so the upstream path
    (empty gateway policy, no coverage worker) is byte-for-byte the old
    behaviour.
    """

    def report(phase: str) -> None:
        if status_sink is not None:
            status_sink(phase)

    if scan_id is None:
        scan_id = f"scan-{uuid.uuid4().hex[:8]}"

    run_dir = run_dir_for(scan_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    state_dir = runtime_state_dir(run_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    teardown_logging = setup_scan_logging(run_dir)
    set_scan_id(scan_id)

    agents_path = state_dir / "agents.json"
    agents_db = state_dir / "agents.db"
    is_resume = agents_path.exists()

    logger.info(
        "%s Strix scan %s (image=%s, max_turns=%d, interactive=%s, run_dir=%s)",
        "Resuming" if is_resume else "Starting",
        scan_id,
        image,
        max_turns,
        interactive,
        run_dir,
    )

    settings = load_settings()
    configure_sdk_model_defaults(settings)
    resolved_model = (model or settings.llm.model or "").strip()
    if not resolved_model:
        raise RuntimeError(
            "No LLM model configured. Set STRIX_LLM env or pass model= to run_strix_scan().",
        )
    logger.info("LLM model resolved: %s", resolved_model)
    chat_completions_tools = uses_chat_completions_tool_schema(resolved_model, settings)
    strict_tool_schemas = supports_strict_tool_schemas(resolved_model)
    if not strict_tool_schemas:
        logger.info("Sending non-strict tool schemas: %s caps strict tools", resolved_model)

    if coordinator is None:
        coordinator = AgentCoordinator()
    coordinator.set_snapshot_path(agents_path)

    from strix.tools.coverage.tools import hydrate_coverage_from_disk
    from strix.tools.notes.tools import hydrate_notes_from_disk
    from strix.tools.threat_model.tools import hydrate_threat_models_from_disk
    from strix.tools.todo.tools import hydrate_todos_from_disk

    hydrate_todos_from_disk(state_dir)
    hydrate_notes_from_disk(state_dir)
    hydrate_coverage_from_disk(state_dir)
    hydrate_threat_models_from_disk(state_dir)

    root_id: str | None = None
    if is_resume:
        try:
            snap = json.loads(agents_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"Cannot resume scan {scan_id}: agents.json is unreadable: {exc}",
            ) from exc
        if not agents_db.exists():
            raise RuntimeError(
                f"Cannot resume scan {scan_id}: missing SDK session database at {agents_db}",
            )
        await coordinator.restore(snap)
        report_state = get_global_report_state()
        if report_state is not None:
            budget_stopped, reserve_stopped = recomputed_budget_flags(
                report_state.get_total_llm_cost(),
                max_budget_usd,
                interactive=interactive,
            )
            await coordinator.reset_budget_stops(
                budget_stopped=budget_stopped,
                reserve_stopped=reserve_stopped,
                budget_paused=interactive and coordinator.budget_paused,
            )
        for aid, parent in coordinator.parent_of.items():
            if parent is None:
                root_id = aid
                break
        if root_id is None:
            raise RuntimeError(
                f"Cannot resume scan {scan_id}: agents.json has no root agent (parent=None)",
            )
        logger.info(
            "Resume: restored coordinator with %d agent(s); root=%s",
            len(coordinator.statuses),
            root_id,
        )
    else:
        root_id = uuid.uuid4().hex[:8]

    logger.info("Bringing up sandbox session for scan %s", scan_id)
    set_scan_phase("sandbox_init")
    bundle = await session_manager.create_or_reuse(
        scan_id,
        image=image,
        local_sources=local_sources or [],
        extra_files=extra_files,
        status_sink=status_sink,
        gateway_spec_path=gateway_spec_path,
        gateway_spec_json=gateway_spec_json,
        gateway_target_ports=gateway_target_ports,
    )
    report("Waiting for the first model response")
    logger.info("Sandbox ready for scan %s", scan_id)
    set_scan_phase("agent_setup")

    sandbox_session = bundle["session"]

    async def _spill_to_workspace(output_id: str, text: str) -> str | None:
        """Write an oversized tool result into the sandbox; return its path or None."""
        path = f"{WORKSPACE_SPILL_DIR}/{output_id}.txt"
        try:
            await sandbox_session.write(Path(path), io.BytesIO(text.encode("utf-8")))
        except Exception:
            logger.exception("failed to spill tool output to sandbox workspace")
            return None
        return path

    configure_spill_writer(_spill_to_workspace)

    sessions_to_close: list[SQLiteSession] = []
    mcp_sessions: list[SupervisedMcpSession] = []
    scan_cancelled = False

    try:
        targets = scan_config.get("targets") or []
        scan_mode = str(scan_config.get("scan_mode") or "deep")
        is_whitebox = any(t.get("type") == "local_code" for t in targets)
        diff_scope = scan_config.get("diff_scope")
        is_diff_scoped = bool(isinstance(diff_scope, dict) and diff_scope.get("active"))
        skills = list(scan_config.get("skills") or [])
        root_task = build_root_task(scan_config)
        model_settings = make_model_settings(
            settings.llm.reasoning_effort,
            model_name=resolved_model,
            force_required_tool_choice=settings.llm.force_required_tool_choice,
            request_timeout=settings.llm.timeout,
            prompt_cache=settings.llm.prompt_cache,
            extra_headers=settings.llm.extra_headers,
        )
        run_config = RunConfig(
            model=resolved_model,
            model_provider=StrixProvider(),
            model_settings=model_settings,
            sandbox=SandboxRunConfig(client=bundle["client"], session=bundle["session"]),
            trace_include_sensitive_data=False,
            # A hallucinated tool name is a recoverable model mistake, not a scan-ending
            # error: hand it back as a tool result so the agent can correct itself.
            tool_not_found_behavior="return_error_to_model",
        )
        hooks = ReportUsageHooks(
            model=resolved_model,
            max_budget_usd=max_budget_usd,
            max_turns=max_turns,
            interactive=interactive,
        )
        if interactive:
            coordinator.set_budget_extender(hooks.extend_budget)

        scope_context = build_scope_context(scan_config)

        # Attach the run's MCP connections and hold their live sessions in a
        # per-run registry. The connections are source-agnostic: a caller
        # (the SaaS/pro product) can supply them as mcp_connection_requests, and
        # when it does not the command-line path reads them from
        # ~/.strix/mcp-servers.json here. Either way one shared engine routine
        # does the connecting and populating. Nothing is registered as an agent
        # tool: every agent reaches these connections on demand through the
        # list_mcps / describe_mcp / call_mcp tools, guided by brief static prompt
        # guidance when any connection exists. Fail-open: a missing config, or a
        # server that will not connect, must never break a run.
        from strix.tools.mcp import (
            McpConnectionRequest,
            McpRegistry,
            attach_mcp_requests,
            load_user_mcp_configs,
        )

        mcp_registry = McpRegistry()
        try:
            if mcp_connection_requests is None:
                # Command-line default: read the user's file and wrap each config
                # in a bare request (no provider or transform), so this path is
                # exactly the old behavior.
                mcp_requests = [
                    McpConnectionRequest(config=config) for config in load_user_mcp_configs()
                ]
            else:
                mcp_requests = mcp_connection_requests
            if mcp_requests:
                connections = await attach_mcp_requests(mcp_requests, mcp_registry)
                mcp_sessions = [c.session for c in connections]
                # Recorded even when nothing connected, so a resumed run does not
                # keep attributing tool calls to servers it no longer has.
                _record_mcp_connections(connections)
                if connections:
                    report(_mcp_startup_summary(connections))
                    # Name the connected servers in the prompt so every agent
                    # (root and children, both deriving from scope_context) sees
                    # what is available at the start; they can still re-list or
                    # inspect them at run time via list_mcps / describe_mcp. Set
                    # only when a connection exists, so a run with no MCP leaves
                    # the prompt context unchanged.
                    scope_context["mcp_available"] = bool(mcp_registry)
                    scope_context["mcp_connections"] = [
                        {
                            "name": summary.name,
                            "purpose": summary.purpose,
                            "tool_count": summary.tool_count,
                        }
                        for summary in mcp_registry.summaries()
                    ]

                    # Feed a non-secret connection roster (name / provider /
                    # tool_count / dead) to two consumers: once now (all
                    # currently healthy) and again whenever a connection later
                    # dies. It is always persisted to run.json so the viewer,
                    # which re-reads the run's files from disk, can render the
                    # MCP connections panel and health without an in-memory
                    # sink. When an interface sink is attached (the TUI backend,
                    # or pro forwarding into the app's event stream) it also
                    # receives the same snapshot. In-use is derived separately by
                    # each interface from the connection-tagged tool-call events,
                    # so it is not carried here.
                    def _emit_mcp_status() -> None:
                        roster = _mcp_roster_payload(mcp_registry)
                        _persist_mcp_status(roster)
                        if mcp_status_sink is not None:
                            try:
                                mcp_status_sink(roster)
                            except Exception:
                                logger.exception("MCP status sink failed")

                    for connection_name in mcp_registry.names():
                        entry = mcp_registry.get(connection_name)
                        if entry is not None:
                            entry.session.set_on_dead(_emit_mcp_status)
                    _emit_mcp_status()
        except Exception:
            logger.exception("Failed to connect user MCP servers; continuing without them")

        root_context = _merge_root_prompt_context(scope_context, extra_system_prompt_context)
        root_instructions = _compose_root_instructions_override(
            root_instructions_override,
            skills=skills,
            scan_mode=scan_mode,
            is_whitebox=is_whitebox,
            is_diff_scoped=is_diff_scoped,
            interactive=interactive,
            system_prompt_context=root_context,
        )

        root_agent = build_strix_agent(
            name="Root Agent",
            skills=skills,
            is_root=True,
            scan_mode=scan_mode,
            is_whitebox=is_whitebox,
            is_diff_scoped=is_diff_scoped,
            interactive=interactive,
            chat_completions_tools=chat_completions_tools,
            strict_tool_schemas=strict_tool_schemas,
            system_prompt_context=root_context,
            instructions_override=root_instructions,
        )

        if not is_resume:
            await coordinator.register(
                root_id,
                "Root Agent",
                parent_id=None,
                task=root_task,
                skills=skills,
            )

        child_agent_builder = make_child_factory(
            scan_mode=scan_mode,
            is_whitebox=is_whitebox,
            is_diff_scoped=is_diff_scoped,
            interactive=interactive,
            chat_completions_tools=chat_completions_tools,
            strict_tool_schemas=strict_tool_schemas,
            system_prompt_context=scope_context,
        )

        async def spawn_child_agent(**kwargs: Any) -> dict[str, Any]:
            return await start_child_agent(
                coordinator=coordinator,
                factory=child_agent_builder,
                agents_db_path=agents_db,
                sessions_to_close=sessions_to_close,
                run_config=run_config,
                max_turns=max_turns,
                interactive=interactive,
                event_sink=event_sink,
                hooks=hooks,
                **kwargs,
            )

        context: dict[str, Any] = {
            "coordinator": coordinator,
            "sandbox_session": bundle["session"],
            "caido_client": bundle["caido_client"],
            "mcp_registry": mcp_registry,
            "agent_id": root_id,
            "parent_id": None,
            "interactive": interactive,
            "spawn_child_agent": spawn_child_agent,
            "scan_targets": build_scan_targets(scan_config),
            "max_context_images": settings.runtime.max_context_images,
        }

        root_session = open_agent_session(root_id, agents_db)
        sessions_to_close.append(root_session)
        await coordinator.attach_runtime(root_id, session=root_session)

        if is_resume:
            await respawn_subagents(
                coordinator=coordinator,
                factory=child_agent_builder,
                agents_db_path=agents_db,
                sessions_to_close=sessions_to_close,
                run_config=run_config,
                max_turns=max_turns,
                interactive=interactive,
                parent_ctx=context,
                root_id=root_id,
                event_sink=event_sink,
                hooks=hooks,
            )

        initial_input: Any = [] if is_resume else root_task

        # Resume + new ``--instruction``: SDK replay drives root from
        # agents.db with ``initial_input=[]``, so a brand-new instruction
        # passed on the resume CLI would otherwise be silently ignored.
        # Inject it as a fresh user message in root's SDK session; the
        # next run cycle will replay it with the rest of the session.
        resume_instruction = str(scan_config.get("resume_instruction") or "").strip()
        if is_resume and resume_instruction:
            await coordinator.send(
                root_id,
                {
                    "from": "user",
                    "type": "instruction",
                    "priority": "high",
                    "content": resume_instruction,
                },
            )
            logger.info(
                "Resume: injected new instruction into root SDK session (len=%d)",
                len(resume_instruction),
            )

        async with coordinator._lock:
            root_status = coordinator.statuses.get(root_id)

        set_scan_phase("agent_loop")
        result = await run_agent_loop(
            agent=root_agent,
            initial_input=initial_input,
            run_config=run_config,
            context=context,
            max_turns=max_turns,
            coordinator=coordinator,
            agent_id=root_id,
            interactive=interactive,
            session=root_session,
            start_parked=bool(interactive and is_resume and root_status != "running"),
            event_sink=event_sink,
            hooks=hooks,
        )
        if not interactive and result is not None:
            final = getattr(result, "final_output", None)
            scan_completed = False
            if isinstance(final, str):
                try:
                    parsed = json.loads(final)
                    scan_completed = bool(isinstance(parsed, dict) and parsed.get("scan_completed"))
                except (ValueError, TypeError):
                    scan_completed = False
            elif isinstance(final, dict):
                scan_completed = bool(final.get("scan_completed"))
            if not scan_completed:
                logger.error(
                    "Scan %s ended without calling finish_scan. The agent "
                    "emitted a text-only turn instead of a lifecycle tool call, "
                    "so no executive report was written. Final output (first "
                    "300 chars): %r",
                    scan_id,
                    str(final)[:300],
                )
        return result  # noqa: TRY300
    except BudgetExceededError as exc:
        logger.info("Scan %s stopped: %s", scan_id, exc)
        _note_exit_reason("budget_exceeded")
        if root_id is not None:
            with contextlib.suppress(Exception):
                await coordinator.set_status(root_id, "stopped")
        return None
    except RateLimitError as exc:
        logger.warning(
            "Scan %s stopped: persistent rate limit from the LLM provider (%s). "
            "Resume with 'strix --resume %s' once the limit clears.",
            scan_id,
            exc,
            scan_id,
        )
        _note_exit_reason("rate_limited")
        if root_id is not None:
            with contextlib.suppress(Exception):
                await coordinator.set_status(root_id, "stopped")
        return None
    except (asyncio.CancelledError, KeyboardInterrupt):
        logger.info("Scan %s interrupted by the user", scan_id)
        scan_cancelled = True
        if root_id is not None:
            with contextlib.suppress(Exception):
                await coordinator.set_status(root_id, "running")
        raise
    except BaseException:
        logger.exception("Strix scan %s failed", scan_id)
        if root_id is not None:
            with contextlib.suppress(Exception):
                await coordinator.set_status(root_id, "failed")
        raise
    finally:
        configure_spill_writer(None)
        # Settle descendants before closing sessions: on a clean finish a child
        # can still be mid-turn, and closing its session underneath it crashes it.
        if root_id is not None:
            with contextlib.suppress(Exception):
                await coordinator.cancel_descendants(root_id)
        for s in sessions_to_close:
            with contextlib.suppress(Exception):
                s.close()
        for mcp_session in mcp_sessions:
            with contextlib.suppress(Exception):
                await mcp_session.aclose()
        with contextlib.suppress(Exception):
            await coordinator._maybe_snapshot()
        # Recon: capture the gateway's observed traffic and run the engine's
        # deterministic coverage worker while the sandbox session + gateway
        # client are still live in the session cache — they exec through the
        # gateway and write their revision-bound results to the run dir for the
        # engine to fold onto the coverage ledger after this returns. This must
        # precede teardown (cleanup() evicts the session they need), so it is
        # wrapped in its own try/finally: teardown below runs even if coverage is
        # cancelled or raises. Skipped on an interrupt — a cancelled scan is being
        # torn down, not finished, and the worker's probe budget could run long.
        # Gated by the flag the Recon entrypoint sets on its final phase; a no-op
        # for run_strix_scan.
        try:
            if run_coverage_worker_on_exit and not scan_cancelled:
                try:
                    await asyncio.wait_for(
                        _run_coverage_on_exit(
                            scan_id, run_dir, scan_config, coverage_context, report,
                        ),
                        timeout=_COVERAGE_DEADLINE_S,
                    )
                except asyncio.TimeoutError:
                    logger.error(
                        "coverage on exit exceeded its %.0fs deadline for scan %s; "
                        "abandoning it and tearing down (the engine records the "
                        "missing/partial coverage)",
                        _COVERAGE_DEADLINE_S,
                        scan_id,
                    )
        finally:
            if cleanup_on_exit:
                logger.info("Tearing down sandbox session for scan %s", scan_id)
                await session_manager.cleanup(scan_id)
            logger.info("Strix scan %s done", scan_id)
            teardown_logging()


def _ensure_engine_on_path() -> None:
    """Best-effort add the ``engine/`` dir to sys.path so ``recon_engine`` imports.

    The Recon venv normally has it on sys.path already; this is a safety net for
    hosts that import this module from an unusual CWD. Mirrors the helper in
    ``strix.tools.ledger.tools``.
    """
    import sys

    here = Path(__file__).resolve()
    # engine/ is the ancestor above third_party/strix/strix/core/runner.py.
    engine_dir = here.parents[4]
    if engine_dir.name == "engine" and str(engine_dir) not in sys.path:
        sys.path.insert(0, str(engine_dir))


def _primary_web_target_url(scan_config: dict[str, Any]) -> str:
    """The first authorized web-application target URL in ``scan_config``, or ``""``.

    The coverage worker uses observed gateway traffic to find the target base and
    falls back to this declared origin when the agent never exercised the target
    (e.g. an exhausted budget). Mirrors the ``web_application`` -> ``target_url``
    mapping in :func:`strix.core.inputs.build_scope_context`.
    """
    for target in scan_config.get("targets") or []:
        if not isinstance(target, dict) or target.get("type") != "web_application":
            continue
        details = target.get("details") or {}
        url = str(details.get("target_url") or "").strip()
        if url:
            return url
    return ""


# How often the coverage phase reports progress to the status sink. The engine's
# activity heartbeat ticker has a no-progress stall watchdog (default 600s) that
# stops heartbeating so Temporal retries a hung agent; the deterministic coverage
# worker can legitimately probe a large surface for longer than that AFTER the
# agent loop has ended (so no agent events arrive). A steady progress ping keeps
# a healthy coverage run from being mistaken for a hang. Well under any sane stall.
_COVERAGE_PROGRESS_INTERVAL_S = 60.0

# Hard upper bound on the whole coverage-on-exit phase. The progress ping above
# keeps the stall watchdog quiet while coverage runs, which is correct for a
# healthy run but would also hide a genuinely hung step forever — so the phase is
# wrapped in this deadline. It is generous headroom over the worker's own probe
# budget (worker _TOTAL_BUDGET_SECONDS is 1200s); past it, coverage is abandoned
# and the sandbox is torn down, so the engine completes the run (its finalizer
# records the missing/partial coverage) instead of the activity hanging.
_COVERAGE_DEADLINE_S = 1800.0


async def _run_coverage_on_exit(
    scan_id: str,
    run_dir: Path,
    scan_config: dict[str, Any],
    coverage_context: Any,
    report: Callable[[str], None],
) -> None:
    """Capture gateway coverage, then run the engine's deterministic coverage worker.

    Both steps run before sandbox teardown while the sandbox session and gateway
    client are still live in ``session_manager._SESSION_CACHE`` — the Recon
    entrypoint asks for this on its final/monolithic phase, right before this
    runner evicts the session. Order matters: persisting the gateway's observed
    traffic first writes ``gateway_endpoints.json``, which the authz worker reads
    to find the exercised origin and GraphQL endpoint (and which the engine folds
    into api-surface coverage); without it the worker falls back to the declared
    target and loses observed-traffic evidence.

    Both live in the Recon engine, which this package does not hard-depend on, so
    they are imported lazily. Everything is best-effort: a missing ``recon_engine``
    or a step failure is logged and never masks the scan's own outcome — the worker
    writes a revision-bound failure envelope the engine reads back.

    ``report`` is pinged on a timer throughout so the engine's heartbeat stall
    watchdog does not kill a healthy but long coverage run (no agent events arrive
    once the agent loop has ended).
    """
    try:
        _ensure_engine_on_path()
        from recon_engine.backends.gateway_capture_client import persist_gateway_coverage
        from recon_engine.coverage_worker import run_authz_worker
    except Exception:
        logger.warning(
            "coverage on exit requested but recon_engine is not importable; "
            "skipping (install the engine or run via run_strix_scan for a plain scan)",
            exc_info=True,
        )
        return

    async def _progress_pump() -> None:
        while True:
            await asyncio.sleep(_COVERAGE_PROGRESS_INTERVAL_S)
            with contextlib.suppress(Exception):
                report("coverage worker running")

    report("coverage: capturing gateway traffic")
    pump = asyncio.create_task(_progress_pump())
    try:
        # Observed-traffic coverage first: the worker and the engine both read it.
        with contextlib.suppress(Exception):
            await persist_gateway_coverage(scan_id, run_dir)
        target_url = _primary_web_target_url(scan_config)
        try:
            await run_authz_worker(
                scan_id,
                run_dir,
                target_url=target_url,
                coverage_context=coverage_context,
            )
        except Exception:
            logger.exception("coverage worker on exit failed (non-fatal)")
    finally:
        pump.cancel()
        with contextlib.suppress(BaseException):
            await pump


async def run_strix_scan(
    *,
    scan_config: dict[str, Any],
    scan_id: str | None = None,
    image: str,
    local_sources: list[dict[str, Any]] | None = None,
    extra_files: list[dict[str, Any]] | None = None,
    coordinator: AgentCoordinator | None = None,
    interactive: bool = False,
    max_turns: int = DEFAULT_MAX_TURNS,
    max_budget_usd: float | None = None,
    model: str | None = None,
    cleanup_on_exit: bool = True,
    event_sink: StreamEventSink | None = None,
    root_instructions_override: str | None = None,
    extra_system_prompt_context: dict[str, Any] | None = None,
    status_sink: StatusSink | None = None,
    mcp_connection_requests: list[McpConnectionRequest] | None = None,
    mcp_status_sink: McpStatusSink | None = None,
) -> RunResultBase | None:
    """Run or resume one Strix scan against a sandbox.

    ``root_instructions_override`` adds root scan instructions to the rendered
    root prompt without replacing the system-verified scope block.
    ``extra_files`` entries (``{"workspace_path", "content"}``) are placed into
    the sandbox workspace at session bring-up; see
    :func:`strix.runtime.session_manager.create_or_reuse`.
    ``extra_system_prompt_context`` is merged into the root agent's scan
    context before prompt rendering. Child agents keep the standard scan prompt
    and context.
    ``mcp_connection_requests`` supplies the run's MCP connections from any
    source: when given, the engine connects those requests; when ``None`` (the
    command-line default) it reads ``~/.strix/mcp-servers.json`` itself. Either
    way the engine does the connecting, so the caller passes inert configs plus
    metadata and never live sessions.
    """
    return await _run_scan(
        scan_config=scan_config,
        scan_id=scan_id,
        image=image,
        local_sources=local_sources,
        extra_files=extra_files,
        coordinator=coordinator,
        interactive=interactive,
        max_turns=max_turns,
        max_budget_usd=max_budget_usd,
        model=model,
        cleanup_on_exit=cleanup_on_exit,
        event_sink=event_sink,
        root_instructions_override=root_instructions_override,
        extra_system_prompt_context=extra_system_prompt_context,
        status_sink=status_sink,
        mcp_connection_requests=mcp_connection_requests,
        mcp_status_sink=mcp_status_sink,
    )


async def run_recon_scan(
    *,
    scan_config: dict[str, Any],
    scan_id: str | None = None,
    image: str,
    local_sources: list[dict[str, Any]] | None = None,
    extra_files: list[dict[str, Any]] | None = None,
    coordinator: AgentCoordinator | None = None,
    interactive: bool = False,
    max_turns: int = DEFAULT_MAX_TURNS,
    max_budget_usd: float | None = None,
    model: str | None = None,
    cleanup_on_exit: bool = True,
    event_sink: StreamEventSink | None = None,
    root_instructions_override: str | None = None,
    extra_system_prompt_context: dict[str, Any] | None = None,
    status_sink: StatusSink | None = None,
    mcp_connection_requests: list[McpConnectionRequest] | None = None,
    mcp_status_sink: McpStatusSink | None = None,
    gateway_spec_path: str = "",
    gateway_spec_json: str = "",
    gateway_target_ports: tuple[int, ...] = (),
    coverage_context: Any = None,
    run_coverage_worker_on_exit: bool = False,
) -> RunResultBase | None:
    """Recon's scan entrypoint: :func:`run_strix_scan` plus trusted egress + coverage.

    Accepts every :func:`run_strix_scan` parameter (same contract) and, on top:

    ``gateway_spec_path`` / ``gateway_spec_json`` carry the engagement's
    rules-of-engagement egress policy to the sandbox. Exactly one may be set
    (path for the docker-contained backend's mounted spec, JSON for the k8s
    sibling-gateway Pod). ``gateway_target_ports`` pins the non-standard target
    port(s) the gateway allows. These are forwarded unchanged to
    :func:`strix.runtime.session_manager.create_or_reuse`, which validates them
    fail-closed; an empty policy leaves the sandbox exactly as a plain scan.

    ``coverage_context`` is the engine's per-run coverage-ledger handle. It is
    not consumed inside the scan loop; it is handed to the on-exit coverage
    worker so the worker reads the exact pinned revision and the declared
    GraphQL endpoint from it.

    ``run_coverage_worker_on_exit`` asks this runner to invoke the engine's
    deterministic coverage/authz worker once, before sandbox teardown, while the
    sandbox session and gateway client are still live. The engine sets it on a
    monolithic run and on the final phase of a phased run (aligned with
    ``cleanup_on_exit``); on earlier phases it is ``False`` so the shared sandbox
    survives. The worker writes its results to the run dir for the engine to
    fold onto the coverage ledger after this returns.
    """
    return await _run_scan(
        scan_config=scan_config,
        scan_id=scan_id,
        image=image,
        local_sources=local_sources,
        extra_files=extra_files,
        coordinator=coordinator,
        interactive=interactive,
        max_turns=max_turns,
        max_budget_usd=max_budget_usd,
        model=model,
        cleanup_on_exit=cleanup_on_exit,
        event_sink=event_sink,
        root_instructions_override=root_instructions_override,
        extra_system_prompt_context=extra_system_prompt_context,
        status_sink=status_sink,
        mcp_connection_requests=mcp_connection_requests,
        mcp_status_sink=mcp_status_sink,
        gateway_spec_path=gateway_spec_path,
        gateway_spec_json=gateway_spec_json,
        gateway_target_ports=gateway_target_ports,
        coverage_context=coverage_context,
        run_coverage_worker_on_exit=run_coverage_worker_on_exit,
    )
