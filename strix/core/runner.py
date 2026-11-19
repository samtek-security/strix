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
import os
import uuid
from collections.abc import Awaitable, Callable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agents import RunConfig
from agents.sandbox import SandboxRunConfig
from openai import RateLimitError

try:
    from temporalio.exceptions import ApplicationError
except ImportError:  # pragma: no cover - non-Temporal host (CLI-only strix usage)
    ApplicationError = None  # type: ignore[assignment]

from strix.agents.factory import build_strix_agent, make_child_factory
from strix.agents.prompt import render_scope_prompt, render_system_prompt
from strix.config import codex, load_settings
from strix.config.models import (
    StrixProvider,
    configure_sdk_api_route,
    configure_sdk_model_defaults,
    model_supports_images,
    supports_strict_tool_schemas,
    uses_chat_completions_tool_schema,
)
from strix.config.settings import DEFAULT_MAX_TURNS
from strix.core.agents import AgentCoordinator, BudgetPolicy
from strix.core.execution import (
    respawn_subagents,
    run_agent_loop,
)
from strix.core.execution import (
    spawn_child_agent as start_child_agent,
)
from strix.core.hooks import (
    SUBAGENT_TURN_LIMITS_KEY,
    BudgetExceededError,
    ReportUsageHooks,
    recomputed_budget_flags,
)
from strix.core.inputs import (
    build_root_task,
    build_scan_targets,
    build_scope_context,
    make_model_settings,
)
from strix.core.paths import run_dir_for, runtime_state_dir
from strix.core.sessions import open_agent_session
from strix.llm import redaction
from strix.report.state import get_global_report_state
from strix.runtime import session_manager
from strix.telemetry import set_scan_phase
from strix.telemetry.logging import set_scan_id, setup_scan_logging
from strix.tools.finish.tool import finish_scan
from strix.tools.output_store import (
    WORKSPACE_SPILL_DIR,
    configure_spill_writer,
)
from strix.tools.reporting.tool import create_vulnerability_report


if TYPE_CHECKING:
    from agents.memory import SQLiteSession
    from agents.result import RunResultBase
    from agents.tool import Tool

    from strix.runtime.status import StatusSink
    from strix.tools.mcp import (
        McpConnectionRequest,
        McpRegistry,
    )


logger = logging.getLogger(__name__)

_MCP_PROMPT_WARMUP_TIMEOUT_SECONDS = 30.0

StreamEventSink = Callable[[str, Any], None]

# Receives the run's MCP connection roster as a list of non-secret status dicts
# ({"name", "provider", "tool_count", "dead", "state"}), once when the connections
# are registered and again on lifecycle transitions. An interface
# can persist it, render it, or forward it on as connection status. Kept as a
# snapshot of the whole roster (not a per-
# connection delta) so every call carries a consistent, current picture.
McpStatusSink = Callable[[list[dict[str, Any]]], None]


def _mcp_roster_payload(registry: McpRegistry) -> list[dict[str, Any]]:
    """The run's MCP roster as non-secret lifecycle status dicts."""
    return [
        {
            "name": status.name,
            "provider": status.provider,
            "tool_count": status.tool_count,
            "dead": status.dead,
            "state": status.state,
        }
        for status in registry.statuses()
    ]


def _mcp_prompt_roster(registry: McpRegistry) -> list[dict[str, Any]]:
    """The MCP roster rendered in agent prompts, with only verified counts."""
    return [
        {
            "name": summary.name,
            "purpose": summary.purpose,
            "tool_count": summary.tool_count if summary.state == "catalog_ready" else None,
            "state": summary.state,
        }
        for summary in registry.summaries()
    ]


def _record_mcp_connections(connection_names: list[str]) -> None:
    """Record which MCP servers this run configured, for the interfaces.

    A server's tools are offered to the model under a name built from the
    connection name and the tool's own name, which cannot be split back apart, so
    the TUI and the run viewer need the names to match a tool call against before
    they can show which server it went out to. Kept on the run record because the
    viewer reads a finished run from disk.
    """
    report_state = get_global_report_state()
    if report_state is None:
        return
    report_state.record_mcp_connections(connection_names)
    # Cred-expiry piece 3: publish the preflight verdicts to the process-global
    # map the engine activity reads after the scan returns.
    cred_pf = report_state.run_record.get("credential_preflight")
    if isinstance(cred_pf, dict) and isinstance(cred_pf.get("verdicts"), dict):
        _LAST_CRED_VERDICTS.update(cred_pf["verdicts"])


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
    parallel_tool_calls: bool,
    system_prompt_context: dict[str, Any],
    supports_images: bool,
    report_tool: str,
    coverage_tools: bool,
    replace_scan_prompt: bool = False,
) -> str | None:
    if root_instructions_override is None:
        return None
    if replace_scan_prompt:
        return f"{root_instructions_override}\n\n{render_scope_prompt(system_prompt_context)}"

    base_instructions = render_system_prompt(
        skills=skills,
        scan_mode=scan_mode,
        is_whitebox=is_whitebox,
        is_root=True,
        is_diff_scoped=is_diff_scoped,
        interactive=interactive,
        parallel_tool_calls=parallel_tool_calls,
        system_prompt_context=system_prompt_context,
        include_scope=False,
        supports_images=supports_images,
        report_tool=report_tool,
        coverage_tools=coverage_tools,
    )
    return (
        f"{base_instructions}\n\n"
        "<root_scan_instructions_override>\n"
        "The following root scan instructions describe the task configuration.\n\n"
        f"{root_instructions_override}\n"
        "</root_scan_instructions_override>\n\n"
        f"{render_scope_prompt(system_prompt_context)}"
    )


# Cred-expiry piece 2/3: the most recent preflight verdict map, kept process-global so
# the engine activity (which invokes the scan synchronously) can read it after the scan
# returns and fold it into the ticker-shared health state + the durable probe cap.
_LAST_CRED_VERDICTS: dict[str, str] = {}

# Cred-expiry piece 2: the closed set of typed credential failure names the
# sanitizer preserves through the engine boundary (values only; recognition is
# by the ApplicationError.type field, never by message text).
_CRED_ERROR_TYPES = frozenset(
    {"CredentialPurgedError", "CredentialRejectedError", "CredentialExpiredError"}
)

# Cred-expiry piece 2 (preflight credential verdict): how long one in-sandbox
# probe request may take, and the {role: verdict} recorded when no role has a
# declared probe target. Three-valued per the plan: ok / dead / unknown.
_CRED_PROBE_TIMEOUT_S = 15.0


def _parse_success_condition(cond: str) -> tuple[str, str]:
    """``('url_contains:/dashboard')`` -> ``('url_contains', '/dashboard')``.

    Local mirror of ``strix.runtime.auth_preflight._parse_success_condition``
    (kept identical so the preflight probe's declared-API reading cannot drift
    from the login preflight's).
    """
    cond = (cond or "").strip()
    if ":" in cond:
        kind, _, val = cond.partition(":")
        return kind.strip().lower(), val.strip()
    return (cond.lower(), "") if cond else ("", "")


def _declared_probe_target_for_role(flow: dict, base: str, graphql_path: str) -> tuple[str, str]:
    """The declared probe target for one role, or ``("", "")`` to record ``unknown``.

    Declared endpoints only, never guessed (cred-expiry piece 2): the
    engagement's ``GraphqlEndpoint`` (``graphql_path``, already normalized
    path-only) when declared, else the role's ``api_ok`` success-condition
    value (the declared API path) joined to the target origin. Returns
    ``(url, kind)`` with kind ``"graphql"`` or ``"api_ok"``.
    """
    if graphql_path:
        return base.rstrip("/") + graphql_path, "graphql"
    kind, val = _parse_success_condition(flow.get("success_condition") or "")
    if kind == "api_ok" and val:
        return base.rstrip("/") + ("" if val.startswith("/") else "/") + val, "api_ok"
    return "", ""


def _gql_identity_ok(body: bytes) -> bool:
    """Whether a GraphQL 2xx body proves identity (cred-expiry piece 2).

    A 2xx counts ONLY when the body is a JSON object whose ``data`` key is
    present, not null, and non-empty, with zero GraphQL ``errors``. A public
    endpoint answering ``{"data": {}}`` to anyone is the known gap recorded in
    the run metadata as a limitation.
    """
    try:
        v = json.loads(body.decode("utf-8", errors="replace"))
    except (ValueError, AttributeError):
        return False
    if not isinstance(v, dict) or v.get("errors"):
        return False
    d = v.get("data")
    return not (d is None or d == "" or d == [] or d == {})


def _record_cred_verdicts(verdicts: dict[str, str], limitation: bool) -> None:
    """Persist the run's preflight credential verdicts into run.json (best-effort).

    Non-secret (role + verdict only). ``limitation`` marks that some verdict
    came from the public-``{"data":{}}``-acceptable GraphQL evidence rule.

    Sticky like the dead verdicts themselves: the watchdog loop re-saves this same record on
    every later verdict CHANGE (one role dying mid-run must not erase evidence from a
    completely different role's EARLIER preflight probe) - OR'd with whatever was already
    persisted so a TRUE gap, once observed, is never reset back to False by an unrelated
    later write."""
    try:
        state = get_global_report_state()
        if state is None:
            return
        prior = (state.run_record.get("credential_preflight") or {}).get("graphql_empty_data_gap")
        state.run_record["credential_preflight"] = {
            "verdicts": dict(verdicts),
            "graphql_empty_data_gap": bool(limitation) or bool(prior),
        }
        state.save_run_data()
    except Exception:  # noqa: BLE001 - telemetry must never break the scan
        logger.exception("failed to record credential preflight verdicts")


def _role_already_dead(sticky_dead: dict[str, str] | None, role: str) -> bool:
    """Whether `role` is already recorded dead in sticky_dead, by exact match OR by any alias
    sharing its sandbox env var. An exact-match-only check misses a role declared under a
    different alias than the one sticky_dead happened to record it under (e.g. "User" vs
    "user", or "qa_user" vs "qa-user" - both pairs collapse to the SAME RECON_CRED_* env var
    the engine's own credential selection uses) - checked the same way here, so a role
    confirmed dead under one alias can never be probed again under another."""
    if not sticky_dead:
        return False
    if sticky_dead.get(role) == "dead":
        return True
    try:
        from recon_engine.activities import _cred_env_name
    except ImportError:  # pragma: no cover - light env without the engine
        return False
    env = _cred_env_name(role)
    return any(_cred_env_name(k) == env and v == "dead" for k, v in sticky_dead.items())


def _apply_sticky_dead(verdicts: dict[str, str], last_verdicts: dict[str, str]) -> dict[str, str]:
    """Overlay every role `last_verdicts` already has as ``dead`` onto `verdicts`, in place.

    `dead` is sticky for the life of a run (cred-expiry piece 3's invariant, otherwise only
    enforced inside the watchdog loop) - a later phase's own fresh preflight probe can
    legitimately come back ``unknown`` (its reservation refused because an earlier phase
    already spent this run's probe cap on that role), and without this overlay that would both
    erase the role's confirmed death from the process-global map AND let this phase's own
    abort-check miss it, proceeding to run agent turns against an already-dead credential."""
    for role, prior in last_verdicts.items():
        if prior == "dead":
            verdicts[role] = "dead"
    return verdicts


def _classify_cred_probe(status: int | None, kind: str, data_ok: bool, empty_data: bool) -> tuple[str, bool]:
    """One probe result -> (verdict, limitation). Shared by preflight (piece 2) and the
    mid-run watchdog (piece 3) so the two can never classify the same response differently.

    ``limitation`` flags the known gap where a public GraphQL endpoint answers ``{"data":{}}``
    to anyone, authenticated or not - too weak to count as identity evidence (the verdict here
    is ``unknown``, never a false ``ok``), but still worth recording so the gap is visible in
    the run metadata rather than silently absent."""
    if status is None:
        return "unknown", False
    if status == 401:
        return "dead", False
    if 200 <= status < 300:
        if kind != "graphql" or data_ok:
            return "ok", False
        return "unknown", bool(empty_data)
    return "unknown", False


async def _retry_dead_verdict_with_fallback(
    session: Any,
    role: str,
    verdict: str,
    limited: bool,
    fallback: tuple[str, str, str, str, str] | None,
    reserve: Callable[[str], Awaitable[bool]] | None,
    sticky_dead: dict[str, str] | None,
    timeout: float,
) -> tuple[str, bool]:
    """A ``dead`` verdict can be a FALSE dead: the identity's primary probe tests only ONE
    declared auth delivery, but the exact same credential can be declared a second time under a
    DIFFERENT delivery (bearer vs api-key) for the same role identity - a 401 under one scheme
    proves nothing about the other. Shared by piece 2's preflight and piece 3's watchdog
    re-probe, both of which reuse ``role_probe_targets``/``role_probe_target_fallbacks`` (round
    22 review, reproduced: declaration order alone decided whether a live credential aborted
    the run).

    Retries ONCE, only when ``verdict`` is already ``dead`` and a fallback target exists for
    this role - never for ``ok``/``unknown``, and never a second fallback beyond this one. Only
    an ``ok`` fallback probe overrides the verdict: a ``dead`` or inconclusive (``unknown``)
    fallback leaves the primary's concrete dead evidence standing, so a credential genuinely
    dead under every declared delivery is still correctly reported dead."""
    if verdict != "dead" or fallback is None:
        return verdict, limited
    if sticky_dead is not None and _role_already_dead(sticky_dead, role):
        return verdict, limited
    from recon_engine.preflight_probe import probe_role_verdicts

    if reserve is not None:
        try:
            granted = await reserve(role)
        except Exception:  # noqa: BLE001 - a broken reservation channel must never abort the run
            logger.exception("credential preflight: fallback probe reservation failed for role %s", role)
            return verdict, limited
        if not granted:
            return verdict, limited
        if sticky_dead is not None and _role_already_dead(sticky_dead, role):
            return verdict, limited
    fb_url, fb_kind, fb_env, fb_header, fb_prefix = fallback
    try:
        fb_status, _fb_body, fb_data_ok, fb_empty = await probe_role_verdicts(
            session, fb_url, fb_kind, fb_env, fb_header, fb_prefix, timeout=timeout,
        )
    except Exception:  # noqa: BLE001 - transport failure: leave the primary verdict as-is
        logger.exception("credential preflight: fallback probe failed for role %s", role)
        return verdict, limited
    fb_verdict, fb_limited = _classify_cred_probe(fb_status, fb_kind, fb_data_ok, fb_empty)
    if fb_verdict != "ok":
        return verdict, limited or fb_limited
    # A 2xx under the fallback's delivery is not, by itself, proof the CREDENTIAL made the
    # difference: the target may simply not check this header/scheme at all and fall through to
    # public access regardless of what is attached (round 24 review, reproduced: a route 401s a
    # revoked bearer token but returns 200 whenever Authorization is absent, so an unrelated
    # X-API-Key fallback also gets 200). A confirmatory probe to the SAME url/kind with NO
    # credential attached at all (env="") distinguishes the two: if the target is ALSO 2xx with
    # nothing attached, this delivery proves nothing and the primary's concrete dead evidence
    # must stand. This carries no secret, so it spends no probe-cap reservation.
    try:
        anon_status, _anon_body, anon_data_ok, anon_empty = await probe_role_verdicts(
            session, fb_url, fb_kind, "", fb_header, fb_prefix, timeout=timeout,
        )
    except Exception:  # noqa: BLE001 - inconclusive: do not let a flaky confirmatory probe
        # make a live credential look dead
        return "ok", limited or fb_limited
    anon_verdict, _anon_limited = _classify_cred_probe(anon_status, fb_kind, anon_data_ok, anon_empty)
    if anon_verdict == "ok":
        logger.warning(
            "credential preflight: fallback target for role %s returns 2xx with no credential "
            "attached - the fallback's \"ok\" verdict is not meaningful, keeping the primary's "
            "dead verdict", role,
        )
        return verdict, limited or fb_limited
    return "ok", limited or fb_limited


async def _preflight_credential_verdicts(
    session: Any,
    scan_config: dict[str, Any],
    graphql_path: str,
    reserve: Callable[[str], Awaitable[bool]] | None = None,
    sticky_dead: dict[str, str] | None = None,
) -> dict[str, str]:
    """One declared-endpoint identity probe per fixed-header role, in-sandbox.

    Cred-expiry piece 2: after the sandbox is up and before any agent turn.
    Reuses the exact header the agent guidance documents (role -> header spec
    computed host-side and mirrored into the probe worklist) so the probe
    cannot drift from what agents send. Values come from the sandbox env
    (``RECON_CRED_<role>``); the probe runs through the sandbox's enforced
    egress with redirects disabled. Returns ``{role: verdict}`` with verdict
    ``ok`` / ``dead`` / ``unknown``. Never raises: a probe harness failure
    records ``unknown`` roles and proceeds.

    Cred-expiry piece 3: ``reserve`` (when given) charges the durable per-run
    probe-cap reservation BEFORE issuing the probe - a phased run's later
    phases and retries all charge the same counter as attempt 1 of the SAME
    cap the watchdog's re-probes spend down, so the cap bounds the whole
    run's probe volume against the target, not just the watchdog's share of
    it. A refused reservation (cap already saturated) or a broken
    reservation channel skips the probe for that role (verdict ``unknown``,
    fail-open to not-probing, never to aborting) - identical treatment to a
    role with no declared endpoint.
    """
    from recon_engine.preflight_probe import (
        probe_role_verdicts,
        role_probe_target_fallbacks,
        role_probe_targets,
    )

    verdicts: dict[str, str] = {}
    limitation = False
    try:
        specs = role_probe_targets(scan_config, graphql_path)
    except Exception:  # noqa: BLE001
        logger.exception("credential preflight role/target derivation failed")
        specs = {}
    try:
        fallbacks = role_probe_target_fallbacks(scan_config, graphql_path)
    except Exception:  # noqa: BLE001 - a broken fallback derivation must never abort the run
        logger.exception("credential preflight fallback target derivation failed")
        fallbacks = {}
    for role, (url, kind, header_env, header_name, prefix) in specs.items():
        if not url:
            verdicts[role] = "unknown"
            continue
        # Sticky dead, checked BEFORE spending a reservation or sending a probe (matching the
        # watchdog loop's own pre-check): a role this run already confirmed dead must never
        # consume another attempt of the probe cap, nor have its credential sent again, only to
        # have the overlay below force the same "dead" verdict anyway.
        if _role_already_dead(sticky_dead, role):
            verdicts[role] = "dead"
            continue
        if reserve is not None:
            try:
                granted = await reserve(role)
            except Exception:  # noqa: BLE001 - a broken reservation channel must never abort the run
                logger.exception("credential preflight: probe reservation failed for role %s", role)
                granted = False
            if not granted:
                verdicts[role] = "unknown"
                continue
            # Re-check: the reservation await can suspend long enough for the local JWT-expiry
            # ticker (a separate task, writing straight into sticky_dead/_LAST_CRED_VERDICTS)
            # to confirm this role dead while this coroutine was waiting - never send the
            # credential after that, matching the watchdog loop's own post-reservation recheck.
            if _role_already_dead(sticky_dead, role):
                verdicts[role] = "dead"
                continue
        try:
            status, body, data_ok, empty_data = await probe_role_verdicts(
                session, url, kind, header_env, header_name, prefix,
                timeout=_CRED_PROBE_TIMEOUT_S,
            )
        except Exception:  # noqa: BLE001 - transport failure is unknown, never fatal here
            logger.exception("credential preflight probe failed for role %s", role)
            verdicts[role] = "unknown"
            continue
        verdict, limited = _classify_cred_probe(status, kind, data_ok, empty_data)
        verdict, limited = await _retry_dead_verdict_with_fallback(
            session, role, verdict, limited, fallbacks.get(role), reserve, sticky_dead, _CRED_PROBE_TIMEOUT_S,
        )
        verdicts[role] = verdict
        limitation = limitation or limited
    # Applied BEFORE run.json is written (not just at the _run_scan call site afterward), so
    # the persisted record can never show "unknown" for a role the run then aborts on for
    # being "dead" - run.json and the abort decision must never disagree about the same role.
    if sticky_dead is not None:
        _apply_sticky_dead(verdicts, sticky_dead)
    _record_cred_verdicts(verdicts, limitation)
    return verdicts


# Cred-expiry piece 3: how often the mid-run watchdog re-probes roles not yet known dead. The
# incident this plan answers (all 6 persona JWTs expired MID-run) is invisible to piece 2's
# one-shot preflight, which only catches a role already dead before the first turn. <= 0 disables
# the watchdog entirely (e.g. for a host that wants piece 2's guarantee only). No interval is
# specified by the plan; 600s spends the frozen 20-probes-per-role cap evenly across the legacy
# 4-hour (14400s) default run budget.
_CRED_WATCHDOG_INTERVAL_S = float(os.environ.get("RECON_CRED_WATCHDOG_SECONDS", "600") or 0)


def _watchdog_should_spawn(reserve: Any, interval_s: float, specs: dict) -> bool:
    """Whether cred-expiry piece 3's mid-run watchdog should spawn: the caller wired the
    reserve hook, the interval is positive (<=0 is the documented disable switch -
    asyncio.sleep(<=0) would otherwise make the loop spin continuously instead of being
    disabled), and at least one role has a declared probe target."""
    return reserve is not None and interval_s > 0 and any(url for url, *_ in specs.values())


async def _cred_watchdog_loop(
    session: Any,
    specs: dict[str, tuple[str, str, str, str, str]],
    verdicts: dict[str, str],
    reserve: Callable[[str], Awaitable[bool]],
    sink: Callable[[str, str], None] | None,
    fallbacks: dict[str, tuple[str, str, str, str, str]] | None = None,
) -> None:
    """Cred-expiry piece 3 containment: periodic mid-run re-probe for every role not yet known
    dead, reusing piece 2's exact probe mechanism (``specs``/``probe_role_verdicts``) on a timer.

    ``reserve`` is the durable per-run probe-cap reservation (engine-owned; a denied reservation -
    cap reached, or any channel failure - skips that role this round: fail-open to not-probing,
    never to aborting). ``sink`` is called on a verdict CHANGE so the engine's live heartbeat/
    timeline can surface it without waiting for the scan to end. ``verdicts`` (and the process-
    global ``_LAST_CRED_VERDICTS``) are updated in place so a late `dead` reaches the engine's
    end-of-scan coverage-worker containment (role-scoped case exclusion) even if this loop is
    cancelled (sandbox teardown) before the scan function returns. ``fallbacks`` (see
    ``_retry_dead_verdict_with_fallback``) is piece 2's same alternate-delivery target per role,
    so a mid-run re-probe can never abort a live credential just because this round happened to
    test the one declared delivery the target does not accept.
    """
    from recon_engine.preflight_probe import probe_role_verdicts

    fallbacks = fallbacks or {}
    while True:
        await asyncio.sleep(_CRED_WATCHDOG_INTERVAL_S)
        for role, (url, kind, header_env, header_name, prefix) in specs.items():
            # `dead` is sticky and wins no matter which of the two independent sources (this
            # loop's own re-probes, or activities.py's local-exp ticker writing straight into
            # _LAST_CRED_VERDICTS) got there first - checked again right before the write below
            # so a probe that was already in flight when the OTHER source went dead can never
            # resurrect the role to ok/unknown.
            if not url or verdicts.get(role) == "dead" or _role_already_dead(_LAST_CRED_VERDICTS, role):
                continue  # no declared target, or already terminal - never re-probed
            try:
                if not await reserve(role):
                    continue
            except Exception:  # noqa: BLE001 - a broken reservation channel must never abort the run
                logger.exception("cred watchdog: probe reservation failed for role %s", role)
                continue
            # The reservation call awaited; re-check dead before spending a probe on a role
            # that went dead elsewhere while this coroutine was suspended. Not required for
            # correctness (the post-probe check below still refuses the write either way) -
            # just avoids an avoidable request to an already-known-dead target.
            if verdicts.get(role) == "dead" or _role_already_dead(_LAST_CRED_VERDICTS, role):
                continue
            try:
                status, _body, data_ok, empty_data = await probe_role_verdicts(
                    session, url, kind, header_env, header_name, prefix, timeout=_CRED_PROBE_TIMEOUT_S,
                )
            except Exception:  # noqa: BLE001 - transport failure: leave the verdict as-is, never escalate
                logger.exception("cred watchdog: probe failed for role %s", role)
                continue
            new_verdict, limited = _classify_cred_probe(status, kind, data_ok, empty_data)
            if verdicts.get(role) == "dead" or _role_already_dead(_LAST_CRED_VERDICTS, role):
                continue  # went dead elsewhere while this probe was in flight
            new_verdict, limited = await _retry_dead_verdict_with_fallback(
                session, role, new_verdict, limited, fallbacks.get(role), reserve, _LAST_CRED_VERDICTS,
                _CRED_PROBE_TIMEOUT_S,
            )
            if verdicts.get(role) == "dead" or _role_already_dead(_LAST_CRED_VERDICTS, role):
                continue  # went dead elsewhere while the fallback probe was in flight
            if new_verdict == verdicts.get(role):
                # No verdict change (never re-fire the sink/log for one - "one event per
                # verdict CHANGE" - see _record_cred_health), but a NEW {"data":{}} gap
                # observed on an unchanged "unknown" must still reach run.json: skipping
                # persistence here entirely would silently drop the first (and possibly only)
                # time this limitation was actually seen for the role.
                if limited:
                    _record_cred_verdicts(verdicts, limited)
                continue
            verdicts[role] = new_verdict
            _LAST_CRED_VERDICTS[role] = new_verdict
            _record_cred_verdicts(verdicts, limited)
            if new_verdict == "dead":
                logger.warning("cred watchdog: role %s died mid-run", role)
            if sink is not None:
                try:
                    sink(role, new_verdict)
                except Exception:  # noqa: BLE001 - telemetry must never break the run
                    logger.exception("cred watchdog: sink failed for role %s", role)


def _sanitized_failure(exc: BaseException) -> BaseException:
    """A redacted stand-in for an exception leaving the engine.

    A fatal scan exception re-raised from here crosses into the Temporal
    activity and the control plane, where its message and cause chain are
    serialized to disk. A provider exception can carry a key in that text, so
    the engine never lets the raw object out: the message is scrubbed, the type
    is preserved when it can be reconstructed, and the cause/context chain is
    dropped (raise ... from None at the call site).

    Cred-expiry piece 2: the three typed credential failures keep their
    Temporal metadata (``type`` + ``non_retryable``). Today's reconstruction
    builds a fresh exception from the message only, which would downgrade a
    non-retryable ``CredentialExpiredError`` to a retryable generic failure
    and re-burn every attempt on sandbox re-creation. The credential branch
    fires ONLY for a ``temporalio.exceptions.ApplicationError`` whose ``type``
    is in the closed set below AND ``non_retryable`` is True; the rebuilt
    error carries approved fields only (type verbatim, redacted message,
    ``non_retryable=True`` — no details, no cause). Every other exception,
    including a non-credential non-retryable ApplicationError (ConfigError),
    takes the generic message-only path. Recognition is by the type field,
    never by message text.
    """
    safe = redaction.redact_text(str(exc)) or type(exc).__name__
    try:
        if (
            ApplicationError is not None
            and isinstance(exc, ApplicationError)
            and getattr(exc, "type", None) in _CRED_ERROR_TYPES
            and getattr(exc, "non_retryable", False)
        ):
            return ApplicationError(safe, type=exc.type, non_retryable=True)
    except Exception:  # noqa: BLE001 - never let sanitization itself crash
        logger.exception("sanitized_failure credential branch failed; using generic path")
    try:
        return type(exc)(safe)
    except Exception:  # noqa: BLE001 - some exceptions need more than a message
        return RuntimeError(f"{type(exc).__module__}.{type(exc).__name__}: {safe}")


async def _run_scan(
    *,
    scan_config: dict[str, Any],
    scan_id: str | None = None,
    image: str,
    local_sources: list[dict[str, Any]] | None = None,
    extra_files: list[dict[str, Any]] | Awaitable[list[dict[str, Any]] | None] | None = None,
    coordinator: AgentCoordinator | None = None,
    interactive: bool = False,
    max_turns: int = DEFAULT_MAX_TURNS,
    max_budget_usd: float | None = None,
    budget_policy: BudgetPolicy = "stop",
    model: str | None = None,
    cleanup_on_exit: bool = True,
    event_sink: StreamEventSink | None = None,
    root_instructions_override: str | None = None,
    replace_root_scan_prompt: bool = False,
    extra_system_prompt_context: dict[str, Any] | None = None,
    status_sink: StatusSink | None = None,
    mcp_connection_requests: list[McpConnectionRequest] | None = None,
    mcp_status_sink: McpStatusSink | None = None,
    root_finish_tool: Tool = finish_scan,
    report_tool: Tool = create_vulnerability_report,
    coverage_tools: bool = True,
    subagent_turn_limits: Mapping[str, int] | None = None,
    gateway_spec_path: str = "",
    gateway_spec_json: str = "",
    gateway_target_ports: tuple[int, ...] = (),
    coverage_context: Any = None,
    run_coverage_worker_on_exit: bool = False,
    cred_watchdog_reserve: Callable[[str], Awaitable[bool]] | None = None,
    cred_watchdog_sink: Callable[[str, str], None] | None = None,
) -> RunResultBase | None:
    """Shared scan body for :func:`run_strix_scan` and :func:`run_recon_scan`.

    ``root_instructions_override`` adds root scan instructions to the rendered
    root prompt without replacing the system-verified scope block.
    ``replace_root_scan_prompt=True`` makes it the root's whole prompt, followed
    by the scope, instead of adding it to the rendered scan prompt.
    ``extra_files`` entries (``{"workspace_path", "content"}``) are placed into
    the sandbox workspace at session bring-up; see
    :func:`strix.runtime.session_manager.create_or_reuse`.
    ``extra_system_prompt_context`` is merged into the root agent's scan
    context before prompt rendering. Child agents keep the standard scan prompt
    and context.
    ``budget_policy`` decides what happens when the LLM spend reaches
    ``max_budget_usd``: ``"stop"`` warns the agents as the limit approaches and
    ends the scan at it; ``"pause"`` tells the agents nothing and parks every
    agent before its next LLM call until the caller resumes the scan through
    ``coordinator.resume_budget()`` (optionally with a higher limit) or cancels
    it. ``coordinator.pause_budget()`` parks a running scan the same way.
    ``mcp_connection_requests`` supplies the run's MCP connections from any
    source: when given, the engine connects those requests; when ``None`` (the
    command-line default) it reads ``~/.strix/mcp-servers.json`` itself. Either
    way the engine does the connecting, so the caller passes inert configs plus
    metadata and never live sessions.
    ``root_finish_tool`` is the tool the root agent ends the run with.
    ``report_tool`` is the tool every agent files findings with, in place of
    ``create_vulnerability_report``.
    ``coverage_tools=False`` drops the coverage ledger tools and their prompt
    rules from every agent.
    ``subagent_turn_limits`` maps a skill name to a soft turn limit for sub-agents
    spawned with that skill (the largest applies). Agents are warned 10 turns
    before it and reminded past it, but never stopped.

    The Recon-only parameters (``gateway_spec_path`` / ``gateway_spec_json`` /
    ``gateway_target_ports`` / ``coverage_context`` / ``run_coverage_worker_on_exit`` /
    ``cred_watchdog_reserve`` / ``cred_watchdog_sink``) are documented on
    :func:`run_recon_scan`; they default to inert values so the upstream path
    (empty gateway policy, no coverage worker, no watchdog) is byte-for-byte the
    old behaviour.
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
    if resolved_model != (settings.llm.model or "").strip() and not codex.subscription_model(
        resolved_model
    ):
        configure_sdk_api_route(resolved_model, settings)
    logger.info("LLM model resolved: %s", resolved_model)
    chat_completions_tools = uses_chat_completions_tool_schema(resolved_model, settings)
    strict_tool_schemas = supports_strict_tool_schemas(resolved_model)
    if not strict_tool_schemas:
        logger.info("Sending non-strict tool schemas: %s caps strict tools", resolved_model)
    supports_images = model_supports_images(resolved_model)
    if not supports_images:
        logger.info("Leaving out image tools: %s does not accept images", resolved_model)

    if budget_policy not in ("stop", "pause"):
        raise ValueError(f"unknown budget_policy: {budget_policy!r}")
    if coordinator is None:
        coordinator = AgentCoordinator()
    coordinator.set_snapshot_path(agents_path)
    coordinator.set_budget_policy(budget_policy)
    coordinator.root_finish_tool = root_finish_tool.name

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
                budget_policy=budget_policy,
            )
            # Under the pause policy the hooks re-park at the first call if the
            # spend is still at the limit, so a restored pause flag would only
            # hold agents back after the limit was raised.
            await coordinator.reset_budget_stops(
                budget_stopped=budget_stopped,
                reserve_stopped=reserve_stopped,
                budget_paused=(
                    interactive and budget_policy != "pause" and coordinator.budget_paused
                ),
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
        # Brokered credentials injected into the sandbox env, not the prompt (#34):
        # {RECON_CRED_<role>: password} lands in the container Environment so the
        # agent (and the header-auth authz probes) read the secret from env.
        extra_env=scan_config.get("sandbox_env") or {},
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
    mcp_registry: McpRegistry | None = None
    scan_cancelled = False
    # Declared here (not inside the try below) so the finally's cancellation check is always
    # bound, even when the preflight raises before the watchdog task is ever created.
    _cred_watchdog_task: asyncio.Task[None] | None = None

    try:
        # Cred-expiry piece 2: preflight credential verdicts BEFORE any agent turn. One
        # declared-endpoint probe per fixed-header role through the sandbox's enforced
        # egress; a `dead` role fails the scan non-retryably before any budget is spent.
        # Inside the protected try so a raise here still reaches the finally below (spill
        # writer reset, descendant cancel, session close) instead of leaking the sandbox
        # this function already brought up.
        cred_verdicts: dict[str, str] = {}
        _gq_path = ""
        if coverage_context is not None:
            _ref = getattr(coverage_context, "ref", None)
            if isinstance(_ref, dict):
                from recon_engine.preflight_probe import normalize_declared_graphql

                _gq_path = normalize_declared_graphql(str(_ref.get("graphql_endpoint") or ""))
        try:
            cred_verdicts = await _preflight_credential_verdicts(
                sandbox_session, scan_config, _gq_path, reserve=cred_watchdog_reserve,
                sticky_dead=_LAST_CRED_VERDICTS,
            )
        except Exception:  # noqa: BLE001 - a broken probe harness must not kill a healthy run
            logger.exception("credential preflight failed (non-fatal); proceeding")
            cred_verdicts = {}
        # Belt-and-suspenders for the exception-fallback path above (the call itself raised, so
        # the function's own internal overlay never ran) - the normal path already applies this
        # overlay before run.json is written; this is a harmless no-op repeat there.
        _apply_sticky_dead(cred_verdicts, _LAST_CRED_VERDICTS)
        # Published to the process-global map, and through the live health sink, HERE - before
        # the dead-role check below can raise. The engine's post-scan fold (which also turns this
        # into a cred_health timeline event) only runs after run_recon_scan RETURNS, which a
        # preflight-dead abort never reaches. Without this, the single most common failure this
        # plan answers (dead before any turn) would be the one case whose cred_health event never
        # appears on the timeline.
        _LAST_CRED_VERDICTS.update(cred_verdicts)
        if cred_watchdog_sink is not None:
            for _role, _verdict in cred_verdicts.items():
                try:
                    cred_watchdog_sink(_role, _verdict)
                except Exception:  # noqa: BLE001 - telemetry must never break the run
                    logger.exception("cred preflight: sink failed for role %s", _role)
        # Cred-expiry piece 3: role/target derivation for the watchdog spawn below. Recomputed
        # (role_probe_targets is pure and cheap - no I/O) rather than threaded out of
        # _preflight_credential_verdicts, which keeps that function's signature unchanged for
        # non-watchdog callers.
        _preflight_specs: dict[str, tuple[str, str, str, str, str]] = {}
        _preflight_fallbacks: dict[str, tuple[str, str, str, str, str]] = {}
        if cred_watchdog_reserve is not None and cred_verdicts:
            try:
                from recon_engine.preflight_probe import (
                    role_probe_target_fallbacks,
                    role_probe_targets,
                )

                _preflight_specs = role_probe_targets(scan_config, _gq_path)
                _preflight_fallbacks = role_probe_target_fallbacks(scan_config, _gq_path)
            except Exception:  # noqa: BLE001 - a broken probe harness must not kill a healthy run
                logger.exception("cred watchdog: role/target derivation failed")
        if "dead" in cred_verdicts.values():
            _dead = sorted(r for r, v in cred_verdicts.items() if v == "dead")
            report("credential preflight: dead role(s) " + ",".join(_dead))
            scan_cancelled = True  # before raising: suppresses coverage-on-exit
            if ApplicationError is None:  # pragma: no cover - non-Temporal host
                raise RuntimeError("credentials expired (" + ", ".join(_dead) + ")")
            raise ApplicationError(
                "credentials expired (" + ", ".join(_dead) + ")",
                type="CredentialExpiredError",
                non_retryable=True,
            )
        # Cred-expiry piece 3: periodic mid-run re-probe for every role preflight did not
        # already find dead (the incident: a credential dying AFTER preflight, not before
        # it). A plain run_strix_scan call (cred_watchdog_reserve=None) never starts it either way.
        if _watchdog_should_spawn(cred_watchdog_reserve, _CRED_WATCHDOG_INTERVAL_S, _preflight_specs):
            _cred_watchdog_task = asyncio.create_task(_cred_watchdog_loop(
                sandbox_session, _preflight_specs, cred_verdicts, cred_watchdog_reserve, cred_watchdog_sink,
                fallbacks=_preflight_fallbacks,
            ))

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
            parallel_tool_calls=settings.llm.parallel_tool_calls,
            request_timeout=settings.llm.timeout,
            prompt_cache=settings.llm.prompt_cache,
            extra_headers=settings.llm.extra_headers,
            extra_body=settings.llm.extra_body,
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
            budget_policy=budget_policy,
            record_tool_timings=settings.telemetry.run_record_timings,
        )
        coordinator.set_budget_limit_setter(hooks.set_max_budget_usd)
        if interactive and budget_policy != "pause":
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
                for request in mcp_requests:
                    mcp_registry.register(request)
                _record_mcp_connections(mcp_registry.names())
                report(
                    f"MCP: configured {len(mcp_registry)} connection(s); "
                    "connecting and listing tools"
                )
                scope_context["mcp_available"] = True
                scope_context["mcp_connections"] = _mcp_prompt_roster(mcp_registry)

                def _emit_mcp_status() -> None:
                    scope_context["mcp_connections"] = _mcp_prompt_roster(mcp_registry)
                    roster = _mcp_roster_payload(mcp_registry)
                    _persist_mcp_status(roster)
                    if mcp_status_sink is not None:
                        try:
                            mcp_status_sink(roster)
                        except Exception:
                            logger.exception("MCP status sink failed")

                mcp_registry.set_status_sink(_emit_mcp_status)
                _emit_mcp_status()
                warmup_task = mcp_registry.start_warmup(max_concurrency=6)
                await asyncio.wait(
                    {warmup_task},
                    timeout=_MCP_PROMPT_WARMUP_TIMEOUT_SECONDS,
                )
        except Exception:
            logger.exception("Failed to configure user MCP servers; continuing without them")

        root_context = _merge_root_prompt_context(scope_context, extra_system_prompt_context)
        root_instructions = _compose_root_instructions_override(
            root_instructions_override,
            skills=skills,
            scan_mode=scan_mode,
            is_whitebox=is_whitebox,
            is_diff_scoped=is_diff_scoped,
            interactive=interactive,
            parallel_tool_calls=settings.llm.parallel_tool_calls,
            system_prompt_context=root_context,
            supports_images=supports_images,
            report_tool=report_tool.name,
            coverage_tools=coverage_tools,
            replace_scan_prompt=replace_root_scan_prompt,
        )

        root_agent = build_strix_agent(
            name="Root Agent",
            skills=skills,
            is_root=True,
            scan_mode=scan_mode,
            is_whitebox=is_whitebox,
            is_diff_scoped=is_diff_scoped,
            interactive=interactive,
            parallel_tool_calls=settings.llm.parallel_tool_calls,
            chat_completions_tools=chat_completions_tools,
            strict_tool_schemas=strict_tool_schemas,
            system_prompt_context=root_context,
            instructions_override=root_instructions,
            supports_images=supports_images,
            finish_tool=root_finish_tool,
            report_tool=report_tool,
            coverage_tools=coverage_tools,
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
            parallel_tool_calls=settings.llm.parallel_tool_calls,
            chat_completions_tools=chat_completions_tools,
            strict_tool_schemas=strict_tool_schemas,
            system_prompt_context=scope_context,
            supports_images=supports_images,
            report_tool=report_tool,
            coverage_tools=coverage_tools,
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
            "supports_images": supports_images,
            "coverage_tools": coverage_tools,
            SUBAGENT_TURN_LIMITS_KEY: dict(subagent_turn_limits or {}),
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
            # Lifecycle tools mark the root completed.
            async with coordinator._lock:
                root_completed = coordinator.statuses.get(root_id) == "completed"
            if not root_completed:
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
    except BaseException as exc:
        logger.exception("Strix scan %s failed", scan_id)
        if root_id is not None:
            with contextlib.suppress(Exception):
                await coordinator.set_status(root_id, "failed")
        # Scrub before the exception leaves the engine for the Temporal activity
        # and control plane; drop the cause chain so no raw text rides along.
        raise _sanitized_failure(exc) from None
    finally:
        configure_spill_writer(None)
        # Cred-expiry piece 3: stop the watchdog before anything else touches the sandbox session
        # (the coverage worker below execs through it too; the two must never run concurrently).
        if _cred_watchdog_task is not None:
            _cred_watchdog_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await _cred_watchdog_task
        # Settle descendants before closing sessions: on a clean finish a child
        # can still be mid-turn, and closing its session underneath it crashes it.
        if root_id is not None:
            with contextlib.suppress(Exception):
                await coordinator.cancel_descendants(root_id)
        for s in sessions_to_close:
            with contextlib.suppress(Exception):
                s.close()
        if mcp_registry is not None:
            with contextlib.suppress(Exception):
                await mcp_registry.close()
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
                except TimeoutError:
                    logger.exception(
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
    except Exception:  # noqa: BLE001 - any import failure degrades to a plain scan
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
    extra_files: list[dict[str, Any]] | Awaitable[list[dict[str, Any]] | None] | None = None,
    coordinator: AgentCoordinator | None = None,
    interactive: bool = False,
    max_turns: int = DEFAULT_MAX_TURNS,
    max_budget_usd: float | None = None,
    budget_policy: BudgetPolicy = "stop",
    model: str | None = None,
    cleanup_on_exit: bool = True,
    event_sink: StreamEventSink | None = None,
    root_instructions_override: str | None = None,
    replace_root_scan_prompt: bool = False,
    extra_system_prompt_context: dict[str, Any] | None = None,
    status_sink: StatusSink | None = None,
    mcp_connection_requests: list[McpConnectionRequest] | None = None,
    mcp_status_sink: McpStatusSink | None = None,
    root_finish_tool: Tool = finish_scan,
    report_tool: Tool = create_vulnerability_report,
    coverage_tools: bool = True,
    subagent_turn_limits: Mapping[str, int] | None = None,
) -> RunResultBase | None:
    """Run or resume one Strix scan against a sandbox.

    Parameters are documented on :func:`_run_scan`.
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
        budget_policy=budget_policy,
        model=model,
        cleanup_on_exit=cleanup_on_exit,
        event_sink=event_sink,
        root_instructions_override=root_instructions_override,
        replace_root_scan_prompt=replace_root_scan_prompt,
        extra_system_prompt_context=extra_system_prompt_context,
        status_sink=status_sink,
        mcp_connection_requests=mcp_connection_requests,
        mcp_status_sink=mcp_status_sink,
        root_finish_tool=root_finish_tool,
        report_tool=report_tool,
        coverage_tools=coverage_tools,
        subagent_turn_limits=subagent_turn_limits,
    )


async def run_recon_scan(
    *,
    scan_config: dict[str, Any],
    scan_id: str | None = None,
    image: str,
    local_sources: list[dict[str, Any]] | None = None,
    extra_files: list[dict[str, Any]] | Awaitable[list[dict[str, Any]] | None] | None = None,
    coordinator: AgentCoordinator | None = None,
    interactive: bool = False,
    max_turns: int = DEFAULT_MAX_TURNS,
    max_budget_usd: float | None = None,
    budget_policy: BudgetPolicy = "stop",
    model: str | None = None,
    cleanup_on_exit: bool = True,
    event_sink: StreamEventSink | None = None,
    root_instructions_override: str | None = None,
    replace_root_scan_prompt: bool = False,
    extra_system_prompt_context: dict[str, Any] | None = None,
    status_sink: StatusSink | None = None,
    mcp_connection_requests: list[McpConnectionRequest] | None = None,
    mcp_status_sink: McpStatusSink | None = None,
    root_finish_tool: Tool = finish_scan,
    report_tool: Tool = create_vulnerability_report,
    coverage_tools: bool = True,
    subagent_turn_limits: Mapping[str, int] | None = None,
    gateway_spec_path: str = "",
    gateway_spec_json: str = "",
    gateway_target_ports: tuple[int, ...] = (),
    coverage_context: Any = None,
    run_coverage_worker_on_exit: bool = False,
    cred_watchdog_reserve: Callable[[str], Awaitable[bool]] | None = None,
    cred_watchdog_sink: Callable[[str, str], None] | None = None,
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

    ``cred_watchdog_reserve``/``cred_watchdog_sink`` (cred-expiry piece 3) opt
    into the mid-run credential watchdog: a periodic re-probe, on top of
    piece 2's one-shot preflight, that catches a role dying AFTER the first
    turn. ``cred_watchdog_reserve(role)`` charges the engine's durable per-run
    probe-cap reservation and returns whether this round's probe is allowed;
    ``cred_watchdog_sink(role, verdict)`` is called on a verdict CHANGE so the
    engine can surface it live. Either left ``None`` disables the watchdog
    (preflight still runs); the two are independent of
    ``run_coverage_worker_on_exit``.
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
        budget_policy=budget_policy,
        model=model,
        cleanup_on_exit=cleanup_on_exit,
        event_sink=event_sink,
        root_instructions_override=root_instructions_override,
        replace_root_scan_prompt=replace_root_scan_prompt,
        extra_system_prompt_context=extra_system_prompt_context,
        status_sink=status_sink,
        mcp_connection_requests=mcp_connection_requests,
        mcp_status_sink=mcp_status_sink,
        root_finish_tool=root_finish_tool,
        report_tool=report_tool,
        coverage_tools=coverage_tools,
        subagent_turn_limits=subagent_turn_limits,
        gateway_spec_path=gateway_spec_path,
        gateway_spec_json=gateway_spec_json,
        gateway_target_ports=gateway_target_ports,
        coverage_context=coverage_context,
        run_coverage_worker_on_exit=run_coverage_worker_on_exit,
        cred_watchdog_reserve=cred_watchdog_reserve,
        cred_watchdog_sink=cred_watchdog_sink,
    )
