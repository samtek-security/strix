# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""Thin ledger-native execution tools — broker-backed, reconciliation-cache only.

These four ``@function_tool`` wrappers expose the accepted
:class:`recon_engine.execution_client.AgentExecutionClient` to the Strix agent
without inventing a parallel campaign store, scheduler, or task hierarchy. The
broker is the single source of truth for case state, leases, and verdict
receipts. The only local state is a reconciliation cache
(``_lease_cache``) that lets an agent detect drift between its own view of the
leases it holds and the broker's view (e.g. after a crash/restart).

Tools
-----
- ``list_execution_cases`` — list assigned/eligible cases for an exact revision.
- ``reserve_execution_cases`` — reserve a bounded set of cases under one lease.
- ``record_execution_verdict`` — finalize one case with a verdict/finding receipt.
- ``reconcile_execution_leases`` — read-only diff of the local cache vs broker.

Binding contracts honoured
--------------------------
- ``reserve`` threads ``(revision_id, revision_num, case_ids, lease_id,
  objective, ttl_seconds, idempotency_key)`` to the client; ``owner`` comes
  exclusively from the client constructor (agent identity), never from model
  arguments (principal-confusion defence).
- Finalization accepts ONLY ``outcome="verdict"`` with ``verdict`` in
  ``("passed", "finding")``. ``not_applicable`` is a host-owned pre-dispatch
  applicability decision and is deliberately NOT exposed here.
- Artifact IDs are host-owned and revalidated by the client (engagement scope +
  integrity); this module passes them through unchanged.
- The local lease tracker is a reconciliation cache ONLY — never a campaign
  store, scheduler, event store, registry, or task hierarchy.
- An originating agent never validates its own finding: these tools only RECORD
  the agent's verdict; verification is a control-plane concern.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import uuid
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)

# ── local lease cache (reconciliation ONLY) ───────────────────────────────────
# Never the source of truth. The broker is authoritative. This cache lets an
# agent detect when its view of its own leases has drifted from the broker
# (e.g. after a crash/restart). It is NOT a campaign store, scheduler, event
# store, or registry: it holds only {lease_id -> {case_id, generation,
# revision_id, revision_num, acquired_at}} for leases THIS agent acquired, and
# it is reconciled against the broker by ``reconcile_execution_leases``.
_lease_cache: dict[str, dict[str, Any]] = {}
_lease_cache_lock = threading.RLock()
_leases_path: Path | None = None


def hydrate_leases_from_disk(state_dir: Path) -> None:
    """Load the reconciliation cache from ``{state_dir}/execution_leases.json``.

    Mirrors the durable hydration pattern used by todos/notes/probes/queue so a
    resumed agent recovers its cached view of its own leases. The broker remains
    authoritative; this only seeds the cache so ``reconcile_execution_leases``
    can detect drift without a first round-trip.
    """
    global _leases_path  # noqa: PLW0603
    _leases_path = state_dir / "execution_leases.json"
    with _lease_cache_lock:
        _lease_cache.clear()
        if not _leases_path.exists():
            return
        try:
            data = json.loads(_leases_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.exception(
                "execution_leases.json at %s is unreadable; starting with empty cache",
                _leases_path,
            )
            return
        if not isinstance(data, dict):
            return
        loaded = 0
        for lid, entry in data.items():
            if isinstance(lid, str) and isinstance(entry, dict):
                _lease_cache[lid] = entry
                loaded += 1
        logger.info("execution leases hydrated (%d)", loaded)


def _persist_leases(state_dir: Path | None = None) -> None:
    """Atomically mirror ``_lease_cache`` to ``execution_leases.json``.

    Reconciliation-cache-only persistence: a stale or lost file is benign — the
    broker is authoritative and ``reconcile_execution_leases`` will rebuild the
    agent's understanding from the broker on demand.
    """
    path = _leases_path
    if path is None and state_dir is not None:
        path = state_dir / "execution_leases.json"
    if path is None:
        return
    try:
        with _lease_cache_lock:
            payload = json.dumps(_lease_cache, ensure_ascii=False, default=str)
            path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=str(path.parent),
                prefix=f".{path.name}.",
                suffix=".tmp",
                delete=False,
            ) as tmp:
                tmp.write(payload)
                tmp_path = Path(tmp.name)
            tmp_path.replace(path)
    except Exception:
        logger.exception("execution leases persist to %s failed", path)


# ── broker connection ─────────────────────────────────────────────────────────
def _ensure_engine_on_path() -> None:
    """Best-effort add the ``engine/`` dir to sys.path so ``recon_engine`` imports.

    The Strix venv normally has it on sys.path already; this is a safety net for
    hosts where the tool module is imported from an unusual CWD.
    """
    import sys

    here = Path(__file__).resolve()
    # engine/ is the ancestor above third_party/strix/reconcore/tools/ledger/.
    engine_dir = here.parents[5]
    if engine_dir.name == "engine" and str(engine_dir) not in sys.path:
        sys.path.insert(0, str(engine_dir))


def _ctx_dict(ctx: RunContextWrapper) -> dict[str, Any]:
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    return inner


def _broker_config(inner: dict[str, Any]) -> dict[str, str]:
    """Resolve broker connection info from the run context, then env vars.

    Precedence: run-context dict keys (set by ``runner.py`` from ``scan_config``)
    > environment variables. This lets a host inject per-engagement broker
    credentials into the sandbox env without leaking them to the prompt, while
    still allowing an env-only fallback for local/dev runs.
    """
    return {
        "engagement_id": str(inner.get("engagement_id") or os.environ.get("RECON_ENGAGEMENT_ID", "")),
        "token": str(inner.get("broker_token") or os.environ.get("RECON_BROKER_TOKEN", "")),
        "base_url": str(inner.get("broker_url") or os.environ.get("RECON_BROKER_URL", "")),
        "owner": str(inner.get("agent_id") or "agent"),
        "revision_id": str(inner.get("revision_id") or os.environ.get("RECON_REVISION_ID", "")),
        "revision_num": str(inner.get("revision_num") or os.environ.get("RECON_REVISION_NUM", "")),
    }


def _get_agent_client(ctx: RunContextWrapper) -> Any:
    """Build an :class:`AgentExecutionClient` from the run context + env.

    Returns ``None`` when the broker is not configured (no engagement_id or
    token), so tools can fail closed with a clear ``success: False`` result
    instead of raising. ``recon_engine.execution_client`` is imported lazily so
    this module does not hard-depend on it at import time (the Strix venv may
    not have ``engine/`` on sys.path at collection time).
    """
    inner = _ctx_dict(ctx)
    cfg = _broker_config(inner)
    engagement_id = cfg["engagement_id"]
    token = cfg["token"]
    if not engagement_id or not token:
        return None
    try:
        _ensure_engine_on_path()
        from recon_engine.execution_client import AgentExecutionClient  # noqa: PLC0415

        return AgentExecutionClient(
            engagement_id,
            token,
            owner=cfg["owner"],
            base_url=cfg["base_url"] or None,
        )
    except Exception:
        logger.exception("failed to build AgentExecutionClient")
        return None


# Lazily-resolved broker exception classes. Imported on first use so the module
# stays importable without ``recon_engine`` on sys.path. Falls back to an empty
# tuple (and a broad ``Exception`` catch) if the import fails — in which case no
# broker call can succeed anyway (client construction would also fail).
_EXC_CACHE: tuple[type[Exception], ...] | None = None


def _exc_classes() -> tuple[type[Exception], ...]:
    global _EXC_CACHE  # noqa: PLW0603
    if _EXC_CACHE is None:
        try:
            _ensure_engine_on_path()
            from recon_engine.execution_client import (  # noqa: PLC0415
                ExecutionBounds,
                ExecutionConflict,
                ExecutionStale,
                ExecutionUnavailable,
            )

            _EXC_CACHE = (
                ExecutionUnavailable,
                ExecutionConflict,
                ExecutionStale,
                ExecutionBounds,
            )
        except Exception:
            _EXC_CACHE = ()
    return _EXC_CACHE


def _exc_match() -> tuple[type[Exception], ...]:
    """Tuple for ``except`` matching; falls back to ``Exception`` if unknown."""
    classes = _exc_classes()
    return classes if classes else (Exception,)


def _ok(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, default=str)


def _fail(error: str, **extra: Any) -> str:
    return json.dumps({"success": False, "error": error, **extra}, ensure_ascii=False, default=str)


_VALID_OUTCOMES = ("verdict",)
_VALID_VERDICTS = ("passed", "finding")


# ── Tool 1: list_execution_cases ──────────────────────────────────────────────
@function_tool(timeout=30)
async def list_execution_cases(
    ctx: RunContextWrapper,
    revision_id: str,
    revision_num: int,
    limit: int = 500,
    profile: str | None = None,
    role: str | None = None,
    eligible: bool | None = None,
) -> str:
    """List execution cases for an exact, immutable ledger revision.

    Every execution operation pins to a ``(revision_id, revision_num)`` snapshot
    so the agent never acts against a moving ledger. Use this to discover which
    cases are assigned to / eligible for this agent before reserving them.

    Args:
        revision_id: the immutable revision ID (from the engagement spec).
        revision_num: the revision number (monotonic integer >= 1).
        limit: page size (1..500). Use the returned ``next_cursor`` to page.
        profile: optional profile filter (e.g. ``"authn"``).
        role: optional role filter (e.g. ``"Administrator"``).
        eligible: when True, list only eligible (un-leased, un-finalized) cases;
            when False, only ineligible; None = no filter.
    """
    client = _get_agent_client(ctx)
    if client is None:
        return _fail("broker not configured (no engagement_id/token)")
    try:
        data = client.list_cases(
            revision_id,
            revision_num,
            limit=limit,
            profile=profile,
            role=role,
            eligible=eligible,
        )
    except _exc_match() as exc:
        code = getattr(exc, "code", "") or ""
        return _fail(str(exc), code=code) if code else _fail(str(exc))
    cases = [
        {
            "case_id": c.get("case_id"),
            "profile": c.get("profile"),
            "role": c.get("role"),
            "status": c.get("status"),
            "eligible": c.get("eligible"),
            "dispatched": c.get("dispatched"),
            "generation": c.get("generation"),
        }
        for c in data.get("cases", [])
        if isinstance(c, dict)
    ]
    return _ok({
        "success": True,
        "revision_id": revision_id,
        "revision_num": revision_num,
        "cases": cases,
        "next_cursor": data.get("next_cursor", ""),
        "count": len(cases),
    })


# ── Tool 2: reserve_execution_cases ───────────────────────────────────────────
@function_tool(timeout=30)
async def reserve_execution_cases(
    ctx: RunContextWrapper,
    revision_id: str,
    revision_num: int,
    case_ids: list[str],
    objective: str,
    ttl_seconds: int = 120,
) -> str:
    """Reserve a bounded set of cases under ONE coordinator lease.

    All ``case_ids`` are reserved atomically under a single ``lease_id``; the
    broker returns a per-case ``generation`` that MUST be threaded into the
    matching ``record_execution_verdict`` call. On conflict (another agent
    already leased one of the cases, or the revision is stale), re-list and
    retry with a fresh ``lease_id``.

    Args:
        revision_id: the immutable revision ID.
        revision_num: the revision number.
        case_ids: 1..100 case IDs to reserve under one lease.
        objective: short human-readable purpose (<=512 chars).
        ttl_seconds: lease lifetime (1..900). Default 120s.
    """
    if not isinstance(case_ids, list) or not case_ids:
        return _fail("case_ids must be a non-empty list")
    client = _get_agent_client(ctx)
    if client is None:
        return _fail("broker not configured (no engagement_id/token)")
    lease_id = uuid.uuid4().hex
    idempotency_key = uuid.uuid4().hex
    try:
        data = client.reserve(
            revision_id,
            revision_num,
            case_ids,
            lease_id=lease_id,
            objective=objective,
            ttl_seconds=ttl_seconds,
            idempotency_key=idempotency_key,
        )
    except _exc_match() as exc:
        code = getattr(exc, "code", "") or ""
        return _fail(str(exc), code=code, lease_id=lease_id)
    leases: list[dict[str, Any]] = []
    acquired_at = ""
    with _lease_cache_lock:
        for entry in data.get("cases", []):
            if not isinstance(entry, dict):
                continue
            case = entry.get("case") or {}
            lease = entry.get("lease") or {}
            cid = case.get("case_id")
            gen = lease.get("generation")
            acquired_at = lease.get("acquired_at", "") or acquired_at
            if cid is None or gen is None:
                continue
            _lease_cache[lease_id] = {
                "case_id": cid,
                "generation": gen,
                "revision_id": revision_id,
                "revision_num": revision_num,
                "acquired_at": acquired_at,
            }
            leases.append({"lease_id": lease_id, "case_id": cid, "generation": gen})
    _persist_leases()
    return _ok({"success": True, "lease_id": lease_id, "leases": leases})


# ── Tool 3: record_execution_verdict ──────────────────────────────────────────
@function_tool(timeout=30)
async def record_execution_verdict(
    ctx: RunContextWrapper,
    case_id: str,
    lease_id: str,
    generation: int,
    outcome: str,
    verdict: str,
    digest: str,
    revision_id: str,
    revision_num: int,
    artifact_ids: list[str] | None = None,
    block_code: str | None = None,
    receipt_id: str | None = None,
    idempotency_key: str | None = None,
) -> str:
    """Finalize ONE case with an execution verdict receipt.

    Only ``outcome="verdict"`` with ``verdict`` in ``("passed", "finding")`` is
    accepted. ``not_applicable`` is a HOST-owned pre-dispatch applicability
    decision and is intentionally not exposed to the agent. Artifact IDs are
    host-owned and revalidated by the broker for engagement scope + integrity;
    pass them through unchanged from ``put_artifact`` responses.

    On a lost response (timeout after the broker accepted the finalize), retry
    with the SAME ``receipt_id`` and ``idempotency_key`` you used originally:
    the broker will return ``duplicate=True`` for the already-recorded receipt.

    Args:
        case_id: the case to finalize.
        lease_id: the lease acquired by ``reserve_execution_cases``.
        generation: the per-case generation returned with that lease.
        outcome: must be ``"verdict"``.
        verdict: ``"passed"`` (case satisfied) or ``"finding"`` (vuln found).
        digest: stable digest of the evidence/claim (<=128 chars).
        revision_id: the immutable revision ID.
        revision_num: the revision number.
        artifact_ids: optional list of host-owned artifact IDs (<=16).
        block_code: optional block/disposition code.
        receipt_id: retry-only; the receipt ID from a prior attempt.
        idempotency_key: retry-only; the idempotency key from a prior attempt.
    """
    if outcome not in _VALID_OUTCOMES:
        return _fail(
            f"outcome must be one of {list(_VALID_OUTCOMES)}; "
            "'not_applicable' is host-owned and not accepted here"
        )
    if verdict not in _VALID_VERDICTS:
        return _fail(f"verdict must be one of {list(_VALID_VERDICTS)}, got {verdict!r}")
    client = _get_agent_client(ctx)
    if client is None:
        return _fail("broker not configured (no engagement_id/token)")
    rid = receipt_id or uuid.uuid4().hex
    ikey = idempotency_key or uuid.uuid4().hex
    try:
        data = client.finalize(
            revision_id,
            revision_num,
            case_id,
            lease_id=lease_id,
            receipt_id=rid,
            idempotency_key=ikey,
            generation=generation,
            digest=digest,
            outcome=outcome,
            verdict=verdict,
            block_code=block_code,
            artifact_ids=artifact_ids,
        )
    except _exc_match() as exc:
        code = getattr(exc, "code", "") or ""
        return _fail(str(exc), code=code)
    with _lease_cache_lock:
        _lease_cache.pop(lease_id, None)
    _persist_leases()
    receipt = data.get("receipt") or {}
    return _ok({
        "success": True,
        "receipt_id": receipt.get("id", rid),
        "duplicate": bool(data.get("duplicate", False)),
        "generation": receipt.get("generation", generation),
        "outcome": receipt.get("outcome", outcome),
    })


# ── Tool 4: reconcile_execution_leases ────────────────────────────────────────
@function_tool(timeout=30)
async def reconcile_execution_leases(
    ctx: RunContextWrapper,
    revision_id: str,
    revision_num: int,
) -> str:
    """Read-only reconciliation of the local lease cache against the broker.

    For each lease the agent believes it holds (from ``_lease_cache``), ask the
    broker for the current case state and classify it:

    - ``active``: the broker agrees this agent still holds the lease at the
      cached generation (case ``status == "leased"``, lease owner is this agent,
      lease id + generation match).
    - ``expired_or_terminal``: the case has moved to ``terminal`` (a verdict was
      recorded) or the lease has expired (case is back to ``eligible`` /
      ``ineligible`` with no lease).
    - ``drift``: the broker's state contradicts the cache in a way the agent
      did not cause locally — e.g. the case is leased by ANOTHER owner, or the
      generation differs, or the lease id differs.

    This tool is READ-ONLY. It never mutates broker state and never creates a
    parallel store. Use it after a crash/restart, or anytime the agent suspects
    its cached view is stale, to decide which leases to re-reserve or abandon.
    """
    client = _get_agent_client(ctx)
    if client is None:
        return _fail("broker not configured (no engagement_id/token)")
    inner = _ctx_dict(ctx)
    owner = str(inner.get("agent_id") or "agent")
    with _lease_cache_lock:
        cached = {lid: dict(v) for lid, v in _lease_cache.items()}

    # Collect every case_id the agent thinks it has a lease on, de-duplicated.
    wanted_case_ids = {entry["case_id"] for entry in cached.values() if entry.get("case_id")}

    # Page through the broker's case list for this revision and index by case_id.
    # The cache is bounded by the number of leases one agent can hold, so this
    # scan is bounded; still cap the page count to avoid an unbounded loop.
    broker_by_case: dict[str, dict[str, Any]] = {}
    cursor: str | None = None
    for _ in range(64):
        page = client.list_cases(
            revision_id,
            revision_num,
            limit=500,
            cursor=cursor,
        )
        for c in page.get("cases", []):
            if isinstance(c, dict) and c.get("case_id") in wanted_case_ids:
                broker_by_case[c["case_id"]] = c
        cursor = page.get("next_cursor") or ""
        if not cursor:
            break

    active: list[dict[str, Any]] = []
    expired_or_terminal: list[dict[str, Any]] = []
    drift: list[dict[str, Any]] = []

    for lease_id, entry in cached.items():
        case_id = entry.get("case_id")
        gen = entry.get("generation")
        rec: dict[str, Any] = {
            "lease_id": lease_id,
            "case_id": case_id,
            "cached_generation": gen,
        }
        case = broker_by_case.get(case_id)
        if case is None:
            # The broker no longer returns this case at all for this revision —
            # treat as drift (revision rolled or case purged); never mutate.
            drift.append({**rec, "reason": "case_not_listed_by_broker"})
            continue
        status = case.get("status")
        lease = case.get("lease")
        if status == "leased" and isinstance(lease, dict):
            lease_owner = lease.get("owner")
            lease_id_b = lease.get("id")
            gen_b = lease.get("generation")
            if lease_owner == owner and lease_id_b == lease_id and gen_b == gen:
                active.append({**rec, "broker_status": status, "broker_generation": gen_b})
            elif lease_owner != owner:
                drift.append({
                    **rec,
                    "reason": "leased_by_other_owner",
                    "broker_owner": lease_owner,
                    "broker_status": status,
                })
            elif lease_id_b != lease_id:
                drift.append({
                    **rec,
                    "reason": "lease_id_mismatch",
                    "broker_lease_id": lease_id_b,
                    "broker_status": status,
                })
            else:  # generation differs
                drift.append({
                    **rec,
                    "reason": "generation_mismatch",
                    "broker_generation": gen_b,
                    "broker_status": status,
                })
        elif status == "terminal":
            expired_or_terminal.append({**rec, "broker_status": status})
        else:
            # eligible/ineligible with no lease -> the lease expired or was
            # finalized and the case returned to the pool.
            expired_or_terminal.append({
                **rec,
                "broker_status": status,
                "reason": "lease_no_longer_held",
            })

    return _ok({
        "success": True,
        "reconciled": True,
        "active": active,
        "expired_or_terminal": expired_or_terminal,
        "drift": drift,
        "cached_count": len(cached),
    })
