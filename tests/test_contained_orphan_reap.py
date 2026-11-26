"""A crashed worker's leftover sandbox boundary is reaped and rebuilt, never reused or mistaken."""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import os
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import docker
import pytest

from strix.core import runner
from strix.runtime import backends, gateway_staging, host_isolation, session_manager
from strix.runtime.backends import _BACKENDS, register_backend
from strix.runtime.docker_client import remove_volume_if_created
from tests.test_runner_teardown import _wire_runner


SCAN = "scan-1"
ENG = "eng-1"
OWNER = {
    "recon.sandbox": "true",
    "recon.scan_id": SCAN,
    "recon.engagement_id": ENG,
    "recon.owner": "contained-egress",
}
NET = f"recon-net-{SCAN}"
CA = f"recon-ca-{SCAN}"
GW = f"recon-egress-{SCAN}"


def _created(age_sec: float) -> str:
    """Docker's nanosecond RFC 3339 creation time, `age_sec` ago."""
    return (datetime.now(UTC) - timedelta(seconds=age_sec)).strftime("%Y-%m-%dT%H:%M:%S.123456789Z")


def _net(name: str = NET, labels: dict[str, str] | None = None) -> MagicMock:
    net = MagicMock()
    net.name = name
    net.attrs = {
        "Name": name,
        "Created": _created(86400),
        "Driver": "bridge",
        "Internal": True,
        "Labels": {**OWNER, "recon.role": "agent-gateway-network"} if labels is None else labels,
        "Containers": {},
        "Options": host_isolation.isolated_options(),
        "IPAM": {"Config": [{"Subnet": "10.250.97.0/29"}]},
    }
    return net


def _volume(labels: dict[str, str] | None = None) -> MagicMock:
    vol = MagicMock()
    vol.attrs = {
        "CreatedAt": _created(86400),
        "Labels": {**OWNER, "recon.role": "gateway-ca-volume"} if labels is None else labels,
    }
    return vol


def _container(name: str, labels: dict[str, str]) -> MagicMock:
    c = MagicMock()
    c.name = name
    c.id = "id-" + name
    c.labels = labels
    return c


def _run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
    *,
    nets: list[MagicMock] | None = None,
    volume: MagicMock | None = None,
    containers: list[MagicMock] | None = None,
    engagement_id: str = ENG,
    create_error: Exception | None = None,
) -> tuple[MagicMock, RuntimeError | None]:
    spec = tmp_path / "gateway.json"
    spec.write_text("{}")
    spec.chmod(0o600)
    token = tmp_path / "reporter-token"
    token.write_text("t" * 32)
    token.chmod(0o600)
    monkeypatch.setenv("RECON_TARGET_HEALTH_REPORTER_URL", "http://control-plane.test:4001")
    monkeypatch.setenv("RECON_TARGET_HEALTH_REPORTER_TOKEN_FILE", str(token))
    monkeypatch.delenv("RECON_GATEWAY_CAPTURE", raising=False)
    monkeypatch.delenv("RECON_HOST_PROBE_PORTS", raising=False)
    # The worker's UID is the gateway's, so no staging volume is involved.
    monkeypatch.setattr(gateway_staging, "gateway_uid", os.geteuid)
    existing = list(containers or [])

    def list_containers(**kwargs: Any) -> list[MagicMock]:
        filters = kwargs.get("filters") or {}
        out = existing
        for want in filters.get("label", []):
            k, _, v = want.partition("=")
            out = [c for c in out if c.labels.get(k) == v]
        if filters.get("name"):
            out = [c for c in out if any(n in c.name for n in filters["name"])]
        return out

    client = MagicMock()
    client.version.return_value = {"Version": "29.9.2"}
    # networks.list(names=...) is a substring filter in Docker; mimic it.
    client.networks.list.side_effect = lambda names=None: [
        n for n in (nets or []) if not names or any(x in n.name for x in names)
    ]
    if volume is None:
        client.volumes.get.side_effect = docker.errors.NotFound("no volume")
    else:
        client.volumes.get.return_value = volume
    client.containers.list.side_effect = list_containers
    fresh_net = _net()
    client.networks.create.return_value = fresh_net
    if create_error is not None:
        client.networks.create.side_effect = create_error
    client.volumes.create.return_value = _volume()
    gateway = MagicMock()
    gateway.status = "running"
    gateway.exec_run.side_effect = lambda _cmd: (0, b"CLOSED")
    client.containers.run.return_value = gateway
    client.networks.get.side_effect = RuntimeError("stop after the boundary is built")
    monkeypatch.setattr(docker, "from_env", lambda: client)
    monkeypatch.setattr(backends, "_wait_gateway_ready", lambda *_a, **_k: True)
    error: RuntimeError | None = None
    try:
        asyncio.run(
            backends._contained_docker_backend(
                image="agent:1",
                manifest=SimpleNamespace(),
                exposed_ports=(),
                scan_id=SCAN,
                engagement_id=engagement_id,
                gateway_spec_path=str(spec),
            )
        )
    except RuntimeError as exc:
        error = exc
    return client, error


def _reached_egress(error: RuntimeError | None) -> bool:
    # The fake stops the run at the outbound network, after the whole boundary is built.
    return error is not None and "could not attach" in str(error)


def test_crash_leftovers_are_reaped_and_the_boundary_is_rebuilt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    net, vol = _net(), _volume()
    stale = _with_heartbeat(tmp_path, age=3600)
    gw = _container(GW, stale)
    agent = _container("agent-1", {**stale, "recon.role": "agent"})
    client, error = _run(monkeypatch, tmp_path, nets=[net], volume=vol, containers=[gw, agent])
    assert _reached_egress(error), error
    gw.remove.assert_called_once_with(force=True)
    agent.remove.assert_called_once_with(force=True)
    vol.remove.assert_called_once_with(force=True)
    net.remove.assert_called_once()
    client.networks.create.assert_called_once()  # recreated, not reused
    created = client.networks.create.call_args.kwargs
    assert created["labels"]["recon.engagement_id"] == ENG
    assert client.containers.run.call_args.kwargs["labels"]["recon.engagement_id"] == ENG


@pytest.mark.parametrize(
    "drop",
    [
        {"recon.engagement_id": None},
        {"recon.scan_id": None},
        {"recon.engagement_id": "eng-2"},
        {"recon.scan_id": "scan-2"},
        {"recon.owner": None},
    ],
)
def test_same_name_network_with_a_missing_or_wrong_label_is_untouched(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, drop: dict[str, str | None]
) -> None:
    labels = {**OWNER, "recon.role": "agent-gateway-network"}
    for k, v in drop.items():
        if v is None:
            labels.pop(k)
        else:
            labels[k] = v
    net = _net(labels=labels)
    client, error = _run(monkeypatch, tmp_path, nets=[net])
    assert error is not None and "refusing to touch" in str(error)
    net.remove.assert_not_called()
    client.networks.create.assert_not_called()
    client.containers.run.assert_not_called()


def test_foreign_prefix_resources_are_never_touched(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    other = {**OWNER, "recon.scan_id": "scan-10", "recon.engagement_id": "eng-10"}
    sibling_net = _net(
        name="recon-net-scan-10", labels={**other, "recon.role": "agent-gateway-network"}
    )
    sibling_gw = _container("recon-egress-scan-10", {**other, "recon.role": "egress-gateway"})
    _, error = _run(monkeypatch, tmp_path, nets=[sibling_net], containers=[sibling_gw])
    assert _reached_egress(error), error
    sibling_net.remove.assert_not_called()
    sibling_gw.remove.assert_not_called()


def test_same_name_gateway_with_foreign_labels_is_untouched(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    squatter = _container(GW, {"recon.scan_id": SCAN})
    client, error = _run(monkeypatch, tmp_path, containers=[squatter])
    assert error is not None and "refusing to touch" in str(error)
    squatter.remove.assert_not_called()
    client.networks.create.assert_not_called()


def test_same_name_volume_with_foreign_labels_is_untouched(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    vol = _volume(labels={"recon.scan_id": SCAN})
    client, error = _run(monkeypatch, tmp_path, volume=vol)
    assert error is not None and "refusing to touch" in str(error)
    vol.remove.assert_not_called()
    client.networks.create.assert_not_called()


def test_without_an_engagement_id_nothing_is_reaped(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    net = _net(labels={**OWNER, "recon.role": "agent-gateway-network"})
    client, error = _run(monkeypatch, tmp_path, nets=[net], engagement_id="")
    assert error is not None and "refusing to touch" in str(error)
    net.remove.assert_not_called()
    client.networks.create.assert_not_called()


def test_a_clean_host_builds_the_boundary_without_reaping(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    client, error = _run(monkeypatch, tmp_path)
    assert _reached_egress(error), error
    client.networks.create.assert_called_once()


def test_an_owned_network_that_cannot_be_removed_fails_clearly(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    net = _net()
    net.remove.side_effect = docker.errors.APIError("active endpoints")
    client, error = _run(monkeypatch, tmp_path, nets=[net])
    assert error is not None and "could not be removed" in str(error)
    client.networks.create.assert_not_called()


def test_create_failure_never_falls_back_to_reusing_an_existing_network(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    # A same-name network that appears between the reap and the create (a race) is not adopted.
    client, error = _run(
        monkeypatch, tmp_path, create_error=docker.errors.APIError("already exists")
    )
    assert error is not None and "could not be created" in str(error)
    client.containers.run.assert_not_called()


def test_cached_session_is_bound_to_its_engagement(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        session_manager, "_compute_gateway_policy_fingerprint", lambda *_a, **_k: "fp"
    )
    monkeypatch.setitem(
        session_manager._SESSION_CACHE,
        "scan-x",
        {"_gateway_policy_fingerprint": "fp", "_engagement_id": "eng-a"},
    )
    with pytest.raises(RuntimeError, match="belongs to engagement"):
        asyncio.run(
            session_manager.create_or_reuse(
                "scan-x", image="i", local_sources=[], engagement_id="eng-b"
            )
        )


def _with_heartbeat(tmp_path: Any, age: float | None) -> dict[str, str]:
    """Labels for a leftover gateway whose engine last touched its heartbeat `age` seconds ago."""
    hb = tmp_path / "heartbeat"
    if age is not None:
        hb.write_text("")
        past = time.time() - age
        os.utime(hb, (past, past))
    return {**OWNER, "recon.role": "egress-gateway", "recon.heartbeat_path": str(hb)}


def test_fresh_heartbeat_skips_the_reap_and_removes_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    net, vol = _net(), _volume()
    gw = _container(GW, _with_heartbeat(tmp_path, age=5))
    client, error = _run(monkeypatch, tmp_path, nets=[net], volume=vol, containers=[gw])
    assert error is not None and "live or unverifiable owner" in str(error)
    for res in (gw, vol, net):
        res.remove.assert_not_called()
    client.networks.create.assert_not_called()


def test_stale_heartbeat_reaps(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    net, vol = _net(), _volume()
    gw = _container(GW, _with_heartbeat(tmp_path, age=3600))
    client, error = _run(monkeypatch, tmp_path, nets=[net], volume=vol, containers=[gw])
    assert _reached_egress(error), error
    gw.remove.assert_called_once_with(force=True)
    net.remove.assert_called_once()
    client.networks.create.assert_called_once()


def test_unreachable_heartbeat_skips_the_reap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    # The file is missing (no run-dir access, or a bad path) and the TTL has not passed.
    labels = {
        **_with_heartbeat(tmp_path, age=None),
        "recon.ttl_deadline": str(int(time.time()) + 3600),
    }
    net = _net()
    gw = _container(GW, labels)
    client, error = _run(monkeypatch, tmp_path, nets=[net], containers=[gw])
    assert error is not None and "live or unverifiable owner" in str(error)
    gw.remove.assert_not_called()
    net.remove.assert_not_called()
    client.networks.create.assert_not_called()


def _reap_directly(net: MagicMock, gw: MagicMock) -> None:
    dc = MagicMock()
    dc.networks.list.return_value = [net]
    dc.volumes.get.side_effect = docker.errors.NotFound("no volume")
    dc.containers.list.side_effect = lambda **kw: (
        [gw] if "label" in (kw.get("filters") or {}) else []
    )
    backends._reap_orphaned_boundary(
        dc, scan_id=SCAN, engagement_id=ENG, net_name=NET, ca_name=CA, gw_name=GW
    )


def test_a_running_engagement_keeps_a_fresh_heartbeat_and_is_not_reaped(tmp_path: Any) -> None:
    hb = tmp_path / ".heartbeat"
    net = _net()
    gw = _container(GW, {**OWNER, "recon.role": "egress-gateway", "recon.heartbeat_path": str(hb)})

    async def scenario() -> None:
        task = asyncio.create_task(runner._heartbeat_writer(hb, interval=0.01))
        try:
            # Age the file past the window, as a long gap would; the writer must refresh it.
            await asyncio.sleep(0.05)
            past = time.time() - 3600
            os.utime(hb, (past, past))
            await asyncio.sleep(0.05)
            with pytest.raises(RuntimeError, match="live or unverifiable owner"):
                _reap_directly(net, gw)
        finally:
            task.cancel()

    asyncio.run(scenario())
    gw.remove.assert_not_called()
    net.remove.assert_not_called()


def test_a_crashed_workers_heartbeat_ages_out_and_is_reaped(tmp_path: Any) -> None:
    hb = tmp_path / ".heartbeat"
    net = _net()
    gw = _container(GW, {**OWNER, "recon.role": "egress-gateway", "recon.heartbeat_path": str(hb)})

    async def run_then_crash() -> None:
        task = asyncio.create_task(runner._heartbeat_writer(hb, interval=0.01))
        await asyncio.sleep(0.05)
        task.cancel()  # the worker dies: nothing touches the file again
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run_then_crash())
    with pytest.raises(RuntimeError, match="live or unverifiable owner"):
        _reap_directly(net, gw)  # just stopped: still inside the window
    gw.remove.assert_not_called()
    past = time.time() - backends._heartbeat_stale_sec() - 60
    os.utime(hb, (past, past))
    _reap_directly(net, gw)
    gw.remove.assert_called_once_with(force=True)
    net.remove.assert_called_once()


def test_a_heartbeat_write_failure_is_logged_and_never_raises(tmp_path: Any) -> None:
    missing = tmp_path / "no-such-dir" / ".heartbeat"
    runner._touch_heartbeat(missing)  # must not raise
    assert not missing.exists()


def _ownerless(net: MagicMock) -> None:
    dc = MagicMock()
    dc.networks.list.return_value = [net]
    dc.volumes.get.side_effect = docker.errors.NotFound("no volume")
    dc.containers.list.return_value = []
    backends._reap_orphaned_boundary(
        dc, scan_id=SCAN, engagement_id=ENG, net_name=NET, ca_name=CA, gw_name=GW
    )


def test_a_boundary_still_being_set_up_is_not_reaped() -> None:
    # A retry overlapping the first worker between network and gateway creation.
    net = _net()
    net.attrs["Created"] = _created(10)
    with pytest.raises(RuntimeError, match="live or unverifiable owner"):
        _ownerless(net)
    net.remove.assert_not_called()


def test_an_old_ownerless_boundary_is_reaped() -> None:
    net = _net()
    _ownerless(net)
    net.remove.assert_called_once()


@pytest.mark.parametrize("created", [None, "", "not-a-time", "2020-01-01T00:00:00"])
def test_an_ownerless_boundary_with_no_usable_creation_time_is_skipped(
    created: str | None,
) -> None:
    net = _net()
    net.attrs["Created"] = created
    with pytest.raises(RuntimeError, match="live or unverifiable owner"):
        _ownerless(net)
    net.remove.assert_not_called()


def test_each_attempt_gets_its_own_heartbeat_file_so_a_retry_cannot_revive_the_old_one(
    tmp_path: Any,
) -> None:
    first = runner._attempt_heartbeat_path(tmp_path)
    second = runner._attempt_heartbeat_path(tmp_path)
    assert first != second and first.parent == second.parent == tmp_path
    runner._touch_heartbeat(first)
    past = time.time() - backends._heartbeat_stale_sec() - 60
    os.utime(first, (past, past))
    runner._touch_heartbeat(second)  # the retry's heartbeat
    gw = _container(GW, {**OWNER, "recon.heartbeat_path": str(first)})
    net = _net()
    _reap_directly(net, gw)  # the dead attempt's file is still stale, so it is reaped
    gw.remove.assert_called_once_with(force=True)


async def test_the_heartbeat_runs_until_after_sandbox_cleanup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    _wire_runner(monkeypatch, tmp_path)
    seen: dict[str, bool] = {}
    original_cleanup = session_manager.cleanup

    async def _root(**_kwargs: Any) -> None:
        return None

    async def _cleanup(*a: Any, **k: Any) -> None:
        tasks = [t for t in asyncio.all_tasks() if t.get_name().startswith("heartbeat-")]
        seen["running_during_cleanup"] = bool(tasks) and not any(t.done() for t in tasks)
        await original_cleanup(*a, **k)

    monkeypatch.setattr(runner, "run_agent_loop", _root)
    monkeypatch.setattr(session_manager, "cleanup", _cleanup)
    await runner.run_strix_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-hb",
        image="img",
        coordinator=runner.AgentCoordinator(),
    )
    assert seen["running_during_cleanup"] is True
    assert not [t for t in asyncio.all_tasks() if t.get_name().startswith("heartbeat-")]


async def test_a_later_phase_keeps_feeding_the_file_the_cached_sandbox_is_labelled_with(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    _wire_runner(monkeypatch, tmp_path)
    labelled = tmp_path / ".heartbeat-phase1"
    monkeypatch.setitem(
        session_manager._SESSION_CACHE, "scan-ph", {"_heartbeat_path": str(labelled)}
    )
    passed: dict[str, str] = {}

    async def _create_or_reuse(*_a: Any, **kw: Any) -> dict[str, Any]:
        passed["path"] = kw["heartbeat_path"]
        return {"client": object(), "session": object(), "caido_client": None}

    async def _root(**_kwargs: Any) -> None:
        return None

    monkeypatch.setattr(session_manager, "create_or_reuse", _create_or_reuse)
    monkeypatch.setattr(runner, "run_agent_loop", _root)
    await runner.run_strix_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-ph",
        image="img",
        coordinator=runner.AgentCoordinator(),
        cleanup_on_exit=False,
    )
    assert passed["path"] == str(labelled)
    assert labelled.exists(), "the phase must refresh the file the sandbox labels name"


class _ReachedError(Exception):
    pass


async def _old_signature_backend(
    *,
    image: str,
    manifest: Any,
    exposed_ports: tuple[int, ...],
    bind_mounts: Any = None,
    scan_id: str = "",
    heartbeat_path: str = "",
    gateway_spec_path: str = "",
    gateway_spec_json: str = "",
    gateway_target_ports: tuple[int, ...] = (),
) -> tuple[Any, Any]:
    """The k8s backend's signature before it learned engagement_id (no **kwargs)."""
    del image, manifest, exposed_ports, bind_mounts, scan_id, heartbeat_path
    del gateway_spec_path, gateway_spec_json, gateway_target_ports
    raise _ReachedError


def _registered(monkeypatch: pytest.MonkeyPatch, name: str, backend: Any) -> None:
    register_backend(name, backend)
    monkeypatch.setattr(
        session_manager,
        "load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(backend=name)),
    )


async def test_a_backend_with_the_old_signature_is_still_callable_with_an_engagement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _registered(monkeypatch, "old-sig", _old_signature_backend)
    try:
        # Without the guard this is a TypeError before the backend body runs.
        with pytest.raises(_ReachedError):
            await session_manager.create_or_reuse(
                "scan-old", image="img", local_sources=[], engagement_id=ENG
            )
    finally:
        _BACKENDS.pop("old-sig", None)


async def test_backends_that_declare_the_argument_receive_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[dict[str, Any]] = []

    async def named(*, engagement_id: str = "", **_rest: Any) -> tuple[Any, Any]:
        seen.append({"engagement_id": engagement_id})
        raise _ReachedError

    async def catch_all(**kwargs: Any) -> tuple[Any, Any]:
        seen.append(kwargs)
        raise _ReachedError

    for name, backend in (("named", named), ("catch-all", catch_all)):
        _registered(monkeypatch, name, backend)
        try:
            with pytest.raises(_ReachedError):
                await session_manager.create_or_reuse(
                    f"scan-{name}", image="img", local_sources=[], engagement_id=ENG
                )
        finally:
            _BACKENDS.pop(name, None)
    assert [d["engagement_id"] for d in seen] == [ENG, ENG]


def test_the_argument_is_forwarded_only_to_backends_that_declare_it() -> None:
    assert session_manager._engagement_kwargs(_old_signature_backend, ENG) == {}
    assert session_manager._engagement_kwargs(backends._contained_docker_backend, ENG) == {
        "engagement_id": ENG
    }
    assert session_manager._engagement_kwargs(backends._contained_docker_backend, "") == {}


def test_a_stalled_run_stops_touching_the_heartbeat_and_resumes_when_it_recovers(
    tmp_path: Any,
) -> None:
    hb = tmp_path / ".heartbeat"
    state = {"alive": True}

    async def scenario() -> tuple[float, float, float]:
        task = asyncio.create_task(
            runner._heartbeat_writer(hb, interval=0.01, alive=lambda: state["alive"])
        )
        try:
            await asyncio.sleep(0.05)
            state["alive"] = False  # the engine's progress watchdog gives up
            await asyncio.sleep(0.03)
            frozen = hb.stat().st_mtime_ns
            await asyncio.sleep(0.08)
            still = hb.stat().st_mtime_ns
            state["alive"] = True
            await asyncio.sleep(0.05)
            return frozen, still, hb.stat().st_mtime_ns
        finally:
            task.cancel()

    frozen, still, resumed = asyncio.run(scenario())
    assert still == frozen, "a stalled run must not keep its sandbox looking live"
    assert resumed > still


def test_a_stalled_heartbeat_ages_out_so_a_retry_elsewhere_can_reap(tmp_path: Any) -> None:
    hb = tmp_path / ".heartbeat"
    hb.write_text("0")
    past = time.time() - backends._heartbeat_stale_sec() - 60
    os.utime(hb, (past, past))
    gw = _container(GW, {**OWNER, "recon.role": "egress-gateway", "recon.heartbeat_path": str(hb)})
    _reap_directly(_net(), gw)
    gw.remove.assert_called_once_with(force=True)


async def test_a_failing_liveness_check_keeps_a_live_run_protected(tmp_path: Any) -> None:
    def broken() -> bool:
        raise RuntimeError("watchdog state unreadable")

    beat = runner._SandboxHeartbeat(tmp_path / ".heartbeat", interval=0.01)
    beat.alive = broken
    beat.start("hb-test")
    try:
        await asyncio.sleep(0.05)
        first = beat.path.stat().st_mtime_ns
        await asyncio.sleep(0.05)
        assert beat.path.stat().st_mtime_ns > first
    finally:
        await beat.stop()


_CLEANUP_STATES: list[bool] = []


async def _phase(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
    *,
    fail: bool,
    cleanup: bool,
    record: list[str] | None = None,
) -> dict[str, Any]:
    _wire_runner(monkeypatch, tmp_path)
    cache: dict[str, Any] = {}
    states = _CLEANUP_STATES
    states.clear()
    monkeypatch.setattr(session_manager, "_SESSION_CACHE", cache)

    async def _create_or_reuse(scan_id: str, **_kw: Any) -> dict[str, Any]:
        return cache.setdefault(
            scan_id, {"client": object(), "session": object(), "caido_client": None}
        )

    async def _root(**_kwargs: Any) -> None:
        if fail:
            raise ValueError("agent crashed")

    async def _cleanup(scan_id: str, **_kw: Any) -> None:
        if record is not None:
            record.append(scan_id)
            beat = cache.get(scan_id, {}).get("_heartbeat")
            states.append(beat is not None and not beat.stopped)
        cache.pop(scan_id, None)

    monkeypatch.setattr(session_manager, "create_or_reuse", _create_or_reuse)
    monkeypatch.setattr(session_manager, "cleanup", _cleanup)
    monkeypatch.setattr(runner, "run_agent_loop", _root)
    with contextlib.suppress(Exception):  # the failing phase re-raises
        await runner._run_scan(
            scan_config={"targets": [], "scan_mode": "deep"},
            scan_id="scan-gap",
            image="img",
            coordinator=runner.AgentCoordinator(),
            cleanup_on_exit=cleanup,
            heartbeat_alive=lambda: False,
        )
    return cache


async def test_a_retained_sandbox_keeps_its_heartbeat_across_the_gap_between_phases(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    cache = await _phase(monkeypatch, tmp_path, fail=False, cleanup=False)
    beat = cache["scan-gap"]["_heartbeat"]
    try:
        assert not beat.stopped, "the heartbeat must outlive the phase that retained the sandbox"
        assert beat.alive is None, "between phases it beats unconditionally"
    finally:
        await beat.stop()


async def test_the_final_cleanup_stops_the_retained_heartbeat(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    real_cleanup = session_manager.cleanup  # _wire_runner stubs the module attribute
    cache = await _phase(monkeypatch, tmp_path, fail=False, cleanup=False)
    beat = cache["scan-gap"]["_heartbeat"]
    await real_cleanup("scan-gap")
    assert beat.stopped


async def test_a_phase_that_fails_evicts_the_retained_sandbox(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    cleaned: list[str] = []
    cache = await _phase(monkeypatch, tmp_path, fail=True, cleanup=False, record=cleaned)
    assert cleaned == ["scan-gap"], "the failed attempt's sandbox must not stay cached"
    assert "scan-gap" not in cache
    assert _CLEANUP_STATES == [True], "the heartbeat must still run while the cleanup deletes"


async def test_a_phase_that_ends_cleanly_keeps_the_retained_sandbox(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    cleaned: list[str] = []
    cache = await _phase(monkeypatch, tmp_path, fail=False, cleanup=False, record=cleaned)
    try:
        assert cleaned == [] and "scan-gap" in cache
    finally:
        await cache["scan-gap"]["_heartbeat"].stop()


async def test_every_keyword_the_runner_passes_is_one_create_or_reuse_accepts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    # The other tests stub create_or_reuse with **kwargs, which would hide a stray keyword.
    _wire_runner(monkeypatch, tmp_path)
    real = inspect.signature(session_manager.create_or_reuse)
    seen: list[dict[str, Any]] = []

    async def _checking(scan_id: str, **kw: Any) -> dict[str, Any]:
        real.bind(scan_id, **kw)  # raises TypeError on a keyword the real function lacks
        seen.append(kw)
        return {"client": object(), "session": object(), "caido_client": None}

    async def _root(**_kwargs: Any) -> None:
        return None

    monkeypatch.setattr(session_manager, "create_or_reuse", _checking)
    monkeypatch.setattr(runner, "run_agent_loop", _root)
    await runner._run_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-sig",
        image="img",
        coordinator=runner.AgentCoordinator(),
        engagement_id=ENG,
        heartbeat_alive=lambda: True,
    )
    assert seen and seen[0]["engagement_id"] == ENG and "heartbeat_path" in seen[0]


async def test_cleanup_keeps_the_heartbeat_until_the_sandbox_is_deleted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    real_cleanup = session_manager.cleanup
    beat = runner._SandboxHeartbeat(tmp_path / ".heartbeat", interval=0.01)
    beat.start("hb-teardown")
    states: list[bool] = []

    class _Client:
        async def delete(self, _session: Any) -> None:
            states.append(beat.stopped)  # still beating while the sandbox is being deleted

    monkeypatch.setitem(
        session_manager._SESSION_CACHE,
        "scan-td",
        {"client": _Client(), "session": object(), "caido_client": None, "_heartbeat": beat},
    )
    await real_cleanup("scan-td")
    assert states == [False]
    assert beat.stopped


def test_duplicate_exact_name_networks_are_skipped_and_nothing_is_reaped() -> None:
    first, second = _net(), _net()
    gw = _container(GW, {**OWNER, "recon.role": "egress-gateway"})
    dc = MagicMock()
    dc.networks.list.return_value = [first, second]
    dc.volumes.get.side_effect = docker.errors.NotFound("no volume")
    dc.containers.list.return_value = [gw]
    with pytest.raises(RuntimeError, match="2 networks are named"):
        backends._reap_orphaned_boundary(
            dc, scan_id=SCAN, engagement_id=ENG, net_name=NET, ca_name=CA, gw_name=GW
        )
    for res in (first, second, gw):
        res.remove.assert_not_called()


def test_a_passed_ttl_deadline_wins_over_a_fresh_heartbeat(tmp_path: Any) -> None:
    net = _net()
    labels = {
        **_with_heartbeat(tmp_path, age=1),
        "recon.ttl_deadline": str(int(time.time()) - 5),
    }
    gw = _container(GW, labels)
    _reap_directly(net, gw)  # a run that beats past its hard ceiling is not a healthy engagement
    gw.remove.assert_called_once_with(force=True)


def test_a_fresh_heartbeat_inside_the_ttl_still_protects_the_owner(tmp_path: Any) -> None:
    labels = {
        **_with_heartbeat(tmp_path, age=1),
        "recon.ttl_deadline": str(int(time.time()) + 600),
    }
    gw = _container(GW, labels)
    with pytest.raises(RuntimeError, match="live or unverifiable owner"):
        _reap_directly(_net(), gw)
    gw.remove.assert_not_called()


async def test_a_cancelled_bring_up_keeps_the_heartbeat_until_its_teardown_ends(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    _wire_runner(monkeypatch, tmp_path)
    release = asyncio.Event()

    async def _slow_discard() -> None:
        await release.wait()

    discard = asyncio.get_running_loop().create_task(_slow_discard())

    async def _cancelled_creation(*_a: Any, **_k: Any) -> dict[str, Any]:
        session_manager._DISCARD_TASKS.add(discard)  # what _create_or_discard leaves behind
        raise asyncio.CancelledError

    monkeypatch.setattr(session_manager, "create_or_reuse", _cancelled_creation)

    def beating() -> bool:
        return any(
            t.get_name() == "heartbeat-scan-cx" and not t.done() for t in asyncio.all_tasks()
        )

    with pytest.raises(asyncio.CancelledError):
        await runner._run_scan(
            scan_config={"targets": [], "scan_mode": "deep"},
            scan_id="scan-cx",
            image="img",
            coordinator=runner.AgentCoordinator(),
        )
    try:
        await asyncio.sleep(0.05)
        assert beating(), "the boundary is still being deleted: it must keep looking live"
        release.set()
        await asyncio.sleep(0.05)
        assert not beating(), "once the discard has ended the heartbeat stops"
    finally:
        release.set()
        session_manager._DISCARD_TASKS.discard(discard)


def _volume_handle(created: str | None, current: str | None) -> tuple[MagicMock, MagicMock]:
    """A stale handle that remembers `created`, and what the daemon holds under the name now."""
    handle = MagicMock()
    handle.name = CA
    handle.attrs = {"CreatedAt": created} if created else {}
    now_there = MagicMock()
    now_there.attrs = {"CreatedAt": current}
    if current is None:
        handle.client.volumes.get.side_effect = docker.errors.NotFound("gone")
    else:
        handle.client.volumes.get.return_value = now_there
    return handle, now_there


def test_a_stale_handle_removes_only_the_volume_it_created() -> None:
    handle, now_there = _volume_handle("2026-11-26T01:00:00Z", "2026-11-26T01:00:00Z")
    remove_volume_if_created(handle)
    now_there.remove.assert_called_once_with(force=True)


def test_a_stale_handle_never_removes_a_replacement_volume() -> None:
    handle, replacement = _volume_handle("2026-11-26T01:00:00Z", "2026-11-26T02:30:00Z")
    remove_volume_if_created(handle)
    replacement.remove.assert_not_called()
    handle.remove.assert_not_called()


def test_a_handle_with_no_creation_time_removes_nothing() -> None:
    handle, now_there = _volume_handle(None, "2026-11-26T01:00:00Z")
    remove_volume_if_created(handle)
    now_there.remove.assert_not_called()
    handle.remove.assert_not_called()


def test_a_volume_that_is_already_gone_is_not_an_error() -> None:
    handle, _ = _volume_handle("2026-11-26T01:00:00Z", None)
    remove_volume_if_created(handle)
