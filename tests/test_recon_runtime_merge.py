# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""Recon's runtime behaviour on top of the upstream session, Docker and runner changes.

Covers what the upstream suites cannot: contained egress, Kubernetes source
hydration, the copy-unless-mounted source policy, gateway capture wiring, the
contained Docker container shape, and the Recon entrypoint forwarding the
caller-chosen finish and report tools while keeping coverage before teardown.
"""

from __future__ import annotations

import asyncio
import io
import json
import tarfile
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from agents import ModelSettings, function_tool
from agents.sandbox.entries import LocalDir
from agents.tool_context import ToolContext

import strix.tools.notes.tools as notes_tools
import strix.tools.todo.tools as todo_tools
from strix.core import runner
from strix.runtime import docker_client, session_manager
from strix.runtime.backends import _BACKENDS, _BIND_MOUNT_BACKENDS, register_backend
from strix.runtime.caido_handle import CaidoBootstrapHandle
from strix.runtime.deferred_session import DeferredSandboxSession
from strix.tools.exploitation import tool as exploitation
from strix.tools.proxy import caido_api, tools
from strix.tools.reporting import tool as reporting


@dataclass
class _ExecResult:
    exit_code: int = 0
    stdout: bytes = b""
    stderr: bytes = b""

    def ok(self) -> bool:
        return self.exit_code == 0


class _Session:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.writes: list[tuple[Path, bytes]] = []
        self.hydrated: list[bytes] = []

    async def hydrate_workspace(self, data: io.IOBase) -> None:
        self.calls.append("hydrate")
        self.hydrated.append(data.read())

    async def write(self, path: Path, data: io.IOBase) -> None:
        self.calls.append("write")
        self.writes.append((path, data.read()))

    async def exec(self, *argv: Any, **_kwargs: Any) -> _ExecResult:
        self.calls.append("exec:" + " ".join(str(a) for a in argv))
        return _ExecResult()

    async def resolve_exposed_port(self, port: int) -> Any:
        return types.SimpleNamespace(host="127.0.0.1", port=port, tls=False)


class _Client:
    def __init__(self) -> None:
        self.deleted: list[Any] = []

    async def delete(self, session: Any) -> None:
        self.deleted.append(session)


async def _no_caido(*_args: Any, **_kwargs: Any) -> None:
    return None


@pytest.fixture
def backend(monkeypatch: pytest.MonkeyPatch):
    """Register a fake backend under a given name; yields a setter returning the capture."""
    registered: list[str] = []

    def _use(name: str, *, session: Any = None, bind: bool = False) -> dict[str, Any]:
        captured: dict[str, Any] = {"session": session or _Session(), "client": _Client()}

        async def _backend(**kwargs: Any) -> tuple[Any, Any]:
            captured.update(kwargs)
            captured["called"] = True
            return captured["client"], captured["session"]

        saved = _BACKENDS.get(name)
        was_bind = name in _BIND_MOUNT_BACKENDS
        registered.append((name, saved, was_bind))  # type: ignore[arg-type]
        register_backend(name, _backend, supports_bind_mounts=bind)
        monkeypatch.setattr(session_manager, "bootstrap_caido", _no_caido)
        settings = types.SimpleNamespace(runtime=types.SimpleNamespace(backend=name))
        monkeypatch.setattr(session_manager, "load_settings", lambda: settings)
        return captured

    yield _use
    for name, saved, was_bind in registered:  # type: ignore[misc]
        if saved is None:
            _BACKENDS.pop(name, None)
        else:
            _BACKENDS[name] = saved
        if was_bind:
            _BIND_MOUNT_BACKENDS.add(name)
        else:
            _BIND_MOUNT_BACKENDS.discard(name)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "RECON_CONTAINED_EGRESS",
        "RECON_GATEWAY_CAPTURE",
        "RECON_EGRESS_PROXY",
        "RECON_EGRESS_CONTROL",
        "RECON_MOUNT_SOURCE",
        "STRIX_DOCKER_SANDBOX_NETWORK",
        "STRIX_DOCKER_SANDBOX_DEVICES",
        "STRIX_SANDBOX_LOG_MAX_SIZE",
    ):
        monkeypatch.delenv(name, raising=False)


def _members(archive: bytes) -> dict[str, bytes]:
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        out: dict[str, bytes] = {}
        for info in tar.getmembers():
            extracted = tar.extractfile(info)
            if extracted is not None:
                out[info.name] = extracted.read()
        return out


_NOTE = {"workspace_path": "/workspace/.recon/controlled-input.txt", "content": "token list"}


@pytest.mark.asyncio
async def test_extra_files_reach_a_kubernetes_sandbox_after_its_source(
    backend: Any, tmp_path: Path
) -> None:
    """Operator-attached files used to be accepted and silently dropped."""
    (tmp_path / "app.py").write_text("print(1)\n")
    captured = backend("k8s")
    try:
        bundle = await session_manager.create_or_reuse(
            "k8s-extra",
            image="img",
            local_sources=[{"workspace_subdir": "repo", "source_path": str(tmp_path)}],
            extra_files=[_NOTE],
        )
    finally:
        await session_manager.cleanup("k8s-extra")

    session = captured["session"]
    assert captured["manifest"].entries == {}
    assert captured["exposed_ports"] == ()
    assert session.calls[0] == "hydrate"
    assert "repo/app.py" in _members(session.hydrated[0])
    assert session.calls[1] == "write"
    [(path, archive)] = session.writes
    assert path == Path("/workspace/.strix-extra-files.tar")
    assert _members(archive) == {".recon/controlled-input.txt": b"token list"}
    assert any(call.startswith("exec:sh -c tar --no-same-owner") for call in session.calls)
    assert bundle["caido_client"] is None


@pytest.mark.asyncio
async def test_contained_sandbox_routes_egress_to_the_gateway(backend: Any) -> None:
    captured = backend("docker-contained", bind=True)
    try:
        await session_manager.create_or_reuse(
            "eng-7",
            image="img",
            local_sources=[],
            extra_files=[_NOTE],
            extra_env={"APP_TOKEN": "brokered"},
        )
    finally:
        await session_manager.cleanup("eng-7")

    env = captured["manifest"].environment.value
    assert env["http_proxy"] == "http://recon-egress-eng-7:8888"
    assert env["RECON_EGRESS_UPSTREAM"] == "http://recon-egress-eng-7:8888"
    assert env["APP_TOKEN"] == "brokered"  # noqa: S105 - fixture value
    assert captured["scan_id"] == "eng-7"
    assert len(captured["session"].writes) == 1


@pytest.mark.asyncio
async def test_deferred_bring_up_is_refused_for_contained_egress(backend: Any) -> None:
    captured = backend("k8s-contained")
    with pytest.raises(ValueError, match="contained egress"):
        await session_manager.create_or_reuse(
            "defer-k8s", image="img", local_sources=[], defer=True
        )
    assert "called" not in captured
    assert "defer-k8s" not in session_manager._SESSION_CACHE


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("bind", "mount", "copied", "mounted"),
    [
        (True, False, True, False),
        (True, True, False, True),
        (False, True, True, False),
    ],
    ids=["bind-backend-copies-by-default", "mount-flag-binds", "no-bind-backend-copies"],
)
async def test_sources_copy_unless_a_mount_is_requested(
    backend: Any, tmp_path: Path, *, bind: bool, mount: bool, copied: bool, mounted: bool
) -> None:
    captured = backend("test-source-policy", bind=bind)
    source = {"workspace_subdir": "repo", "source_path": str(tmp_path), "mount": mount}
    try:
        await session_manager.create_or_reuse("src-policy", image="img", local_sources=[source])
    finally:
        await session_manager.cleanup("src-policy")

    entries = captured["manifest"].entries
    assert isinstance(entries.get("repo"), LocalDir) is copied
    if mounted:
        assert captured["bind_mounts"] == [
            {"source": str(tmp_path.resolve()), "target": "/workspace/repo", "read_only": True}
        ]
    else:
        assert captured["bind_mounts"] == []


@pytest.mark.asyncio
async def test_a_writable_mount_request_is_still_mounted_read_only(
    backend: Any, tmp_path: Path
) -> None:
    (tmp_path / ".git").mkdir()
    captured = backend("test-ro-mount", bind=True)
    source = {
        "workspace_subdir": "repo",
        "source_path": str(tmp_path),
        "mount": True,
        "read_only": False,
        "protect_metadata": True,
    }
    try:
        await session_manager.create_or_reuse("ro-mount", image="img", local_sources=[source])
    finally:
        await session_manager.cleanup("ro-mount")
    assert [(m["target"], m["read_only"]) for m in captured["bind_mounts"]] == [
        ("/workspace/repo", True)
    ]


@pytest.mark.asyncio
async def test_cleanup_of_a_pending_deferred_session_skips_the_auth_purge(
    backend: Any,
) -> None:
    release = asyncio.Event()
    session = _Session()
    captured = backend("test-pending-purge", session=session)

    async def _slow_backend(**kwargs: Any) -> tuple[Any, Any]:
        captured.update(kwargs)
        await release.wait()
        return captured["client"], session

    register_backend("test-pending-purge", _slow_backend)
    bundle = await session_manager.create_or_reuse(
        "pending-purge", image="img", local_sources=[], defer=True
    )
    assert isinstance(bundle["session"], DeferredSandboxSession)
    await session_manager.cleanup("pending-purge")

    assert session.calls == []
    assert "pending-purge" not in session_manager._SESSION_CACHE


@pytest.mark.asyncio
async def test_gateway_capture_client_is_the_contained_proxy_client(
    backend: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    capture = object()

    class _Raw(_Session):
        def gateway_capture_client(self) -> object:
            return capture

    session = types.SimpleNamespace(_inner=_Raw())
    session.hydrate_workspace = session._inner.hydrate_workspace
    backend("k8s", session=session)
    monkeypatch.setenv("RECON_GATEWAY_CAPTURE", "1")
    try:
        bundle = await session_manager.create_or_reuse("cap-on", image="img", local_sources=[])
        assert bundle["caido_client"] is capture
    finally:
        session_manager._SESSION_CACHE.pop("cap-on", None)


@pytest.mark.asyncio
async def test_a_failing_gateway_capture_client_degrades_to_none(
    backend: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Raw(_Session):
        def gateway_capture_client(self) -> object:
            raise RuntimeError("gateway pod gone")

    backend("k8s", session=_Raw())
    monkeypatch.setenv("RECON_GATEWAY_CAPTURE", "1")
    try:
        bundle = await session_manager.create_or_reuse("cap-fail", image="img", local_sources=[])
        assert bundle["caido_client"] is None
    finally:
        session_manager._SESSION_CACHE.pop("cap-fail", None)


class _FakeContainers:
    def __init__(self) -> None:
        self.kwargs: dict[str, Any] = {}

    def create(self, **kwargs: Any) -> Any:
        self.kwargs = kwargs
        return types.SimpleNamespace(short_id="abc")


def _docker_client(*, contained: bool) -> tuple[Any, _FakeContainers]:
    containers = _FakeContainers()
    client = docker_client.StrixDockerSandboxClient.__new__(docker_client.StrixDockerSandboxClient)
    client.docker_client = types.SimpleNamespace(containers=containers)
    client.image_exists = lambda _image: True  # type: ignore[method-assign]
    client.recon_contained = contained
    client.recon_network = "recon-net-s1" if contained else ""
    client.recon_gateway_ca_volume = types.SimpleNamespace(name="recon-ca-s1")
    client.recon_scan_id = "s1"
    return client, containers


@pytest.mark.asyncio
async def test_contained_container_ignores_network_and_device_overrides(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_DOCKER_SANDBOX_NETWORK", "host-lan")
    monkeypatch.setenv("STRIX_DOCKER_SANDBOX_DEVICES", "/dev/net/tun")
    client, containers = _docker_client(contained=True)

    await client._create_container("img", exposed_ports=())

    kwargs = containers.kwargs
    assert kwargs["network"] == "recon-net-s1"
    assert "devices" not in kwargs
    assert "cap_add" not in kwargs
    assert kwargs["cap_drop"] == ["NET_ADMIN", "NET_RAW", "SYS_ADMIN"]
    assert "extra_hosts" not in kwargs
    assert kwargs["log_config"]["Config"] == {"max-size": "50m", "max-file": "3"}
    assert kwargs["labels"]["recon.role"] == "agent"


@pytest.mark.asyncio
async def test_uncontained_container_takes_the_upstream_overrides(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_DOCKER_SANDBOX_DEVICES", "/dev/net/tun")
    client, containers = _docker_client(contained=False)
    client.strix_bind_mounts = [
        {"source": "/src/repo/sub", "target": "/workspace/repo/sub"},
        {"source": "/src/repo", "target": "/workspace/repo"},
    ]

    await client._create_container("img", exposed_ports=(48080,))

    kwargs = containers.kwargs
    assert kwargs["devices"] == ["/dev/net/tun:/dev/net/tun:rwm"]
    assert set(kwargs["cap_add"]) >= {"NET_ADMIN", "NET_RAW"}
    assert kwargs["extra_hosts"] == {"host.docker.internal": "host-gateway"}
    assert [m["Target"] for m in kwargs["mounts"]] == ["/workspace/repo", "/workspace/repo/sub"]
    assert all(m["ReadOnly"] for m in kwargs["mounts"])


def test_recon_name_still_resolves_to_the_upstream_client() -> None:
    assert docker_client.ReconDockerSandboxClient is docker_client.StrixDockerSandboxClient


def _wire_runner(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, events: list[str]) -> dict:
    seen: dict[str, Any] = {}
    monkeypatch.setattr(runner, "run_dir_for", lambda _scan_id: tmp_path)
    monkeypatch.setattr(runner, "runtime_state_dir", lambda _run_dir: tmp_path)
    monkeypatch.setattr(runner, "setup_scan_logging", lambda _run_dir: lambda: None)
    monkeypatch.setattr(runner, "set_scan_id", lambda _scan_id: None)
    settings = types.SimpleNamespace(
        llm=types.SimpleNamespace(
            model="openai/gpt-4o",
            reasoning_effort="high",
            force_required_tool_choice=False,
            parallel_tool_calls=False,
            timeout=300,
            prompt_cache=True,
            extra_headers=None,
            extra_body=None,
        ),
        runtime=types.SimpleNamespace(max_context_images=3),
        telemetry=types.SimpleNamespace(run_record_timings=False),
    )
    monkeypatch.setattr(runner, "load_settings", lambda: settings)
    monkeypatch.setattr(runner, "configure_sdk_model_defaults", lambda _s: None)
    monkeypatch.setattr(runner, "uses_chat_completions_tool_schema", lambda _m, _s: False)
    monkeypatch.setattr(todo_tools, "hydrate_todos_from_disk", lambda _d: None)
    monkeypatch.setattr(notes_tools, "hydrate_notes_from_disk", lambda _d: None)

    async def _create_or_reuse(*_a: Any, **_k: Any) -> dict[str, Any]:
        return {"client": object(), "session": object(), "caido_client": None}

    async def _cleanup(*_a: Any, **_k: Any) -> None:
        events.append("teardown")

    async def _coverage(*_a: Any, **_k: Any) -> None:
        events.append("coverage")

    def _build_agent(**kwargs: Any) -> object:
        seen.update(kwargs)
        return object()

    async def _root_finishes(**_kwargs: Any) -> None:
        events.append("root-finished")

    monkeypatch.setattr(session_manager, "create_or_reuse", _create_or_reuse)
    monkeypatch.setattr(session_manager, "cleanup", _cleanup)
    monkeypatch.setattr(runner, "_run_coverage_on_exit", _coverage)
    monkeypatch.setattr(runner, "build_root_task", lambda _c: "task")
    monkeypatch.setattr(runner, "build_scope_context", lambda _c: "")
    monkeypatch.setattr(runner, "make_model_settings", lambda *_a, **_k: ModelSettings())
    monkeypatch.setattr(runner, "build_strix_agent", _build_agent)
    monkeypatch.setattr(runner, "make_child_factory", lambda **_k: lambda **_kk: object())
    monkeypatch.setattr(runner, "open_agent_session", lambda _root_id, _db: object())
    monkeypatch.setattr(runner, "run_agent_loop", _root_finishes)
    return seen


@function_tool
def finish_assessment(summary: str) -> str:
    """End the assessment."""
    return summary


@function_tool
def file_lead(title: str) -> str:
    """File a lead."""
    return title


@pytest.mark.asyncio
async def test_a_chosen_finish_tool_still_runs_coverage_before_teardown(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    events: list[str] = []
    seen = _wire_runner(monkeypatch, tmp_path, events)

    await runner.run_recon_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-finish",
        image="img",
        root_finish_tool=finish_assessment,
        report_tool=file_lead,
        coverage_tools=False,
        run_coverage_worker_on_exit=True,
    )

    assert seen["finish_tool"] is finish_assessment
    assert seen["report_tool"] is file_lead
    assert seen["coverage_tools"] is False
    assert events == ["root-finished", "coverage", "teardown"]


@pytest.mark.asyncio
@pytest.mark.parametrize("entrypoint", ["run_recon_scan", "run_strix_scan"])
async def test_entrypoints_forward_the_upstream_scan_options(
    monkeypatch: pytest.MonkeyPatch, entrypoint: str
) -> None:
    forwarded: dict[str, Any] = {}

    async def _run_scan(**kwargs: Any) -> None:
        forwarded.update(kwargs)

    monkeypatch.setattr(runner, "_run_scan", _run_scan)
    options = {
        "budget_policy": "pause",
        "replace_root_scan_prompt": True,
        "root_finish_tool": finish_assessment,
        "report_tool": file_lead,
        "coverage_tools": False,
        "subagent_turn_limits": {"recon": 40},
    }

    await getattr(runner, entrypoint)(scan_config={}, image="img", **options)

    assert {key: forwarded[key] for key in options} == options


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cancel", [False, True], ids=["proxy-setup-fails", "proxy-setup-cancelled"]
)
async def test_a_failed_proxy_setup_discards_the_sandbox(backend: Any, *, cancel: bool) -> None:
    started = asyncio.Event()

    class _Unreachable(_Session):
        async def resolve_exposed_port(self, port: int) -> Any:
            del port
            started.set()
            if cancel:
                await asyncio.Event().wait()
            raise RuntimeError("port not published")

    session = _Unreachable()
    captured = backend("test-proxy-setup", session=session)
    task = asyncio.create_task(
        session_manager.create_or_reuse("proxy-setup", image="img", local_sources=[])
    )
    await started.wait()
    if cancel:
        task.cancel()
    with pytest.raises((RuntimeError, asyncio.CancelledError)):
        await task

    assert captured["client"].deleted == [session]
    assert "proxy-setup" not in session_manager._SESSION_CACHE


class _GatewayCapture:
    _is_gateway_capture = True

    def __init__(self) -> None:
        self.captures = {"cap-1": b"GET /a HTTP/1.1\r\n\r\n"}

    async def list_requests_connection(self, *, httpql_filter: Any = None, first: int = 50) -> Any:
        node = types.SimpleNamespace(request=types.SimpleNamespace(id="cap-1"), response=None)
        return types.SimpleNamespace(
            edges=[types.SimpleNamespace(cursor="cap-1", node=node)][:first],
            page_info=None,
            filter=httpql_filter,
        )

    async def view_request(self, request_id: str, *, part: str = "request") -> Any:
        raw = self.captures.get(request_id)
        if raw is None:
            return None
        return types.SimpleNamespace(
            request=types.SimpleNamespace(raw=raw), response=None, part=part
        )


def _tool_ctx(context: dict[str, Any], name: str) -> Any:
    return ToolContext(context=context, tool_name=name, tool_call_id="call-1", tool_arguments="{}")


@pytest.mark.asyncio
async def test_gateway_capture_serves_listing_viewing_and_evidence_checks() -> None:
    gateway = _GatewayCapture()
    listed = await caido_api.list_requests_with_client(gateway, httpql_filter="x", first=5)
    assert [edge.cursor for edge in listed.edges] == ["cap-1"]
    viewed = await caido_api.get_request_with_client(gateway, "cap-1", part="response")
    assert viewed.request.raw.startswith(b"GET /a")

    ctx = _tool_ctx({"caido_client": gateway}, "create_vulnerability_report")
    assert await tools.existing_request_ids(ctx, ["cap-1", "cap-9"]) == {"cap-1"}


@pytest.mark.asyncio
@pytest.mark.parametrize("tool_name", ["repeat_request", "list_sitemap", "scope_rules"])
async def test_caido_only_tools_say_so_under_gateway_capture(tool_name: str) -> None:
    tool = getattr(tools, tool_name)
    args = {"repeat_request": {"request_id": "cap-1"}, "scope_rules": {"action": "list"}}
    ctx = _tool_ctx({"caido_client": _GatewayCapture()}, tool.name)
    raw = await tool.on_invoke_tool(ctx, json.dumps(args.get(tool_name, {})))
    result = json.loads(raw)
    assert result["success"] is False
    assert "contained egress" in result["error"]


@pytest.mark.asyncio
async def test_exploit_evidence_waits_for_the_caido_bootstrap() -> None:
    gateway = _GatewayCapture()

    async def _bootstrap() -> Any:
        await asyncio.sleep(0)
        return gateway

    handle = CaidoBootstrapHandle(asyncio.create_task(_bootstrap()))
    ctx = _tool_ctx({"caido_client": handle}, "promote_finding")
    request_text, response_text = await exploitation._fetch_caido_raw(ctx, "cap-1")

    assert request_text is not None
    assert request_text.startswith("GET /a")
    assert response_text is None


_GW_ID = "gw-0123456789ab-" + "f" * 32


@pytest.mark.asyncio
async def test_a_report_can_cite_a_gateway_capture() -> None:
    gateway = _GatewayCapture()
    gateway.captures[_GW_ID] = b"POST /api/login HTTP/1.1\r\n\r\n"
    ctx = _tool_ctx({"caido_client": gateway}, "create_vulnerability_report")

    ids, errors, warning = await reporting._verify_http_exchange_ids(ctx, [_GW_ID, "42"])
    assert errors == ["http_exchange_ids do not exist in the current proxy project: 42"]
    assert ids is None

    ids, errors, warning = await reporting._verify_http_exchange_ids(ctx, [_GW_ID])
    assert (ids, errors, warning) == ([_GW_ID], [], None)


@pytest.mark.parametrize("bad", ["gw-abc-123", "gw--" + "f" * 32, "cap-1", "gw-a b-" + "f" * 32])
def test_malformed_evidence_ids_are_still_rejected(bad: str) -> None:
    ids, errors = reporting._normalize_http_exchange_ids([bad])
    assert errors
    assert ids == []
