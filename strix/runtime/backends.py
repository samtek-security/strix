# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""Sandbox backend registry — selected via RECON_RUNTIME_BACKEND (default: docker)."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from agents.sandbox.manifest import Manifest


logger = logging.getLogger(__name__)


SandboxBackend = Callable[..., Awaitable[tuple[Any, Any]]]


async def _docker_backend(
    *,
    image: str,
    manifest: Manifest,
    exposed_ports: tuple[int, ...],
    bind_mounts: list[dict[str, Any]] | None = None,
    scan_id: str = "",
    heartbeat_path: str = "",
    gateway_spec_path: str = "",
    gateway_spec_json: str = "",
    gateway_target_ports: tuple[int, ...] = (),
) -> tuple[Any, Any]:
    """Bring up a session backed by the local Docker daemon.

    Uses :class:`ReconDockerSandboxClient` to inject NET_ADMIN /
    NET_RAW caps + ``host.docker.internal`` host-gateway. Imports
    ``docker`` lazily so deployments that target a non-Docker
    backend don't need the docker-py library installed.

    ``session.start()`` is what materializes the manifest entries
    (LocalDir copies and manifest-declared volume/FUSE mounts) into the
    running container — the SDK's ``client.create()`` only builds the inner
    session object without applying the manifest. ``async with session:``
    would call it too, but Recon manages session lifetime explicitly via
    ``client.delete()`` so we trigger ``start()`` ourselves.

    ``bind_mounts`` are host directories (e.g. large repos passed via
    ``--mount``) bind-mounted read-only; unlike manifest entries they are
    applied by Docker at container-create time, not by ``start()``.
    """
    import docker
    from agents.sandbox.sandboxes.docker import DockerSandboxClientOptions

    from strix.runtime.docker_client import ReconDockerSandboxClient

    client = ReconDockerSandboxClient(docker.from_env())
    client.recon_bind_mounts = bind_mounts or []
    client.recon_scan_id = scan_id  # stamped onto the container's recon.scan_id label for the reaper
    client.recon_heartbeat_path = heartbeat_path  # recon.heartbeat_path label (liveness signal)
    options = DockerSandboxClientOptions(image=image, exposed_ports=exposed_ports)
    session = await client.create(options=options, manifest=manifest)
    await session.start()
    return client, session


def _gateway_name(scan_id: str) -> str:
    """Deterministic gateway container name so the agent's proxy env can point at it by name on the
    internal network BEFORE it is up (docker resolves the name once both join the network)."""
    return "recon-egress-" + (scan_id or "default")


async def _contained_docker_backend(
    *,
    image: str,
    manifest: Manifest,
    exposed_ports: tuple[int, ...],
    bind_mounts: list[dict[str, Any]] | None = None,
    scan_id: str = "",
    heartbeat_path: str = "",
    gateway_spec_path: str = "",
    gateway_spec_json: str = "",
    gateway_target_ports: tuple[int, ...] = (),
) -> tuple[Any, Any]:
    """Own-netns contained backend (P0-2, opt-in via RECON_CONTAINED_EGRESS).

    Ordering (fail-closed): create an INTERNAL-only network -> start the egress-gateway container on
    it (same recon.* labels so the reaper owns it) -> WAIT for readiness -> only then create the
    agent joined to that network with caps dropped and no host route (docker_client.recon_contained).
    The agent's proxy env is the gateway's deterministic name (set in session_manager). If the
    gateway never becomes ready this raises before the agent is created - the agent is never brought
    up with a broken/absent boundary.
    """
    import stat as _stat
    import docker
    from agents.sandbox.sandboxes.docker import DockerSandboxClientOptions

    from strix.runtime.docker_client import ReconDockerSandboxClient, _sandbox_ttl_sec

    # Validate gateway_spec_path before creating any Docker resources (fail-closed).
    _gsp = (gateway_spec_path or "").strip()
    if not _gsp:
        raise ValueError("contained docker backend requires gateway_spec_path")
    try:
        _stat_result = os.stat(_gsp)
    except OSError as exc:
        raise ValueError(f"gateway_spec_path {_gsp!r} is not accessible: {exc}") from exc
    if not _stat.S_ISREG(_stat_result.st_mode):
        raise ValueError(f"gateway_spec_path {_gsp!r} is not a regular file")
    if _stat_result.st_uid != os.geteuid():
        raise ValueError(f"gateway_spec_path {_gsp!r} is not owned by the worker user")
    if _stat.S_IMODE(_stat_result.st_mode) & 0o077:
        raise ValueError(f"gateway_spec_path {_gsp!r} must not be accessible by group or other")

    dc = docker.from_env()
    net_name = "recon-net-" + (scan_id or "default")
    ca_name = "recon-ca-" + (scan_id or "default")
    gw_name = _gateway_name(scan_id)
    gw_image = os.environ.get("RECON_EGRESS_GATEWAY_IMAGE", "recon/egress-gateway:latest")
    boundary_labels = {
        "recon.sandbox": "true",
        "recon.scan_id": scan_id or "",
        "recon.owner": "contained-egress",
    }

    # 1. Internal-only network (no NAT/gateway to host or internet).
    network_created = False
    try:
        internal_net = dc.networks.create(
            net_name,
            driver="bridge",
            internal=True,
            check_duplicate=True,
            labels={**boundary_labels, "recon.role": "agent-gateway-network"},
        )
        network_created = True
    except docker.errors.APIError:
        matches = dc.networks.list(names=[net_name])
        if len(matches) != 1:
            raise RuntimeError(
                f"contained network {net_name!r} could not be created or uniquely resolved"
            )
        internal_net = matches[0]
    internal_net.reload()
    net_attrs = internal_net.attrs
    expected_net_labels = {**boundary_labels, "recon.role": "agent-gateway-network"}
    if (
        net_attrs.get("Name") != net_name
        or net_attrs.get("Driver") != "bridge"
        or net_attrs.get("Internal") is not True
        or any((net_attrs.get("Labels") or {}).get(k) != v for k, v in expected_net_labels.items())
        or bool(net_attrs.get("Containers"))
    ):
        if network_created:
            with _suppress():
                internal_net.remove()
        raise RuntimeError(
            f"contained network {net_name!r} failed ownership/driver/isolation/attachment checks; "
            "refusing to start gateway or agent"
        )

    expected_ca_labels = {**boundary_labels, "recon.role": "gateway-ca-volume"}
    ca_created = False
    try:
        ca_volume = dc.volumes.create(name=ca_name, labels=expected_ca_labels)
        ca_created = True
    except docker.errors.APIError:
        ca_volume = dc.volumes.get(ca_name)
    ca_volume.reload()
    if any((ca_volume.attrs.get("Labels") or {}).get(k) != v for k, v in expected_ca_labels.items()):
        if ca_created:
            with _suppress():
                ca_volume.remove(force=True)
        with _suppress():
            internal_net.remove()
        raise RuntimeError(
            f"gateway CA volume {ca_name!r} failed ownership checks; refusing to start gateway"
        )

    def _cleanup_boundary(gateway: Any | None = None) -> None:
        if gateway is not None:
            with _suppress():
                gateway.remove(force=True)
        with _suppress():
            ca_volume.remove(force=True)
        with _suppress():
            internal_net.remove()

    # 2. Gateway container: same recon.* labels as the agent so the independent reaper tears both
    #    down together; the signed spec is mounted read-only.
    now = int(time.time())
    labels = {
        **boundary_labels,
        "recon.role": "egress-gateway",
        "recon.created_at": str(now),
        "recon.ttl_deadline": str(now + _sandbox_ttl_sec()),
        "recon.heartbeat_path": heartbeat_path or "",
    }
    volumes = {
        _gsp: {"bind": "/etc/recon/engagement.json", "mode": "ro"},
        ca_name: {"bind": "/ca", "mode": "rw"},
    }
    # Gateway capture (Plan Phase 4): when enabled, give the gateway a SESSION-DERIVED capability
    # token + scan id so it runs the redacted capture store + retrieval API and publishes the
    # /ca/recon-capture-ready marker the agent-path readiness gate checks before sending traffic.
    gateway_env = {
        "RECON_MODEL_HOSTS": os.environ.get("RECON_MODEL_HOSTS", ""),
        # entrypoint resolves/binds the internal-net address before the
        # outbound NIC is attached, so egress-network peers cannot proxy.
        "RECON_PROXY_INTERNAL_ONLY": "1",
    }
    capture_enabled = os.environ.get("RECON_GATEWAY_CAPTURE", "").strip().lower() in ("1", "true", "yes")
    if capture_enabled:
        from strix.runtime.capture_token import capture_capability_token

        # Fail closed: capture with no session secret would mint a publicly-computable token
        # (HMAC over an empty key), regressing the unguessable secret the gateway used before.
        # Never start a capture-enabled gateway without the session secret.
        _session_secret = os.environ.get("RECON_SESSION_SECRET", "")
        if not _session_secret.strip():
            raise RuntimeError(
                "RECON_GATEWAY_CAPTURE is enabled but RECON_SESSION_SECRET is unset/empty; "
                "refusing to start the capture-enabled gateway (fail-closed: an empty-keyed "
                "capture token is publicly computable from the engagement id)"
            )
        gateway_env["RECON_GATEWAY_CAPTURE"] = "1"
        gateway_env["RECON_CAPTURE_TOKEN"] = capture_capability_token(
            _session_secret,
            scan_id or "",
        )
        gateway_env["RECON_SCAN_ID"] = scan_id or ""
        gateway_env["RECON_CAPTURE_CONTROL_HOST"] = "127.0.0.1"
    try:
        gw = dc.containers.run(
            gw_image,
            name=gw_name,
            detach=True,
            network=net_name,
            labels=labels,
            volumes=volumes,
            environment=gateway_env,
        )
    except BaseException:
        _cleanup_boundary()
        raise

    # 3. Readiness barrier happens before adding the outbound NIC. This makes
    # RECON_PROXY_INTERNAL_ONLY deterministically resolve/bind only the private
    # per-run address, never the shared egress-network address. When capture is
    # enabled the barrier ALSO requires the /ca/recon-capture-ready marker, so
    # the agent never starts against a gateway that cannot serve redacted evidence.
    if not _wait_gateway_ready(gw, require_capture_ready=capture_enabled):
        _cleanup_boundary(gw)
        raise RuntimeError(f"egress gateway {gw_name} not ready; refusing to start the agent (fail-closed)")

    # Dual-home only after the private listener is ready. Attachment is mandatory:
    # without it the run is broken, so remove the gateway and fail before the agent.
    egress_net = os.environ.get("RECON_EGRESS_NETWORK", "bridge")
    try:
        dc.networks.get(egress_net).connect(gw)
    except Exception as exc:
        _cleanup_boundary(gw)
        raise RuntimeError(
            f"egress gateway {gw_name} could not attach outbound network {egress_net!r}"
        ) from exc

    # 4. Agent, contained: joined to the internal network, caps dropped, no host route.
    client = ReconDockerSandboxClient(dc)
    client.recon_bind_mounts = bind_mounts or []
    client.recon_scan_id = scan_id
    client.recon_heartbeat_path = heartbeat_path
    client.recon_contained = True
    client.recon_network = net_name
    client.recon_gateway_container = gw
    client.recon_internal_network = internal_net
    client.recon_gateway_ca_volume = ca_volume
    options = DockerSandboxClientOptions(image=image, exposed_ports=exposed_ports)
    session = None
    try:
        session = await client.create(options=options, manifest=manifest)
        await session.start()
        ready = await asyncio.to_thread(_wait_agent_ready, client, session)
        if not ready:
            raise RuntimeError(
                f"contained agent for {scan_id!r} did not publish its readiness marker"
            )
    except BaseException:
        if session is not None:
            try:
                await client.delete(session)
            except Exception:
                _cleanup_boundary(gw)
        else:
            _cleanup_boundary(gw)
        raise
    return client, session



def _wait_gateway_ready(container: Any, timeout_s: int = 30, require_capture_ready: bool = False) -> bool:
    """Poll until the gateway is running with both valid policy and CA published.

    When ``require_capture_ready`` is set (RECON_GATEWAY_CAPTURE enabled), ALSO require the
    /ca/recon-capture-ready marker, which the gateway publishes only after its redacted capture
    retrieval API is bound and token-gated. A gateway with capture enabled but no marker never
    becomes ready -> the agent is never started against it (fail-closed)."""
    deadline = time.monotonic() + timeout_s
    ready_cmd = "test -f /ca/recon-policy-loaded && test -f /ca/recon-egress-ca.pem"
    if require_capture_ready:
        ready_cmd += " && test -f /ca/recon-capture-ready"
    while time.monotonic() < deadline:
        with _suppress():
            container.reload()
            if container.status == "running":
                code, _ = container.exec_run(f"sh -c '{ready_cmd}'")
                if code == 0:
                    return True
        time.sleep(1)
    return False


def _wait_agent_ready(client: Any, session: Any, timeout_s: int = 120) -> bool:
    """Wait for the real image entrypoint to install trust and publish readiness."""
    inner = getattr(session, "_inner", session)
    container_id = getattr(getattr(inner, "state", None), "container_id", None)
    if not container_id:
        return False
    try:
        container = client.docker_client.containers.get(container_id)
    except Exception:
        return False
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            container.reload()
            if container.status != "running":
                return False
            code, _ = container.exec_run("test -f /tmp/recon-agent-ready")
            if code == 0:
                return True
        except Exception:
            return False
        time.sleep(1)
    return False


class _suppress:
    """contextlib.suppress(Exception) without importing contextlib at module top."""

    def __enter__(self) -> "_suppress":
        return self

    def __exit__(self, *exc: object) -> bool:
        return True


_BACKENDS: dict[str, SandboxBackend] = {
    "docker": _docker_backend,
    "docker-contained": _contained_docker_backend,
}


def effective_backend_name(name: str) -> str:
    """Resolve ``name`` applying the RECON_CONTAINED_EGRESS upgrade rule."""
    if name == "docker" and os.environ.get("RECON_CONTAINED_EGRESS", "").strip().lower() in ("1", "true", "yes"):
        return "docker-contained"
    return name


def get_backend(name: str) -> SandboxBackend:
    """Return the backend factory for ``name`` or raise.

    Args:
        name: Backend identifier (e.g. ``"docker"``). Match is exact;
            no fallback. Unknown values raise so config typos surface
            immediately instead of silently picking a default.
    """
    name = effective_backend_name(name)
    backend = _BACKENDS.get(name)
    if backend is None:
        supported = ", ".join(sorted(_BACKENDS))
        raise ValueError(
            f"Unknown RECON_RUNTIME_BACKEND: {name!r} (supported: {supported})",
        )
    logger.debug("Selected sandbox backend: %s", name)
    return backend


def register_backend(name: str, backend: SandboxBackend) -> None:
    """Register a custom backend under ``name``.

    Intended for downstream users who ship their own runtime — register
    before any ``session_manager.create_or_reuse`` call. Re-registering
    an existing name overwrites the prior entry.
    """
    _BACKENDS[name] = backend
    logger.info("Registered sandbox backend: %s", name)


def supported_backends() -> list[str]:
    return sorted(_BACKENDS)
