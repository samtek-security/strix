# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""Sandbox backend registry — selected via RECON_RUNTIME_BACKEND (default: docker)."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from stat import S_IMODE, S_ISREG
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from strix.runtime import host_isolation


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

    Uses :class:`StrixDockerSandboxClient` to inject NET_ADMIN /
    NET_RAW caps + ``host.docker.internal`` host-gateway, on the same
    endpoint the startup check resolved (``DOCKER_HOST``, docker context,
    default socket). Imports ``docker`` lazily so deployments that target
    a non-Docker backend don't need the docker-py library installed.

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
    from agents.sandbox.sandboxes.docker import DockerSandboxClientOptions

    from strix.runtime.docker_client import StrixDockerSandboxClient
    from strix.runtime.docker_connection import connect_docker

    client = StrixDockerSandboxClient(connect_docker())
    client.strix_bind_mounts = bind_mounts or []
    client.recon_scan_id = scan_id  # stamped onto the container's recon.scan_id label for the reaper
    client.recon_heartbeat_path = heartbeat_path  # recon.heartbeat_path label (liveness signal)
    options = DockerSandboxClientOptions(image=image, exposed_ports=exposed_ports)
    session = await client.create(options=options, manifest=manifest)
    await session.start()
    return client, session


_REPORTER_TOKEN_MOUNT = "/etc/recon/target-health-token"  # noqa: S105  (a path, not a secret)
_REPORTER_TOKEN_MIN_BYTES = 32


def _gateway_name(scan_id: str) -> str:
    """Deterministic gateway container name so the agent's proxy env can point at it by name on the
    internal network BEFORE it is up (docker resolves the name once both join the network)."""
    return "recon-egress-" + (scan_id or "default")


# One DNS label is 1-63 letters, digits or inner hyphens; labels are joined by single dots.
_REPORTER_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_REPORTER_HOST_RE = re.compile(rf"{_REPORTER_LABEL}(?:\.{_REPORTER_LABEL})*")
_REPORTER_IPV6_RE = re.compile(r"[0-9A-Fa-f:.]+")
_REPORTER_PATH_RE = re.compile(r"(?:/[A-Za-z0-9._~-]+)*/?")


def _canonical_reporter_url(raw: str) -> str:
    """Return the reporter base URL rebuilt from scheme, host, port and path only.

    A strict allowlist, not a denylist: the URL is parsed, rebuilt from those four parts, and
    refused unless the raw string equals the rebuilt one. Anything the parser tolerates but the
    rebuild drops (query, fragment, credentials, whitespace, odd ports, mixed case) fails the
    comparison, so the gateway receives exactly the string that was validated.
    """
    try:
        parts = urlsplit(raw)
        host = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise ValueError(
            f"RECON_TARGET_HEALTH_REPORTER_URL {raw!r} is not a valid URL: {exc}"
        ) from exc
    bad = (
        parts.scheme not in ("http", "https")
        or not host
        or (port is not None and not 1 <= port <= 65535)
        or not _REPORTER_PATH_RE.fullmatch(parts.path)
    )
    if not bad:
        ipv6 = ":" in host
        host_ok = _REPORTER_IPV6_RE if ipv6 else _REPORTER_HOST_RE
        bad = len(host) > 253 or not host_ok.fullmatch(host)
    if bad:
        raise ValueError(
            f"RECON_TARGET_HEALTH_REPORTER_URL {raw!r} must be http(s)://host[:port][/path] "
            "using letters, digits, '.', '-' and '/'"
        )
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"
    rebuilt = f"{parts.scheme}://{netloc}{parts.path}"
    if raw != rebuilt:
        raise ValueError(
            f"RECON_TARGET_HEALTH_REPORTER_URL {raw!r} is not in canonical form; write it as "
            f"{rebuilt!r}"
        )
    return rebuilt


def _reporter_settings() -> tuple[str, Path]:
    """Validate the control-plane escalation reporter the contained gateway must carry.

    Without both settings an RoE trip would block the target but never stop the engagement, so
    the engagement refuses to start. There is no opt-out.
    """
    url = os.environ.get("RECON_TARGET_HEALTH_REPORTER_URL", "")
    token_path = os.environ.get("RECON_TARGET_HEALTH_REPORTER_TOKEN_FILE", "").strip()
    missing = [
        name
        for name, value in (
            ("RECON_TARGET_HEALTH_REPORTER_URL", url),
            ("RECON_TARGET_HEALTH_REPORTER_TOKEN_FILE", token_path),
        )
        if not value.strip()
    ]
    if missing:
        raise ValueError(
            "contained docker backend requires the control-plane escalation reporter; "
            f"missing {', '.join(missing)}"
        )
    url = _canonical_reporter_url(url)
    token_file = Path(token_path)
    try:
        token_stat = token_file.stat()
    except OSError as exc:
        raise ValueError(
            f"RECON_TARGET_HEALTH_REPORTER_TOKEN_FILE {token_path!r} is not a readable file: {exc}"
        ) from exc
    if not S_ISREG(token_stat.st_mode):
        raise ValueError(
            f"RECON_TARGET_HEALTH_REPORTER_TOKEN_FILE {token_path!r} is not a regular file"
        )
    # Same rule as the signed spec: this is a bearer credential that can stop engagements.
    if token_stat.st_uid != os.geteuid() or S_IMODE(token_stat.st_mode) & 0o077:
        raise ValueError(
            f"RECON_TARGET_HEALTH_REPORTER_TOKEN_FILE {token_path!r} must be owned by the worker "
            "user and not accessible by group or other"
        )
    try:
        # Raw bytes, so CRLF is not translated. Exactly one trailing LF is dropped, as `$(cat file)`
        # does for the control plane's copy; a CR or any other whitespace is rejected below.
        token = token_file.read_bytes().decode("utf-8").removesuffix("\n")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(
            f"RECON_TARGET_HEALTH_REPORTER_TOKEN_FILE {token_path!r} is not a readable file: {exc}"
        ) from exc
    # The control plane rejects gateway credentials under 32 bytes, so a shorter token would
    # only fail after a trip, when the emergency stop can no longer be delivered.
    if not (token.isascii() and token.isprintable() and " " not in token):
        raise ValueError(
            f"RECON_TARGET_HEALTH_REPORTER_TOKEN_FILE {token_path!r} must hold one line of "
            "printable ASCII with no spaces (it is sent as an Authorization header)"
        )
    if len(token.encode()) < _REPORTER_TOKEN_MIN_BYTES:
        raise ValueError(
            f"RECON_TARGET_HEALTH_REPORTER_TOKEN_FILE {token_path!r} holds fewer than "
            f"{_REPORTER_TOKEN_MIN_BYTES} bytes"
        )
    return url, token_file.resolve()


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

    # Checked before any Docker resource exists (fail-closed).
    reporter_url, reporter_token_host = _reporter_settings()

    dc = docker.from_env()
    host_isolation.require_isolated_gateway_support(dc)
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
            options=host_isolation.isolated_options(),
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
    try:
        host_isolation.require_isolated_network(net_attrs, net_name)
    except RuntimeError:
        if network_created:
            with _suppress():
                internal_net.remove()
        raise
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
        str(reporter_token_host): {"bind": _REPORTER_TOKEN_MOUNT, "mode": "ro"},
    }
    # Gateway capture (Plan Phase 4): when enabled, give the gateway a SESSION-DERIVED capability
    # token + scan id so it runs the redacted capture store + retrieval API and publishes the
    # /ca/recon-capture-ready marker the agent-path readiness gate checks before sending traffic.
    gateway_env = {
        "RECON_MODEL_HOSTS": os.environ.get("RECON_MODEL_HOSTS", ""),
        "RECON_PENTEST_SUPPORT_HOSTS": os.environ.get("RECON_PENTEST_SUPPORT_HOSTS", ""),
        # entrypoint resolves/binds the internal-net address before the
        # outbound NIC is attached, so egress-network peers cannot proxy.
        "RECON_PROXY_INTERNAL_ONLY": "1",
        "RECON_TARGET_HEALTH_REPORTER_URL": reporter_url,
        "RECON_TARGET_HEALTH_REPORTER_TOKEN_FILE": _REPORTER_TOKEN_MOUNT,
    }
    capture_enabled = os.environ.get("RECON_GATEWAY_CAPTURE", "").strip().lower() in ("1", "true", "yes")
    if capture_enabled:
        # The token helper lives with the Recon wrapper's Kubernetes backend,
        # which shares it; this path only runs inside the Recon engine.
        from recon_engine.backends.capture_token import capture_capability_token

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

    try:
        token_readable = _gateway_can_read_token(gw)
    except BaseException:
        _cleanup_boundary(gw)
        raise
    if not token_readable:
        _cleanup_boundary(gw)
        raise RuntimeError(
            f"egress gateway {gw_name} cannot read the escalation token at "
            f"{_REPORTER_TOKEN_MOUNT}; refusing to start the agent (fail-closed). The token "
            "file must be readable by the gateway's user"
        )

    # The gateway is still on the internal network alone: prove it cannot reach the host before
    # the outbound NIC goes on and before the agent exists.
    try:
        internal_net.reload()
        host_isolation.check_host_unreachable(gw, internal_net.attrs)
    except BaseException:
        _cleanup_boundary(gw)
        raise

    # Practice targets live on their own isolated network that only the gateway joins. Verify it
    # and probe the host from it before the gateway reaches the targets.
    targets_net_name = os.environ.get("RECON_TARGETS_NETWORK", "").strip()
    if targets_net_name:
        try:
            targets_net = dc.networks.get(targets_net_name)
            targets_net.reload()
            host_isolation.require_isolated_network(targets_net.attrs, targets_net_name)
            targets_net.connect(gw)
            targets_net.reload()
            host_isolation.check_host_unreachable(gw, targets_net.attrs)
        except BaseException as exc:
            _cleanup_boundary(gw)
            if isinstance(exc, RuntimeError):
                raise
            raise RuntimeError(
                f"targets network {targets_net_name!r} could not be verified and joined"
            ) from exc

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
    client.strix_bind_mounts = bind_mounts or []
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



def _gateway_can_read_token(gateway: Any) -> bool:
    """The gateway runs as an unprivileged user, so a private host file can mount yet be unreadable.

    Readiness never opens the token, and the failure would surface only after a trip.
    """
    code, _out = gateway.exec_run(["head", "-c", "1", _REPORTER_TOKEN_MOUNT])
    return code == 0


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

_BIND_MOUNT_BACKENDS: set[str] = {"docker", "docker-contained"}


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


def register_backend(
    name: str,
    backend: SandboxBackend,
    *,
    supports_bind_mounts: bool = False,
) -> None:
    """Register a custom backend under ``name``.

    Intended for downstream users who ship their own runtime — register
    before any ``session_manager.create_or_reuse`` call. Re-registering
    an existing name overwrites the prior entry. ``supports_bind_mounts``
    defaults to False: a remote runtime cannot see the caller's filesystem, so
    it is handed local sources as manifest entries to upload instead.
    """
    _BACKENDS[name] = backend
    if supports_bind_mounts:
        _BIND_MOUNT_BACKENDS.add(name)
    else:
        _BIND_MOUNT_BACKENDS.discard(name)
    logger.info("Registered sandbox backend: %s (bind mounts: %s)", name, supports_bind_mounts)


def backend_supports_bind_mounts(name: str) -> bool:
    return name in _BIND_MOUNT_BACKENDS


def supported_backends() -> list[str]:
    return sorted(_BACKENDS)
