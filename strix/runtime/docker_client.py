# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""StrixDockerSandboxClient — preserves the image's ENTRYPOINT and adds
NET_ADMIN/NET_RAW capabilities + host-gateway.

The SDK's ``DockerSandboxClient._create_container`` does not expose a hook for
extending ``create_kwargs`` before ``containers.create`` is called. We subclass
and reimplement the method body verbatim from the SDK source, with three
deltas:

1. Drop the SDK's ``entrypoint=["tail"]`` override; supply ``["tail", "-f",
   "/dev/null"]`` as ``command`` instead. This lets our image's
   ``docker-entrypoint.sh`` actually run — without it, ``caido-cli`` never
   starts inside the container and ``bootstrap_caido`` retries against a
   dead port.
2. Append NET_ADMIN/NET_RAW to ``cap_add`` (required by ``nmap -sS`` and
   other raw-socket tools).
3. Add ``host.docker.internal`` → host-gateway to ``extra_hosts`` so the
   agent can reach host-served apps.

Recon's contained-egress mode replaces deltas 2 and 3: the agent joins an
internal-only network, drops the network and escape capabilities, and gets no
host route.

Pinned to ``openai-agents==0.14.6``. Bumping the SDK requires
re-merging the parent body. Track upstream for an injection hook.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import time
import uuid
from typing import Any, cast

from agents.sandbox.errors import ExposedPortUnavailableError
from agents.sandbox.manifest import Manifest
from agents.sandbox.sandboxes.docker import (
    DockerSandboxClient,
    DockerSandboxSession,
    _build_docker_volume_mounts,
    _docker_port_key,
    _manifest_requires_fuse,
    _manifest_requires_sys_admin,
)
from agents.sandbox.session.sandbox_session import SandboxSession
from agents.sandbox.types import ExecResult, ExposedPortEndpoint
from docker import errors as docker_errors  # type: ignore[import-untyped, unused-ignore]
from docker.models.containers import Container  # type: ignore[import-untyped, unused-ignore]
from docker.types import LogConfig  # type: ignore[import-untyped, unused-ignore]
from docker.types import Mount as DockerSDKMount  # type: ignore[import-untyped, unused-ignore]
from docker.utils import parse_repository_tag  # type: ignore[import-untyped, unused-ignore]
from requests.exceptions import RequestException


logger = logging.getLogger(__name__)

# A hard ceiling on any sandbox container's life (seconds), enforced by the independent
# reaper via the recon.ttl_deadline label — a container orphaned by a crashed engine or a
# wedged workflow is torn down at this deadline no matter what. Default 4h.
_DEFAULT_SANDBOX_TTL_SEC = 14400


def _sandbox_ttl_sec() -> int:
    raw = (os.environ.get("RECON_SANDBOX_MAX_TTL_SEC") or "").strip()
    if raw.isdigit() and int(raw) > 0:
        return int(raw)
    return _DEFAULT_SANDBOX_TTL_SEC


# Public alias for downstream (wrapper) consumers.
sandbox_ttl_sec = _sandbox_ttl_sec


_SANDBOX_NETWORK_ENV = "STRIX_DOCKER_SANDBOX_NETWORK"


def _sandbox_network() -> str | None:
    value = os.environ.get(_SANDBOX_NETWORK_ENV, "").strip()
    return value or None


def _apply_sandbox_network(create_kwargs: dict[str, Any]) -> None:
    network = _sandbox_network()
    if network:
        create_kwargs["network"] = network
        create_kwargs.pop("ports", None)


_SANDBOX_DEVICES_ENV = "STRIX_DOCKER_SANDBOX_DEVICES"


def _sandbox_devices() -> list[str]:
    raw = os.environ.get(_SANDBOX_DEVICES_ENV, "")
    return [item.strip() for item in raw.split(",") if item.strip()]


def _apply_sandbox_devices(create_kwargs: dict[str, Any]) -> None:
    """Pass the host devices listed in ``STRIX_DOCKER_SANDBOX_DEVICES`` through.

    Comma-separated device paths, each mapped to the same path in the container
    with ``rwm`` access. A tunnel brought up inside the sandbox (OpenVPN,
    Tailscale) needs ``/dev/net/tun``: Docker's default device cgroup denies it
    even with ``NET_ADMIN``. Unset means no extra devices.
    """
    devices = _sandbox_devices()
    if not devices:
        return
    existing = [str(item) for item in (create_kwargs.get("devices") or [])]
    for path in devices:
        spec = f"{path}:{path}:rwm"
        if spec not in existing and path not in existing:
            existing.append(spec)
    create_kwargs["devices"] = existing


def _apply_resource_limits(create_kwargs: dict[str, Any]) -> None:
    """Apply optional cgroup resource caps from the environment. Unset/blank
    values leave docker's default (unbounded), so this is opt-in per host."""
    mem_limit = os.environ.get("STRIX_SANDBOX_MEM_LIMIT", "").strip()
    if mem_limit:
        create_kwargs["mem_limit"] = mem_limit

    shm_size = os.environ.get("STRIX_SANDBOX_SHM_SIZE", "").strip()
    if shm_size:
        create_kwargs["shm_size"] = shm_size

    cpus = os.environ.get("STRIX_SANDBOX_CPUS", "").strip()
    if cpus:
        with contextlib.suppress(ValueError, OverflowError):
            nano_cpus = int(float(cpus) * 1_000_000_000)
            if 0 < nano_cpus <= 2**63 - 1:
                create_kwargs["nano_cpus"] = nano_cpus

    pids_limit = os.environ.get("STRIX_SANDBOX_PIDS_LIMIT", "").strip()
    if pids_limit:
        with contextlib.suppress(ValueError):
            create_kwargs["pids_limit"] = int(pids_limit)


def _apply_log_limits(create_kwargs: dict[str, Any]) -> None:
    """Bound the container's json-file log so a runaway process in the sandbox
    (e.g. a tool that busy-loops writing to stdout) cannot fill the host disk
    and take the Docker daemon down with it.

    Unlike the cgroup caps above, this defaults **on** — docker's own default
    is an unbounded json-file, which is unsafe for an autonomous agent that
    executes arbitrary commands. ``max-file`` rotation means the on-disk cap is
    ``max-size * max-file``. Set ``STRIX_SANDBOX_LOG_MAX_SIZE`` to ``0``/``off``
    to opt back out to docker's default."""
    max_size = os.environ.get("STRIX_SANDBOX_LOG_MAX_SIZE", "50m").strip()
    if max_size.lower() in ("0", "off", "none", "unlimited"):
        return
    max_file = os.environ.get("STRIX_SANDBOX_LOG_MAX_FILE", "3").strip() or "3"
    create_kwargs["log_config"] = LogConfig(
        type=LogConfig.types.JSON,
        config={"max-size": max_size, "max-file": max_file},
    )


def _apply_run_labels(create_kwargs: dict[str, Any]) -> None:
    run_id = os.getenv("STRIX_RUN_ID")
    if not run_id:
        return
    labels = create_kwargs.setdefault("labels", {})
    if not isinstance(labels, dict):
        return
    labels["strix-run-id"] = run_id
    run_type = os.getenv("STRIX_RUN_TYPE")
    if run_type:
        labels["strix-run-type"] = run_type


class StrixDockerSandboxSession(DockerSandboxSession):
    sandbox_network: str = ""

    async def _resolve_exposed_port(self, port: int) -> ExposedPortEndpoint:
        try:
            self._container.reload()
        except docker_errors.APIError as e:
            raise ExposedPortUnavailableError(
                port=port,
                exposed_ports=self.state.exposed_ports,
                reason="backend_unavailable",
                context={
                    "backend": "docker",
                    "detail": "container_reload_failed",
                    "network": self.sandbox_network,
                },
                cause=e,
            ) from e

        attrs = getattr(self._container, "attrs", {}) or {}
        networks = attrs.get("NetworkSettings", {}).get("Networks", {})
        endpoint = networks.get(self.sandbox_network) or {}
        ip = endpoint.get("IPAddress") or endpoint.get("GlobalIPv6Address")
        if not isinstance(ip, str) or not ip:
            raise ExposedPortUnavailableError(
                port=port,
                exposed_ports=self.state.exposed_ports,
                reason="backend_unavailable",
                context={
                    "backend": "docker",
                    "detail": "container_not_on_network",
                    "network": self.sandbox_network,
                },
            )
        host = f"[{ip}]" if ":" in ip else ip
        return ExposedPortEndpoint(host=host, port=port, tls=False)


class StrixDockerSandboxClient(DockerSandboxClient):
    # Host directories to bind-mount into the container, set by the docker
    # backend before ``create()``. Each item is ``{source, target, read_only}``.
    strix_bind_mounts: list[dict[str, Any]] | None = None
    # Contained-egress mode (P0-2): when True, the agent container joins recon_network (internal
    # only), drops the network and escape caps, and gets no host-gateway route. Set per-instance
    # by the contained docker backend. Default False keeps the uncontained path unchanged.
    recon_contained: bool = False
    recon_network: str = ""
    recon_gateway_container: Any | None = None
    recon_internal_network: Any | None = None
    recon_gateway_ca_volume: Any | None = None

    async def _create_container(  # noqa: PLR0912, PLR0915
        self,
        image: str,
        *,
        manifest: Manifest | None = None,
        exposed_ports: tuple[int, ...] = (),
        session_id: uuid.UUID | None = None,
    ) -> Container:
        # ----- BEGIN VERBATIM COPY of DockerSandboxClient._create_container -----
        # SDK ref: src/agents/sandbox/sandboxes/docker.py:1434-1477 (v0.14.6).
        if not self.image_exists(image):
            repo, tag = parse_repository_tag(image)
            self.docker_client.images.pull(repo, tag=tag or None, all_tags=False)

        assert self.image_exists(image)
        environment: dict[str, str] | None = None
        if manifest:
            environment = await manifest.environment.resolve()
        # Delta from the SDK body: drop ``entrypoint`` override and
        # supply ``tail -f /dev/null`` as ``command`` so the image's
        # ENTRYPOINT (``docker-entrypoint.sh``) runs setup, then ``exec
        # "$@"`` becomes ``exec tail -f /dev/null`` for the keep-alive.
        # Without this, caido-cli + the in-container CA trust never get
        # initialized.
        create_kwargs: dict[str, Any] = {
            "image": image,
            "detach": True,
            "command": ["tail", "-f", "/dev/null"],
            "environment": environment,
        }
        if manifest is not None:
            docker_mounts = _build_docker_volume_mounts(
                manifest,
                session_id=session_id,
            )
            if docker_mounts:
                create_kwargs["mounts"] = docker_mounts
            if _manifest_requires_fuse(manifest):
                create_kwargs.update(
                    devices=["/dev/fuse"],
                    cap_add=["SYS_ADMIN"],
                    security_opt=["apparmor:unconfined"],
                )
            elif _manifest_requires_sys_admin(manifest):
                create_kwargs.update(
                    cap_add=["SYS_ADMIN"],
                    security_opt=["apparmor:unconfined"],
                )
        if exposed_ports:
            create_kwargs["ports"] = {
                _docker_port_key(port): ("127.0.0.1", None) for port in exposed_ports
            }
        # ----- END VERBATIM COPY -----

        contained = bool(getattr(self, "recon_contained", False))
        if contained:
            # CONTAINED egress mode (P0-2, docs/SPEC-sandbox-containment.md). The agent joins an
            # INTERNAL-only Docker network whose only reachable peer is the egress-gateway
            # container; it has no egress NIC of its own. Drop the network and escape capability
            # vectors (NET_ADMIN reconfigures routes, NET_RAW crafts packets that ignore the
            # proxy, SYS_ADMIN is an escape primitive) and any add-back such as FUSE's SYS_ADMIN.
            # cap_drop=ALL and no-new-privileges would break the image entrypoint's sudo; the real
            # boundary is the own-netns, the caps are defense in depth.
            if getattr(self, "recon_network", ""):
                create_kwargs["network"] = self.recon_network
            create_kwargs.pop("cap_add", None)
            create_kwargs["cap_drop"] = ["NET_ADMIN", "NET_RAW", "SYS_ADMIN"]
            # No host.docker.internal: the agent gets no route to the host.
            # The operator network and device overrides would both widen the
            # boundary, so the contained path never honours them.
            for env_name in (_SANDBOX_NETWORK_ENV, _SANDBOX_DEVICES_ENV):
                if os.environ.get(env_name, "").strip():
                    logger.warning("%s is ignored for a contained sandbox", env_name)
        else:
            # Append, don't overwrite, so FUSE/SYS_ADMIN survives.
            cap_add = create_kwargs.setdefault("cap_add", [])
            if not isinstance(cap_add, list):
                cap_add = list(cap_add)
                create_kwargs["cap_add"] = cap_add
            for cap in ("NET_ADMIN", "NET_RAW"):
                if cap not in cap_add:
                    cap_add.append(cap)

            extra_hosts = create_kwargs.setdefault("extra_hosts", {})
            extra_hosts["host.docker.internal"] = "host-gateway"

            _apply_sandbox_network(create_kwargs)
            _apply_sandbox_devices(create_kwargs)

        _apply_resource_limits(create_kwargs)
        _apply_log_limits(create_kwargs)
        _apply_run_labels(create_kwargs)

        # Local source trees, sorted shallowest-first so a nested spec lands on
        # top of the tree it covers. Read-only unless the spec says otherwise.
        bind_mounts = self.strix_bind_mounts or ()
        if bind_mounts:
            mounts = create_kwargs.setdefault("mounts", [])
            for spec in sorted(bind_mounts, key=lambda s: str(s["target"]).count("/")):
                mounts.append(
                    DockerSDKMount(
                        target=spec["target"],
                        source=spec["source"],
                        type="bind",
                        read_only=spec.get("read_only", True),
                    )
                )

        if contained:
            ca_volume = getattr(self, "recon_gateway_ca_volume", None)
            ca_name = getattr(ca_volume, "name", "") if ca_volume is not None else ""
            if not ca_name:
                raise RuntimeError("contained sandbox requires the per-run gateway CA volume")
            mounts = create_kwargs.setdefault("mounts", [])
            mounts.append(
                DockerSDKMount(
                    target="/recon-ca",
                    source=ca_name,
                    type="volume",
                    read_only=True,
                )
            )

        # Self-describing lifecycle labels so an INDEPENDENT reaper can find and tear down a
        # container orphaned by an engine crash or a wedged workflow. recon.ttl_deadline is a
        # HARD ceiling on the container's life, independent of any workflow; recon.scan_id lets
        # a targeted reap / credential purge find the engagement.
        now = int(time.time())
        labels = create_kwargs.setdefault("labels", {})
        if isinstance(labels, dict):
            labels.update(
                {
                    "recon.sandbox": "true",
                    "recon.scan_id": str(getattr(self, "recon_scan_id", "") or ""),
                    "recon.created_at": str(now),
                    "recon.ttl_deadline": str(now + _sandbox_ttl_sec()),
                    # Host path to the run's heartbeat file. The reaper keeps any container whose
                    # heartbeat is fresh and reaps promptly once it goes stale. Empty => the
                    # reaper falls back to the ttl_deadline hard ceiling.
                    "recon.heartbeat_path": str(getattr(self, "recon_heartbeat_path", "") or ""),
                }
            )
            if contained:
                labels.update({"recon.owner": "contained-egress", "recon.role": "agent"})

        logger.debug(
            "Creating sandbox container: image=%s cap_add=%s cap_drop=%s network=%s "
            "exposed_ports=%s",
            image,
            create_kwargs.get("cap_add"),
            create_kwargs.get("cap_drop"),
            create_kwargs.get("network"),
            list(exposed_ports),
        )
        container = self.docker_client.containers.create(**create_kwargs)
        logger.info(
            "Sandbox container created: id=%s image=%s",
            container.short_id if hasattr(container, "short_id") else "?",
            image,
        )
        return container

    async def create(self, **kwargs: Any) -> SandboxSession:
        session = await super().create(**kwargs)
        network = None if getattr(self, "recon_contained", False) else _sandbox_network()
        inner = session._inner
        if network and isinstance(inner, DockerSandboxSession):
            inner.__class__ = StrixDockerSandboxSession
            cast("StrixDockerSandboxSession", inner).sandbox_network = network
        return session

    def gateway_capture_client(self) -> Any:
        """Reuse the shared :class:`GatewayCaptureClient` for the contained docker gateway.

        The Docker path reuses the capture-reading client the Kubernetes path uses; only the
        transport differs: a ``docker exec`` into this session's gateway container instead of a
        Kubernetes API-server exec into the gateway pod. The exec'd retrieval script reads the
        capability token from the gateway container's own env, so no secret crosses an argv.
        Returns None when no gateway container is paired with this client.
        """
        gateway = getattr(self, "recon_gateway_container", None)
        if gateway is None:
            return None
        # The client lives with the Recon wrapper's Kubernetes backend, which
        # shares it; this path only runs inside the Recon engine.
        from recon_engine.backends.gateway_capture_client import (  # noqa: PLC0415
            GatewayCaptureClient,
        )

        async def _exec(
            *,
            pod_name: str,
            container_name: str,
            command: Any,
            timeout: float | None = None,
            stdin_data: bytes | None = None,
        ) -> ExecResult:
            # pod_name / container_name are ignored: we hold the gateway Container handle.
            del pod_name, container_name
            # The retrieval script is argv+env only. docker-py's non-stream exec_run cannot take
            # stdin, so fail loudly rather than silently drop it.
            if stdin_data is not None:
                raise NotImplementedError(
                    "docker gateway_capture_client._exec does not support stdin_data; the capture "
                    "retrieval script is argv+env only"
                )
            try:
                # demux keeps stderr out of the JSON body. exec_run blocks and has no native
                # timeout, so honour the caller's timeout around a worker thread.
                coro = asyncio.to_thread(gateway.exec_run, command, demux=True, stdin=False)
                exit_code, output = await asyncio.wait_for(coro, timeout=timeout)
            except TimeoutError as exc:
                raise TimeoutError(f"docker exec timed out after {timeout}s") from exc
            except Exception as exc:  # noqa: BLE001 - degrade (no evidence), never crash a finding
                return ExecResult(
                    stdout=b"", stderr=str(exc).encode("utf-8", "replace"), exit_code=1
                )
            if isinstance(output, tuple):
                out_bytes, err_bytes = output
            else:
                out_bytes, err_bytes = output, b""
            out_bytes = out_bytes or b""
            err_bytes = err_bytes or b""
            if isinstance(out_bytes, str):
                out_bytes = out_bytes.encode("utf-8", "replace")
            if isinstance(err_bytes, str):
                err_bytes = err_bytes.encode("utf-8", "replace")
            # Same shape as the Kubernetes exec, so GatewayCaptureClient is transport-agnostic.
            return ExecResult(stdout=bytes(out_bytes), stderr=bytes(err_bytes), exit_code=exit_code)

        gateway_pod = getattr(gateway, "name", "") or "recon-egress"
        return GatewayCaptureClient(_exec, gateway_pod=gateway_pod)

    async def delete(self, session: SandboxSession) -> SandboxSession:
        container_id = getattr(getattr(session._inner, "state", None), "container_id", None)
        if container_id:
            # Best-effort kill: NotFound/APIError cover a gone or unhappy
            # container. RequestException covers a torn-down daemon socket —
            # containers.get() -> inspect_container raises requests'
            # ConnectionError, which is a sibling of docker.errors.APIError
            # under requests.RequestException (not a subclass), so it escapes
            # an APIError-only suppress and surfaces a full traceback even
            # though this teardown is meant to be best-effort.
            with contextlib.suppress(
                docker_errors.NotFound, docker_errors.APIError, RequestException
            ):
                self.docker_client.containers.get(container_id).kill()
        try:
            return await super().delete(session)
        finally:
            gateway = getattr(self, "recon_gateway_container", None)
            if gateway is not None:
                with contextlib.suppress(Exception):
                    gateway.remove(force=True)
            ca_volume = getattr(self, "recon_gateway_ca_volume", None)
            if ca_volume is not None:
                with contextlib.suppress(Exception):
                    ca_volume.remove(force=True)
            network = getattr(self, "recon_internal_network", None)
            if network is not None:
                with contextlib.suppress(Exception):
                    network.remove()


# The Recon wrapper and its tests use this name.
ReconDockerSandboxClient = StrixDockerSandboxClient
