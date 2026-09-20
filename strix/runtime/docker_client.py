# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""ReconDockerSandboxClient — preserves the image's ENTRYPOINT and adds
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

Pinned to ``openai-agents==0.14.6``. Bumping the SDK requires
re-merging the parent body. Track upstream for an injection hook.
"""

from __future__ import annotations

import contextlib
import logging
import os
import time
import uuid
from typing import Any

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
from agents.sandbox.manifest import Manifest
from agents.sandbox.sandboxes.docker import (
    DockerSandboxClient,
    _build_docker_volume_mounts,
    _docker_port_key,
    _manifest_requires_fuse,
    _manifest_requires_sys_admin,
)
from agents.sandbox.session.sandbox_session import SandboxSession
from agents.sandbox.types import ExecResult
from docker import errors as docker_errors  # type: ignore[import-untyped, unused-ignore]
from docker.models.containers import Container  # type: ignore[import-untyped, unused-ignore]
from docker.types import Mount as DockerSDKMount  # type: ignore[import-untyped, unused-ignore]
from docker.utils import parse_repository_tag  # type: ignore[import-untyped, unused-ignore]


logger = logging.getLogger(__name__)


class ReconDockerSandboxClient(DockerSandboxClient):
    # Host directories to bind-mount into the container, set by the docker
    # backend before ``create()``. Each item is ``{source, target, read_only}``.
    recon_bind_mounts: list[dict[str, Any]] = []  # overridden per-instance in backends.py
    # Contained-egress mode (P0-2): when True, the agent container joins recon_network (internal
    # only), drops ALL caps, and gets no host-gateway route. Set per-instance by the contained
    # docker backend. Default False keeps the legacy uncontained path byte-for-byte unchanged.
    recon_contained: bool = False
    recon_network: str = ""
    recon_gateway_container: Any | None = None
    recon_internal_network: Any | None = None
    recon_gateway_ca_volume: Any | None = None

    async def _create_container(
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
        # Recon delta from the SDK body: drop ``entrypoint`` override and
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

        # CONTAINED egress mode (P0-2, docs/SPEC-sandbox-containment.md, opt-in via
        # recon_contained / RECON_CONTAINED_EGRESS). The agent joins an INTERNAL-only Docker
        # network whose only reachable peer is the egress-gateway container - it has no egress NIC
        # of its own (own-netns). We therefore DROP all caps (no NET_ADMIN/NET_RAW to reconfigure
        # routes or craft raw packets) and DO NOT add the host-gateway route. This is the local
        # Phase-1 analogue of the K8s NetworkPolicy + Pod securityContext (internal/sandboxnet).
        if getattr(self, "recon_contained", False):
            if getattr(self, "recon_network", ""):
                create_kwargs["network"] = self.recon_network
            # Drop the NETWORK + ESCAPE capability vectors (NET_ADMIN reconfigures routes, NET_RAW
            # crafts packets that ignore the proxy, SYS_ADMIN is an escape primitive) and remove any
            # add-back (e.g. FUSE's SYS_ADMIN). We do NOT cap_drop=ALL or set no-new-privileges here:
            # the Strix sandbox image's entrypoint needs sudo (setuid) at startup, and those would
            # break it. The REAL egress boundary is the own-netns (internal network, no egress NIC),
            # not the caps - the caps are defense-in-depth against route/raw/escape, and keeping
            # SETUID/SETGID for in-container sudo does not affect network containment. (A fully
            # unprivileged image - cap_drop=ALL + no-new-privileges + non-root - needs the entrypoint
            # re-worked to not use sudo; tracked as follow-on hardening.)
            create_kwargs.pop("cap_add", None)
            create_kwargs["cap_drop"] = ["NET_ADMIN", "NET_RAW", "SYS_ADMIN"]
            # No host.docker.internal: the agent gets no route to the host (kills that bypass).
        else:
            # Legacy (uncontained) path — unchanged. Recon injections append, don't overwrite, so
            # FUSE/SYS_ADMIN survives.
            cap_add = create_kwargs.setdefault("cap_add", [])
            if not isinstance(cap_add, list):
                cap_add = list(cap_add)
                create_kwargs["cap_add"] = cap_add
            for cap in ("NET_ADMIN", "NET_RAW"):
                if cap not in cap_add:
                    cap_add.append(cap)

            extra_hosts = create_kwargs.setdefault("extra_hosts", {})
            extra_hosts["host.docker.internal"] = "host-gateway"

        # Recon injection: host bind mounts (e.g. large repos passed via --mount)
        # that bypass the SDK's file-by-file LocalDir copy.
        bind_mounts = getattr(self, "recon_bind_mounts", ())
        if bind_mounts:
            mounts = create_kwargs.setdefault("mounts", [])
            for spec in bind_mounts:
                mounts.append(
                    DockerSDKMount(
                        target=spec["target"],
                        source=spec["source"],
                        type="bind",
                        read_only=spec.get("read_only", True),
                    )
                )

        if getattr(self, "recon_contained", False):
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

        # Recon injection: self-describing lifecycle labels so an INDEPENDENT reaper can find
        # and tear down a container orphaned by an engine crash or a wedged workflow (both
        # in-process cleanup_on_exit AND the workflow's CleanupSandbox fail in that case).
        # recon.ttl_deadline is a HARD ceiling on the container's life, independent of any
        # workflow; recon.scan_id lets a targeted reap / credential purge find the engagement.
        now = int(time.time())
        labels = create_kwargs.setdefault("labels", {})
        if isinstance(labels, dict):
            labels.update(
                {
                    "recon.sandbox": "true",
                    "recon.scan_id": str(getattr(self, "recon_scan_id", "") or ""),
                    "recon.created_at": str(now),
                    "recon.ttl_deadline": str(now + _sandbox_ttl_sec()),
                    # Host path to the run's heartbeat file. The engine touches it while alive;
                    # the reaper KEEPS any container whose heartbeat is fresh (never kills a live
                    # scan) and reaps promptly once it goes stale (dead engine). Empty => reaper
                    # falls back to the ttl_deadline hard ceiling.
                    "recon.heartbeat_path": str(
                        getattr(self, "recon_heartbeat_path", "") or ""
                    ),
                }
            )
            if getattr(self, "recon_contained", False):
                labels.update(
                    {
                        "recon.owner": "contained-egress",
                        "recon.role": "agent",
                    }
                )

        logger.debug(
            "Creating sandbox container: image=%s cap_add=%s cap_drop=%s network=%s exposed_ports=%s",
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

    def gateway_capture_client(self) -> Any:
        """Reuse the shared :class:`GatewayCaptureClient` for the contained docker gateway.

        The Docker execution adapter deliberately REUSES the same capture-reading client the
        Kubernetes path uses (no parallel implementation): the only transport difference is the
        ``exec_fn`` - here a ``docker exec`` into this session's gateway container, instead of a
        Kubernetes API-server exec into the gateway pod. The exec'd retrieval script is identical
        (it reads the capability token from the gateway container's OWN env, so no secret crosses an
        argv). Returns None when no gateway container is paired with this client."""
        gateway = getattr(self, "recon_gateway_container", None)
        if gateway is None:
            return None
        from strix.tools.proxy.gateway_capture_client import GatewayCaptureClient

        async def _exec(*, pod_name: str, container_name: str, command, timeout=None, stdin_data=None):
            # ``pod_name`` is the gateway container name (ignored - we hold the Container handle);
            # ``container_name`` is "gateway" (ignored). Run the script inside the gateway container.
            #
            # The capture retrieval script reads its capability token from the gateway container's
            # OWN env and calls the loopback control API - it is argv+env only and never sends stdin.
            # docker-py's non-stream ``exec_run`` cannot accept stdin bytes, so rather than silently
            # dropping ``stdin_data`` we fail loudly if a caller ever passes it (honest fail-closed).
            if stdin_data is not None:
                raise NotImplementedError(
                    "docker gateway_capture_client._exec does not support stdin_data; the capture "
                    "retrieval script is argv+env only"
                )
            import asyncio

            try:
                # demux=True returns (stdout, stderr) separately so stderr can never corrupt the
                # JSON body read from the loopback control API. Honor the caller's timeout via
                # asyncio.wait_for around a to_thread call (docker-py's exec_run is blocking and has
                # no native timeout): on expiry raise TimeoutError, matching K8sSandboxClient._exec.
                coro = asyncio.to_thread(gateway.exec_run, command, demux=True, stdin=False)
                exit_code, output = await asyncio.wait_for(coro, timeout=timeout)
            except asyncio.TimeoutError as exc:
                raise TimeoutError(f"docker exec timed out after {timeout}s") from exc
            except Exception as exc:  # noqa: BLE001 - degrade (no evidence), never crash a finding
                return ExecResult(stdout=b"", stderr=str(exc).encode("utf-8", "replace"), exit_code=1)
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
            # Uniform shape: ExecResult(.ok()->bool, .stdout bytes, .stderr bytes, .exit_code int),
            # identical to K8sSandboxClient._exec so GatewayCaptureClient is transport-agnostic.
            # Success path returns ONLY stdout (stderr surfaced separately on .stderr), matching k8s.
            return ExecResult(
                stdout=bytes(out_bytes), stderr=bytes(err_bytes), exit_code=exit_code
            )

        return GatewayCaptureClient(_exec, gateway_pod=getattr(gateway, "name", "") or "recon-egress")

    async def delete(self, session: SandboxSession) -> SandboxSession:
        container_id = getattr(getattr(session._inner, "state", None), "container_id", None)
        if container_id:
            with contextlib.suppress(docker_errors.NotFound, docker_errors.APIError):
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
