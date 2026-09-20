# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""Per-scan sandbox session lifecycle."""

from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any

from agents.sandbox.entries import BaseEntry, LocalDir
from agents.sandbox.manifest import Environment, Manifest

from strix.config import load_settings
from strix.runtime.backends import effective_backend_name, get_backend
from strix.runtime.caido_bootstrap import bootstrap_caido


logger = logging.getLogger(__name__)


# In-container Caido sidecar port (matches the image's caido-cli bind).
_CONTAINER_CAIDO_PORT = 48080


_SESSION_CACHE: dict[str, dict[str, Any]] = {}

# Manifest root inside the container; entry keys hang off this path.
_WORKSPACE_ROOT = "/workspace"


def _normalize_gateway_target_ports(ports: Any) -> tuple[int, ...]:
    """Return a deduplicated, order-preserving tuple of validated port integers."""
    if not isinstance(ports, tuple):
        raise TypeError(f"gateway_target_ports must be a tuple, got {type(ports).__name__}")
    seen: dict[int, None] = {}
    for p in ports:
        if isinstance(p, bool):
            raise TypeError("gateway_target_ports values must be int, got bool")
        if not isinstance(p, int):
            raise TypeError(f"gateway_target_ports values must be int, got {type(p).__name__}")
        if not (1 <= p <= 65535):
            raise ValueError(f"gateway_target_ports value out of range 1..65535: {p}")
        seen[p] = None
    return tuple(seen)


def _compute_gateway_policy_fingerprint(
    *,
    gateway_spec_path: str,
    gateway_spec_json: str,
    normalized_ports: tuple[int, ...],
    backend_name: str,
) -> str:
    """Return a hex SHA-256 fingerprint over the gateway policy inputs.

    Exactly one of gateway_spec_path or gateway_spec_json may be non-empty.
    If path is given, its bytes are read and a missing file is a hard error.
    """
    if gateway_spec_path and gateway_spec_json:
        raise ValueError("Provide gateway_spec_path or gateway_spec_json, not both")
    if gateway_spec_path:
        p = Path(gateway_spec_path)
        if not p.exists():
            raise FileNotFoundError(f"gateway_spec_path not found: {gateway_spec_path}")
        spec_bytes = p.read_bytes()
    elif gateway_spec_json:
        spec_bytes = gateway_spec_json.encode()
    else:
        spec_bytes = b""
    h = hashlib.sha256()
    h.update(spec_bytes)
    h.update(b"\x00ports\x00")
    h.update(json.dumps(list(normalized_ports), separators=(",", ":")).encode())
    h.update(b"\x00backend\x00")
    h.update(backend_name.encode())
    return h.hexdigest()


def _recon_set_gateway_upstream(caido_url: str) -> None:
    """RECON FORK PATCH: tell the egress gateway (if fronting this run) to use
    this session's Caido as its upstream. No-op when RECON_EGRESS_CONTROL unset."""
    control = os.environ.get("RECON_EGRESS_CONTROL")
    if not control:
        return
    import json as _json
    import urllib.request as _url

    body = _json.dumps({"url": caido_url}).encode()
    req = _url.Request(
        f"{control}/upstream", data=body, method="PUT",
        headers={"Content-Type": "application/json"},
    )
    try:
        with _url.urlopen(req, timeout=3):  # noqa: S310 - localhost control endpoint
            logger.info("Recon: egress gateway upstream set to session Caido %s", caido_url)
    except OSError as exc:
        logger.warning("Recon: could not set egress gateway upstream via %s: %s", control, exc)


def build_session_entries(
    local_sources: list[dict[str, Any]],
) -> tuple[dict[str | Path, BaseEntry], list[dict[str, Any]]]:
    """Split local sources into copied manifest entries and host bind mounts.

    Sources flagged ``mount`` are bind-mounted read-only at
    ``/workspace/<workspace_subdir>`` (not added to the manifest, so the SDK
    does not stream them in file-by-file). Every other source becomes a
    ``LocalDir`` entry copied into the container as before.
    """
    entries: dict[str | Path, BaseEntry] = {}
    bind_mounts: list[dict[str, Any]] = []
    for src in local_sources:
        ws_subdir = src.get("workspace_subdir") or ""
        host_path = src.get("source_path") or ""
        if not ws_subdir or not host_path:
            continue
        resolved = Path(host_path).expanduser().resolve()
        if src.get("mount"):
            bind_mounts.append(
                {
                    "source": str(resolved),
                    "target": f"{_WORKSPACE_ROOT}/{ws_subdir}",
                    "read_only": True,
                }
            )
        else:
            entries[ws_subdir] = LocalDir(src=resolved)
    return entries, bind_mounts


async def create_or_reuse(
    scan_id: str,
    *,
    image: str,
    local_sources: list[dict[str, Any]],
    extra_env: dict[str, str] | None = None,
    heartbeat_path: str = "",
    gateway_spec_path: str = "",
    gateway_spec_json: str = "",
    gateway_target_ports: tuple[int, ...] = (),
) -> dict[str, Any]:
    """Return the existing session bundle for ``scan_id`` or create a new one.

    Each ``local_sources`` entry exposes its host ``source_path`` at
    ``/workspace/<workspace_subdir>`` inside the container — copied in, or
    bind-mounted read-only when the entry is flagged ``mount``.
    """
    normalized_ports = _normalize_gateway_target_ports(gateway_target_ports)
    backend_name = effective_backend_name(load_settings().runtime.backend)
    fingerprint = _compute_gateway_policy_fingerprint(
        gateway_spec_path=gateway_spec_path,
        gateway_spec_json=gateway_spec_json,
        normalized_ports=normalized_ports,
        backend_name=backend_name,
    )

    cached = _SESSION_CACHE.get(scan_id)
    if cached is not None:
        cached_fp = cached.get("_gateway_policy_fingerprint")
        if cached_fp != fingerprint:
            raise RuntimeError(
                f"scan {scan_id!r}: cached session has gateway policy fingerprint "
                f"{cached_fp!r} but caller supplied {fingerprint!r}; "
                "tear down the session before changing the gateway policy"
            )
        logger.info("Reusing existing sandbox session for scan %s", scan_id)
        return cached
    _is_k8s = backend_name in {"k8s", "k8s-contained"}
    # Docker materializes manifest LocalDir entries at session.start(); K8s does NOT — so give K8s no
    # source entries here (they'd be dead weight / a potential choke) and materialize the tree via the
    # hydrate step below instead. Docker keeps the native copy.
    entries, bind_mounts = build_session_entries([] if _is_k8s else local_sources)

    # Caido runs as an in-container sidecar; HTTP(S) traffic from any
    # process started via ``session.exec`` (the SDK's Shell tool, etc.)
    # picks up these env vars automatically. ``NO_PROXY`` keeps the
    # recon-browser CDP daemon's localhost traffic from looping back
    # through Caido.
    container_caido_url = f"http://127.0.0.1:{_CONTAINER_CAIDO_PORT}"
    # RECON FORK PATCH (P1, do-no-harm): when RECON_EGRESS_PROXY is set, route the
    # sandbox's egress through Recon's RoE-locked gateway instead of straight to
    # the in-container Caido. The gateway enforces the engagement scope + rate
    # below the agent (a prompt-injected agent cannot widen scope), and is
    # configured with Caido as its upstream so request/response capture is
    # preserved: sandbox -> gateway (scope+rate) -> Caido (capture) -> target.
    # Unset => stock upstream behaviour (proxy straight to Caido).
    sandbox_proxy = os.environ.get("RECON_EGRESS_PROXY", container_caido_url)
    # Contained-egress mode (P0-2): the agent's ONLY egress is the egress-gateway container, reached
    # by its deterministic name on the internal network (the contained backend brings it up first).
    # This overrides any RECON_EGRESS_PROXY - in contained mode the gateway IS the proxy. We also pass
    # RECON_EGRESS_UPSTREAM so the container entrypoint re-points its system proxy + browser at the
    # gateway (the entrypoint otherwise hardwires everything to the in-container Caido).
    contained = (
        os.environ.get("RECON_CONTAINED_EGRESS", "").strip().lower()
        in ("1", "true", "yes")
        or backend_name in {"docker-contained", "k8s", "k8s-contained"}
    )
    contained_env: dict[str, str] = {}
    if contained:
        sandbox_proxy = f"http://recon-egress-{scan_id or 'default'}:8888"
        contained_env["RECON_EGRESS_UPSTREAM"] = sandbox_proxy
    manifest = Manifest(
        entries=entries,
        environment=Environment(
            value={
                "PYTHONUNBUFFERED": "1",
                "HOST_GATEWAY": "host.docker.internal",
                "http_proxy": sandbox_proxy,
                "https_proxy": sandbox_proxy,
                "ALL_PROXY": sandbox_proxy,
                "NO_PROXY": "localhost,127.0.0.1",
                **contained_env,
                # #34: brokered secrets injected into the sandbox env (never the prompt/history).
                **{k: str(v) for k, v in (extra_env or {}).items()},
            },
        ),
    )

    backend = get_backend(backend_name)

    logger.info(
        "Creating sandbox session for scan %s (backend=%s, image=%s)",
        scan_id,
        backend_name,
        image,
    )
    client, session = await backend(
        image=image,
        manifest=manifest,
        # Contained mode: the agent is on an internal-only network (no host port exposure) and does
        # not use the in-container Caido as its egress, so don't ask the SDK to publish Caido's port.
        exposed_ports=() if contained else (_CONTAINER_CAIDO_PORT,),
        bind_mounts=bind_mounts,
        scan_id=scan_id,  # stamped onto the container labels for the independent reaper
        heartbeat_path=heartbeat_path,
        gateway_spec_path=gateway_spec_path,
        gateway_spec_json=gateway_spec_json,
        gateway_target_ports=normalized_ports,
    )

    # K8s has NO native source materialization: the Docker backends copy manifest LocalDir entries at
    # session.start(), but the K8s backend does not (k8s_client._validate_path_access: "V1 has no source
    # materialization"). So for a white-box K8s run, tar each declared source into /workspace/<subdir>
    # via the session's hydrate mechanism, so the agent AND the source-aware skills actually have the
    # tree. Best-effort: a copy failure must never break the run (the agent still has route/graphql/SAST
    # intel injected as text). Gated on RECON_MOUNT_SOURCE (default on).
    if (backend_name in {"k8s", "k8s-contained"} and local_sources
            and os.environ.get("RECON_MOUNT_SOURCE", "1") not in ("0", "false", "no")):
        import io as _io
        import tarfile as _tarfile

        def _skip_vcs(ti: "Any") -> "Any":
            if set(ti.name.split("/")) & {".git", "node_modules", "vendor", "__pycache__", ".venv", "dist"}:
                return None
            return ti

        for src in local_sources:
            ws = str(src.get("workspace_subdir") or "").strip()
            host = str(src.get("source_path") or "").strip()
            if not ws or not host:
                continue
            hp = Path(host).expanduser().resolve()
            if not hp.exists():
                logger.warning("source materialization: host path missing for %s: %s", ws, host)
                continue
            buf = _io.BytesIO()
            try:
                with _tarfile.open(fileobj=buf, mode="w") as tf:
                    tf.add(str(hp), arcname=ws, filter=_skip_vcs)  # arcname=<subdir> -> /workspace/<subdir>
                nbytes = buf.getbuffer().nbytes
                buf.seek(0)
                await session.hydrate_workspace(buf)
                logger.info("Materialized source into k8s pod: /workspace/%s (%d bytes)", ws, nbytes)
            except Exception:  # noqa: BLE001 - source copy is best-effort; the run continues either way
                logger.warning("source materialization failed for %s; continuing without mounted source",
                               ws, exc_info=True)

    if contained:
        # The in-container Caido is NOT the egress path in contained mode: the agent proxies straight
        # to the trusted gateway (which captures via mitmproxy, A2). The internal-only network means
        # Caido's port can't be host-resolved anyway. Skip the host-resolve + gateway-upstream +
        # bootstrap; the Caido agent-tools degrade gracefully (no client => _no_client()).
        caido_client = None
        # Gateway capture (Plan Phase 4): when enabled, retrieve REAL redacted wire evidence + the
        # traffic-derived coverage signal from the trusted egress gateway instead of relaxing to
        # agent-transcription. The client execs into the gateway's loopback control API. Best-effort:
        # any failure falls back to the transcription path (caido_client stays None).
        # The backend returns an INSTRUMENTATION-WRAPPED session; the raw K8sSandboxSession (which
        # carries the gateway pod name + exec) is exposed at `._inner` (see K8sSandboxClient.delete).
        _raw = getattr(session, "_inner", session)
        if os.environ.get("RECON_GATEWAY_CAPTURE", "").strip().lower() in ("1", "true", "yes"):
            _gwc = None
            # Kubernetes: the raw session exposes gateway_capture_client() (exec into the gateway pod).
            if hasattr(_raw, "gateway_capture_client"):
                _gwc = _raw.gateway_capture_client()
            # Docker-contained: the CLIENT (ReconDockerSandboxClient) reuses the same
            # GatewayCaptureClient via `docker exec` into this session's gateway container. This is
            # the SAME capture-reading client as K8s - no parallel implementation (blocker 6).
            elif hasattr(client, "gateway_capture_client"):
                _gwc = client.gateway_capture_client()
            if _gwc is not None:
                try:
                    caido_client = _gwc
                    from strix.tools.proxy import caido_api

                    caido_api.set_gateway_client(_gwc)
                    logger.info("Gateway capture client active for scan %s", scan_id)
                except Exception:  # noqa: BLE001 - never let capture wiring break session setup
                    logger.warning("gateway capture client init failed; using transcription fallback", exc_info=True)
            else:
                logger.warning("gateway capture enabled but no gateway_capture_client on session %r / client %r; transcription fallback",
                               type(_raw).__name__, type(client).__name__)
    else:
        caido_endpoint = await session.resolve_exposed_port(_CONTAINER_CAIDO_PORT)
        host_caido_url = f"http://{caido_endpoint.host}:{caido_endpoint.port}"
        logger.debug("Caido host endpoint resolved: %s", host_caido_url)
        # RECON FORK PATCH (P1): if Recon's egress gateway is fronting the sandbox,
        # point it at THIS session's Caido as upstream so the enforced chain is
        # sandbox → gateway (RoE scope+rate) → Caido (capture) → target.
        _recon_set_gateway_upstream(host_caido_url)
        caido_client = await bootstrap_caido(
            session,
            host_url=host_caido_url,
            container_url=container_caido_url,
        )

    bundle = {
        "client": client,
        "session": session,
        "caido_client": caido_client,
        "_gateway_policy_fingerprint": fingerprint,
    }
    _SESSION_CACHE[scan_id] = bundle
    logger.info("Sandbox session for scan %s ready and cached", scan_id)
    return bundle


async def cleanup(scan_id: str) -> None:
    """Tear down ``scan_id``'s container and drop its cache entry.

    Best-effort: any error during ``client.delete`` is logged and
    swallowed. We never want a cleanup failure to prevent the next
    scan from starting; the worst case is a stranded container that
    Docker's normal reaping will catch on next ``docker prune``.
    """
    bundle = _SESSION_CACHE.pop(scan_id, None)
    if bundle is None:
        logger.debug("cleanup(%s): no cached session", scan_id)
        return

    # Clear the module-level gateway-capture routing (single active slot, mirrors caido_api's
    # _CLIENT_CACHE lifetime) so the next scan doesn't inherit this scan's gateway client.
    try:
        from strix.tools.proxy import caido_api

        caido_api.set_gateway_client(None)
    except Exception:  # noqa: BLE001
        pass

    caido_client = bundle.get("caido_client")
    if caido_client is not None:
        try:
            await caido_client.aclose()
        except Exception:  # noqa: BLE001
            logger.debug("cleanup(%s): caido_client.aclose() raised", scan_id, exc_info=True)

    # Wipe persisted browser cookies before the sandbox is deleted so abort/TTL
    # teardown does not leave /workspace/.recon-auth behind when the volume outlives the process.
    session = bundle.get("session")
    if session is not None and callable(getattr(session, "exec", None)):
        try:
            from strix.runtime.auth_preflight import purge_auth_state

            await purge_auth_state(session)
        except Exception:  # noqa: BLE001 - never fail cleanup
            logger.debug("cleanup(%s): purge_auth_state raised", scan_id, exc_info=True)

    try:
        await bundle["client"].delete(bundle["session"])
        logger.info("Cleaned up sandbox session for scan %s", scan_id)
    except Exception:
        logger.exception(
            "cleanup(%s): client.delete raised; container may need manual reaping",
            scan_id,
        )
