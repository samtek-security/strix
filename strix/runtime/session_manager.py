# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""Per-scan sandbox session lifecycle."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import inspect
import io
import json
import logging
import os
import tarfile
import time
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agents.sandbox.entries import BaseEntry, LocalDir
from agents.sandbox.manifest import Environment, Manifest

from strix.config import load_settings
from strix.runtime.auth_preflight import purge_auth_state
from strix.runtime.backends import (
    backend_supports_bind_mounts,
    effective_backend_name,
    get_backend,
)
from strix.runtime.caido_bootstrap import bootstrap_caido
from strix.runtime.caido_handle import CaidoBootstrapHandle
from strix.runtime.deferred_session import DeferredSandboxClient, DeferredSandboxSession


if TYPE_CHECKING:
    from collections.abc import Awaitable

    from agents.sandbox.session import BaseSandboxSession

    from strix.runtime.status import StatusSink


logger = logging.getLogger(__name__)


# In-container Caido sidecar port (matches the image's caido-cli bind).
_CONTAINER_CAIDO_PORT = 48080


_SESSION_CACHE: dict[str, dict[str, Any]] = {}

# Manifest root inside the container; entry keys hang off this path.
_WORKSPACE_ROOT = "/workspace"

_PROTECTED_METADATA_NAMES = (".git", ".agents")

_K8S_BACKENDS = frozenset({"k8s", "k8s-contained"})
_CONTAINED_BACKENDS = frozenset({"docker-contained"}) | _K8S_BACKENDS

# Extra files travel as one tar archive: a single upload plus one extraction
# inside the sandbox, instead of several round trips per file.
_EXTRA_FILE_ARCHIVE_REL = ".strix-extra-files.tar"
_EXTRA_FILE_ARCHIVE = f"{_WORKSPACE_ROOT}/{_EXTRA_FILE_ARCHIVE_REL}"
_EXTRA_FILE_EXTRACT_TIMEOUT_S = 120
_EXTRA_FILE_MODE = 0o644

_K8S_SOURCE_SKIP = frozenset({".git", "node_modules", "vendor", "__pycache__", ".venv", "dist"})


def _truthy_env(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes")


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
    """Point a fronting egress gateway at this session's Caido as its upstream.

    No-op when ``RECON_EGRESS_CONTROL`` is unset.
    """
    control = os.environ.get("RECON_EGRESS_CONTROL")
    if not control:
        return
    body = json.dumps({"url": caido_url}).encode()
    req = urllib.request.Request(  # noqa: S310 - operator-set localhost control endpoint
        f"{control}/upstream",
        data=body,
        method="PUT",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=3):  # noqa: S310 - same endpoint
            logger.info("Recon: egress gateway upstream set to session Caido %s", caido_url)
    except OSError as exc:
        logger.warning("Recon: could not set egress gateway upstream via %s: %s", control, exc)


def build_bind_mounts(local_sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    bind_mounts: list[dict[str, Any]] = []
    for src in local_sources:
        ws_subdir = src.get("workspace_subdir") or ""
        host_path = src.get("source_path") or ""
        if not ws_subdir or not host_path:
            continue
        resolved = Path(host_path).expanduser().resolve()
        target = f"{_WORKSPACE_ROOT}/{ws_subdir}"
        read_only = bool(src.get("read_only"))
        bind_mounts.append({"source": str(resolved), "target": target, "read_only": read_only})
        if src.get("protect_metadata") and not read_only:
            bind_mounts.extend(_metadata_mounts(resolved, target))
    return bind_mounts


def build_manifest_entries(local_sources: list[dict[str, Any]]) -> dict[str | Path, BaseEntry]:
    entries: dict[str | Path, BaseEntry] = {}
    for src in local_sources:
        ws_subdir = src.get("workspace_subdir") or ""
        host_path = src.get("source_path") or ""
        if not ws_subdir or not host_path:
            continue
        entries[ws_subdir] = LocalDir(src=Path(host_path).expanduser().resolve())
    return entries


def build_session_entries(
    local_sources: list[dict[str, Any]],
    *,
    bind_mounts_supported: bool = True,
) -> tuple[dict[str | Path, BaseEntry], list[dict[str, Any]]]:
    """Split local sources into copied manifest entries and host bind mounts.

    Recon copies every source into the sandbox unless it is flagged ``mount``.
    The Docker daemon can live on another host, where a bind source resolves
    against that host's filesystem and silently mounts an empty directory; a
    copy travels over the Docker API and works either way. A source flagged
    ``mount`` on a backend that can bind-mount is mounted read-only, so the
    agent never writes back into the worker's tree.
    """
    mounted = [src for src in local_sources if src.get("mount")] if bind_mounts_supported else []
    copied = [src for src in local_sources if src not in mounted]
    bind_mounts = build_bind_mounts([{**src, "read_only": True} for src in mounted])
    return build_manifest_entries(copied), bind_mounts


def _extra_file_rel_path(workspace_path: str) -> str | None:
    """Validate an extra-file target path and return it relative to /workspace.

    Only absolute paths under the workspace root are accepted; anything else
    (including ``..`` traversal segments) is rejected so callers cannot place
    orchestrator-provided content outside the sandbox workspace.
    """
    prefix = f"{_WORKSPACE_ROOT}/"
    if not workspace_path.startswith(prefix):
        return None
    rel = workspace_path[len(prefix) :].strip("/")
    if not rel or any(part in ("", ".", "..") for part in rel.split("/")):
        return None
    # Control characters would let a path break out of the single line it is
    # rendered on in the agent task, so the path is rejected rather than escaped.
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in rel):
        return None
    return rel


def _source_root_rels(local_sources: list[dict[str, Any]] | None) -> list[str]:
    """Workspace-relative roots the local sources occupy (e.g. ``["repo"]``)."""
    if not local_sources:
        return []
    return [
        str(src.get("workspace_subdir") or "").strip("/")
        for src in local_sources
        if src.get("workspace_subdir") and src.get("source_path")
    ]


def _collides_with_source_root(rel: str, source_roots: list[str]) -> bool:
    """True when an extra-file path would land on or inside a source tree.

    An exact match would replace the whole source tree with one file (a
    manifest ``entries`` key collision); a path nested under a source root
    would race the source upload; a path that is an ancestor of a source root
    would shadow the directory the source materializes into.
    """
    for root in source_roots:
        if not root:
            continue
        if rel == root or rel.startswith(f"{root}/") or root.startswith(f"{rel}/"):
            return True
    return False


def _extra_file_content(extra_file: dict[str, Any]) -> bytes | None:
    content = extra_file.get("content")
    if isinstance(content, bytes | bytearray):
        return bytes(content)
    if isinstance(content, str):
        return content.encode("utf-8")
    return None


def build_extra_file_archive(
    extra_files: list[dict[str, Any]],
    local_sources: list[dict[str, Any]] | None = None,
) -> bytes | None:
    """Pack extra files into one tar archive rooted at ``/workspace``.

    Each item is ``{"workspace_path": "/workspace/<rel>", "content": bytes|str}``
    and becomes a regular-file member at ``<rel>``. Extracting the archive as
    the sandbox user (see ``stage_extra_files``) leaves every file owned by
    that user, so the agent can edit it and create siblings. Invalid items,
    including paths that collide with a ``local_sources`` tree or with an
    earlier extra file, are skipped with a warning. Returns ``None`` when no
    valid file remains.
    """
    source_roots = _source_root_rels(local_sources)
    placed: list[str] = [_EXTRA_FILE_ARCHIVE_REL]
    buffer = io.BytesIO()
    mtime = int(time.time())
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for extra_file in extra_files:
            rel, content = _validated_extra_file(extra_file, source_roots + placed)
            if rel is None or content is None:
                continue
            placed.append(rel)
            info = tarfile.TarInfo(name=rel)
            info.size = len(content)
            info.mode = _EXTRA_FILE_MODE
            info.mtime = mtime
            archive.addfile(info, io.BytesIO(content))
    if len(placed) == 1:
        return None
    return buffer.getvalue()


def _validated_extra_file(
    extra_file: dict[str, Any], taken: list[str]
) -> tuple[str | None, bytes | None]:
    rel = _extra_file_rel_path(str(extra_file.get("workspace_path") or ""))
    content = _extra_file_content(extra_file)
    if rel is None or content is None:
        logger.warning(
            "Skipping invalid extra file entry (workspace_path=%r)",
            extra_file.get("workspace_path"),
        )
        return None, None
    if _collides_with_source_root(rel, taken):
        logger.warning(
            "Skipping extra file colliding with a local source tree or an "
            "earlier extra file (workspace_path=%r)",
            extra_file.get("workspace_path"),
        )
        return None, None
    return rel, content


async def stage_extra_files(session: BaseSandboxSession, archive: bytes) -> None:
    """Upload ``archive`` and unpack it under ``/workspace`` as the sandbox user.

    ``--no-same-owner`` keeps ownership with the extracting user even where
    the session runs as root, so the agent user can always write the files.
    """
    await session.write(Path(_EXTRA_FILE_ARCHIVE), io.BytesIO(archive))
    result = await session.exec(
        "sh",
        "-c",
        'tar --no-same-owner -xf "$1" -C "$2" && rm -f -- "$1"',
        "sh",
        _EXTRA_FILE_ARCHIVE,
        _WORKSPACE_ROOT,
        timeout=_EXTRA_FILE_EXTRACT_TIMEOUT_S,
    )
    if not result.ok():
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(
            f"unpacking extra files in the sandbox failed (exit {result.exit_code}): {stderr}"
        )


def _metadata_mounts(tree: Path, target: str) -> list[dict[str, Any]]:
    mounts: list[dict[str, Any]] = []
    for name in _PROTECTED_METADATA_NAMES:
        metadata = tree / name
        if not metadata.is_dir() and not metadata.is_file():
            continue
        if not metadata.resolve().is_relative_to(tree):
            continue
        mounts.append({"source": str(metadata), "target": f"{target}/{name}", "read_only": True})
        gitdir = _gitdir_from_pointer(metadata) if metadata.is_file() else None
        if gitdir is not None and gitdir.exists() and gitdir.is_relative_to(tree):
            relative = gitdir.relative_to(tree).as_posix()
            mounts.append(
                {"source": str(gitdir), "target": f"{target}/{relative}", "read_only": True}
            )
    return mounts


def _gitdir_from_pointer(git_file: Path) -> Path | None:
    try:
        content = git_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for line in content.splitlines():
        prefix, _, value = line.partition(":")
        if prefix.strip() == "gitdir" and value.strip():
            candidate = Path(value.strip()).expanduser()
            if not candidate.is_absolute():
                candidate = git_file.parent / candidate
            return candidate.resolve()
    return None


async def _resolve_extra_file_archive(
    extra_files: list[dict[str, Any]] | Awaitable[list[dict[str, Any]] | None] | None,
    local_sources: list[dict[str, Any]],
) -> bytes | None:
    files = await extra_files if inspect.isawaitable(extra_files) else extra_files
    return build_extra_file_archive(files, local_sources) if files else None


async def _hydrate_k8s_sources(session: Any, local_sources: list[dict[str, Any]]) -> None:
    """Tar each local source into ``/workspace/<subdir>`` of a Kubernetes sandbox.

    The Docker backends copy manifest ``LocalDir`` entries at ``session.start()``;
    the Kubernetes backend has no source materialization, so a white-box run
    would otherwise reach the agent without its tree. Best-effort: a copy
    failure never breaks the run (route, GraphQL and SAST intel still reach the
    agent as text). Gated on ``RECON_MOUNT_SOURCE`` (default on).
    """
    if os.environ.get("RECON_MOUNT_SOURCE", "1") in ("0", "false", "no"):
        return

    def _skip_vcs(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
        if set(info.name.split("/")) & _K8S_SOURCE_SKIP:
            return None
        return info

    for src in local_sources:
        ws = str(src.get("workspace_subdir") or "").strip()
        host = str(src.get("source_path") or "").strip()
        if not ws or not host:
            continue
        host_path = Path(host).expanduser().resolve()
        if not host_path.exists():
            logger.warning("source materialization: host path missing for %s: %s", ws, host)
            continue
        buf = io.BytesIO()
        try:
            with tarfile.open(fileobj=buf, mode="w") as tf:
                tf.add(str(host_path), arcname=ws, filter=_skip_vcs)
            nbytes = buf.getbuffer().nbytes
            buf.seek(0)
            await session.hydrate_workspace(buf)
            logger.info("Materialized source into k8s pod: /workspace/%s (%d bytes)", ws, nbytes)
        except Exception:  # noqa: BLE001 - best-effort; the run continues either way
            logger.warning(
                "source materialization failed for %s; continuing without mounted source",
                ws,
                exc_info=True,
            )


def _gateway_capture_client(client: Any, session: Any, scan_id: str) -> Any:
    """Return the trusted gateway's redacted-capture client for a contained run, or None.

    In contained mode the in-container Caido is not the egress path: the agent
    proxies straight to the trusted gateway, which captures the traffic. With
    ``RECON_GATEWAY_CAPTURE`` on, proxy tools read real redacted wire evidence
    through this client instead of relying on agent transcription. The backend
    may return an instrumentation-wrapped session; the raw Kubernetes session
    (gateway pod name + exec) is at ``._inner``.
    """
    if not _truthy_env("RECON_GATEWAY_CAPTURE"):
        return None
    raw = getattr(session, "_inner", session)
    try:
        if hasattr(raw, "gateway_capture_client"):
            capture = raw.gateway_capture_client()
        elif hasattr(client, "gateway_capture_client"):
            capture = client.gateway_capture_client()
        else:
            capture = None
    except Exception:  # noqa: BLE001 - capture wiring must never break session setup
        logger.warning(
            "gateway capture client init failed for scan %s; transcription fallback",
            scan_id,
            exc_info=True,
        )
        return None
    if capture is None:
        logger.warning(
            "gateway capture enabled but no gateway_capture_client on session %r / client %r; "
            "transcription fallback",
            type(raw).__name__,
            type(client).__name__,
        )
        return None
    logger.info("Gateway capture client active for scan %s", scan_id)
    return capture


async def create_or_reuse(  # noqa: PLR0915
    scan_id: str,
    *,
    image: str,
    local_sources: list[dict[str, Any]],
    extra_files: list[dict[str, Any]] | Awaitable[list[dict[str, Any]] | None] | None = None,
    status_sink: StatusSink | None = None,
    defer: bool = False,
    extra_env: dict[str, str] | None = None,
    heartbeat_path: str = "",
    gateway_spec_path: str = "",
    gateway_spec_json: str = "",
    gateway_target_ports: tuple[int, ...] = (),
) -> dict[str, Any]:
    """Return the existing session bundle for ``scan_id`` or create a new one.

    Each ``local_sources`` entry exposes its host ``source_path`` at
    ``/workspace/<workspace_subdir>`` inside the container: copied in, or
    bind-mounted read-only when flagged ``mount`` (see
    :func:`build_session_entries`). Kubernetes backends get the tree through
    :func:`_hydrate_k8s_sources` instead.

    Each ``extra_files`` entry (``{"workspace_path": "/workspace/<rel>",
    "content": bytes | str}``) lands as a regular, agent-writable file at its
    ``workspace_path`` on every backend: the files are uploaded as one archive
    and unpacked inside the sandbox right after bring-up. ``extra_files`` may
    also be an awaitable resolving to that list: provisioning starts at once and
    the files are awaited only when the sandbox is ready to receive them.

    ``defer=True`` returns at once with a session that resolves on first use.
    Bring-up still starts immediately in a background task, so it overlaps the
    first model call rather than saving sandbox time. Contained egress refuses
    it, because its proxy evidence client only exists once the gateway is up.

    The gateway policy inputs (``gateway_spec_path`` / ``gateway_spec_json``,
    ``gateway_target_ports``, backend) are fingerprinted; reusing a cached
    session under a different policy raises.
    """

    def report(phase: str) -> None:
        if status_sink is not None:
            status_sink(phase)

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

    is_k8s = backend_name in _K8S_BACKENDS
    contained = _truthy_env("RECON_CONTAINED_EGRESS") or backend_name in _CONTAINED_BACKENDS
    if defer and contained:
        raise ValueError(
            "deferred sandbox bring-up is not supported with contained egress "
            f"(backend {backend_name!r})"
        )

    if is_k8s:
        entries: dict[str | Path, BaseEntry] = {}
        bind_mounts: list[dict[str, Any]] = []
    else:
        entries, bind_mounts = build_session_entries(
            local_sources,
            bind_mounts_supported=backend_supports_bind_mounts(backend_name),
        )

    # Caido runs as an in-container sidecar; HTTP(S) traffic from any
    # process started via ``session.exec`` (the SDK's Shell tool, etc.)
    # picks up these env vars automatically. ``NO_PROXY`` keeps the
    # recon-browser CDP daemon's localhost traffic from looping back
    # through Caido.
    container_caido_url = f"http://127.0.0.1:{_CONTAINER_CAIDO_PORT}"
    # RECON_EGRESS_PROXY routes the sandbox's egress through Recon's RoE-locked
    # gateway, which enforces scope and rate below the agent and uses Caido as
    # its upstream so capture survives: sandbox -> gateway -> Caido -> target.
    sandbox_proxy = os.environ.get("RECON_EGRESS_PROXY", container_caido_url)
    # In contained mode the gateway container, reached by its deterministic
    # name on the internal network, is the agent's only egress. The entrypoint
    # reads RECON_EGRESS_UPSTREAM to re-point its system proxy and browser.
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
                # Brokered secrets go into the sandbox env, never the prompt or history.
                **{k: str(v) for k, v in (extra_env or {}).items()},
            },
        ),
    )

    backend = get_backend(backend_name)
    # A contained agent sits on an internal-only network with no host port, and
    # its egress is the gateway, not the in-container Caido.
    exposed_ports: tuple[int, ...] = () if contained else (_CONTAINER_CAIDO_PORT,)

    logger.info(
        "Creating sandbox session for scan %s (backend=%s, image=%s)",
        scan_id,
        backend_name,
        image,
    )

    async def _bring_up() -> tuple[Any, Any]:
        report("Starting sandbox container")
        client, session = await _create_or_discard(
            backend(
                image=image,
                manifest=manifest,
                exposed_ports=exposed_ports,
                bind_mounts=bind_mounts,
                scan_id=scan_id,
                heartbeat_path=heartbeat_path,
                gateway_spec_path=gateway_spec_path,
                gateway_spec_json=gateway_spec_json,
                gateway_target_ports=normalized_ports,
            )
        )
        try:
            if is_k8s and local_sources:
                await _hydrate_k8s_sources(session, local_sources)
            extra_file_archive = await _resolve_extra_file_archive(extra_files, local_sources)
            if extra_file_archive is not None:
                report("Placing workspace files")
                await stage_extra_files(session, extra_file_archive)
        except BaseException:
            await _discard_session(client, session)
            raise
        return client, session

    async def _caido_url(session: Any) -> str:
        report("Setting up the proxy")
        caido_endpoint = await session.resolve_exposed_port(_CONTAINER_CAIDO_PORT)
        scheme = "https" if caido_endpoint.tls else "http"
        host_caido_url = f"{scheme}://{caido_endpoint.host}:{caido_endpoint.port}"
        logger.debug("Caido host endpoint resolved: %s", host_caido_url)
        # A fronting egress gateway takes this session's Caido as its upstream.
        _recon_set_gateway_upstream(host_caido_url)
        return host_caido_url

    def _caido(session: Any, host_caido_url: str) -> Any:
        return bootstrap_caido(
            session,
            host_url=host_caido_url,
            container_url=container_caido_url,
        )

    if defer:
        bring_up = asyncio.create_task(_bring_up(), name=f"sandbox-bring-up-{scan_id}")
        deferred = DeferredSandboxSession(
            bring_up,
            manifest=manifest,
            exposed_ports=exposed_ports,
        )

        async def _caido_when_up() -> Any:
            session = await deferred.resolve()
            return await _caido(session, await _caido_url(session))

        bundle = {
            "client": DeferredSandboxClient(deferred),
            "session": deferred,
            "caido_client": CaidoBootstrapHandle(
                asyncio.create_task(_caido_when_up(), name=f"caido-bootstrap-{scan_id}")
            ),
            "_gateway_policy_fingerprint": fingerprint,
        }
        _SESSION_CACHE[scan_id] = bundle
        logger.info("Sandbox session for scan %s deferred and cached", scan_id)
        return bundle

    client, session = await _bring_up()
    caido_client: Any
    if contained:
        # Proxy tools degrade to "client unavailable" when this is None.
        caido_client = _gateway_capture_client(client, session, scan_id)
    else:
        host_caido_url = await _caido_url(session)
        caido_client = CaidoBootstrapHandle(
            asyncio.create_task(_caido(session, host_caido_url), name=f"caido-bootstrap-{scan_id}")
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


_DISCARD_TASKS: set[asyncio.Task[None]] = set()


async def _create_or_discard(create: Awaitable[tuple[Any, Any]]) -> tuple[Any, Any]:
    pending = asyncio.ensure_future(create)
    try:
        return await asyncio.shield(pending)
    except asyncio.CancelledError:
        discard = asyncio.create_task(_discard_when_created(pending))
        _DISCARD_TASKS.add(discard)
        discard.add_done_callback(_DISCARD_TASKS.discard)
        raise


async def _discard_when_created(create: asyncio.Future[tuple[Any, Any]]) -> None:
    with contextlib.suppress(BaseException):
        client, session = await create
        await _discard_session(client, session)


async def _discard_session(client: Any, session: Any) -> None:
    """Best-effort teardown of a session that never made it into the cache."""
    try:
        await client.delete(session)
    except Exception:  # noqa: BLE001
        logger.warning("Discarding a half-started sandbox session failed", exc_info=True)


async def cleanup(scan_id: str) -> None:
    """Tear down ``scan_id``'s container and drop its cache entry.

    Best-effort: any error during ``client.delete`` is logged and
    swallowed. We never want a cleanup failure to prevent the next
    scan from starting; the worst case is a stranded container that
    the independent reaper removes at its TTL deadline.
    """
    bundle = _SESSION_CACHE.pop(scan_id, None)
    if bundle is None:
        logger.debug("cleanup(%s): no cached session", scan_id)
        return

    caido_client = bundle.get("caido_client")
    if caido_client is not None:
        try:
            await caido_client.aclose()
        except Exception:  # noqa: BLE001
            logger.debug("cleanup(%s): caido_client.aclose() raised", scan_id, exc_info=True)

    # Wipe persisted browser cookies before the sandbox is deleted so abort/TTL
    # teardown does not leave /workspace/.recon-auth behind when the volume
    # outlives the process. A deferred session still coming up has none yet.
    session = bundle.get("session")
    pending = isinstance(session, DeferredSandboxSession) and session.pending
    if session is not None and not pending and callable(getattr(session, "exec", None)):
        try:
            await purge_auth_state(session)
        except Exception:  # noqa: BLE001 - never fail cleanup
            logger.debug("cleanup(%s): purge_auth_state raised", scan_id, exc_info=True)

    client = bundle["client"]
    try:
        await client.delete(bundle["session"])
        logger.info("Cleaned up sandbox session for scan %s", scan_id)
    except Exception:
        logger.exception(
            "cleanup(%s): client.delete raised; container may need manual reaping",
            scan_id,
        )

    docker_client = getattr(client, "docker_client", None)
    if docker_client is not None:
        try:
            docker_client.close()
        except Exception:  # noqa: BLE001
            logger.debug("cleanup(%s): docker_client.close() raised", scan_id, exc_info=True)
