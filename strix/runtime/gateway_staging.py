# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""Stage the signed spec and reporter token for the egress gateway's own UID.

The stock gateway image runs as UID 10001 and the worker-side checks demand that both files are
owned by the worker and closed to group and other. A worker that is not UID 10001 therefore cannot
bind-mount them: the gateway could not read a 0600 file owned by someone else. The worker does not
loosen those checks. A short-lived helper, started as root with no network and only the capabilities
it needs, copies both files into a per-launch Docker volume as UID 10001 with mode 0400. Only the
gateway mounts that volume; the agent container never does.
"""

from __future__ import annotations

import contextlib
import logging
import os
import time
import uuid
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from pathlib import Path


logger = logging.getLogger(__name__)

DEFAULT_GATEWAY_UID = 10001
STAGE_MOUNT = "/etc/recon-staged"
SPEC_NAME = "engagement.json"
TOKEN_NAME = "target-health-token"  # noqa: S105  (a file name, not a secret)
STAGE_ROLE = "gateway-staging-volume"
HELPER_ROLE = "gateway-staging-helper"

# Runs as root inside the helper. The umask makes every file 0400 from creation, so there is no
# window in which a copy is readable by anyone but its owner.
_STAGE_SCRIPT = (
    "set -eu; umask 0277; "
    f"cp /src/{SPEC_NAME} /stage/{SPEC_NAME}; "
    f"cp /src/{TOKEN_NAME} /stage/{TOKEN_NAME}; "
    'chown "$1:$1" /stage /stage/*; '
    "chmod 0500 /stage; chmod 0400 /stage/*"
)
_HELPER_CAPS = ("CHOWN", "DAC_OVERRIDE", "FOWNER")


class StagingError(RuntimeError):
    """The gateway's copies could not be created; the launch must stop."""


def gateway_uid() -> int:
    raw = os.environ.get("RECON_GATEWAY_UID", "").strip()
    if not raw:
        return DEFAULT_GATEWAY_UID
    try:
        uid = int(raw)
    except ValueError:
        uid = -1
    if uid <= 0:
        raise ValueError(f"RECON_GATEWAY_UID {raw!r} must be a positive integer")
    return uid


def resolve_uid(dc: Any, image: str) -> int:
    """The UID the gateway image runs as.

    An explicit ``RECON_GATEWAY_UID`` wins. With the stock image name (no override) the default
    applies. A custom image is inspected for a numeric ``USER``; anything else must be stated.
    """
    if (
        os.environ.get("RECON_GATEWAY_UID", "").strip()
        or not os.environ.get("RECON_EGRESS_GATEWAY_IMAGE", "").strip()
    ):
        return gateway_uid()
    user = ""
    with contextlib.suppress(Exception):
        user = str(dc.images.get(image).attrs.get("Config", {}).get("User") or "")
    first = user.split(":", 1)[0]
    if first.isdigit() and int(first) > 0:
        return int(first)
    raise ValueError(
        f"gateway image {image!r} has no numeric non-root USER (found {user!r}); set "
        "RECON_GATEWAY_UID to the UID it runs as so the staged files are readable"
    )


def needs_staging(uid: int | None = None) -> bool:
    """True when the worker's files cannot be read by the gateway's user in place."""
    return os.geteuid() != (uid if uid is not None else gateway_uid())


def _ttl_seconds() -> int:
    from strix.runtime.docker_client import _sandbox_ttl_sec  # noqa: PLC0415  (heavy SDK import)

    return int(_sandbox_ttl_sec())


def volume_labels(boundary_labels: dict[str, str], run_id: str) -> dict[str, str]:
    scan_id = boundary_labels.get("recon.scan_id", "")
    now = int(time.time())
    return {
        **boundary_labels,
        "recon.role": STAGE_ROLE,
        "recon.created_at": str(now),
        "recon.ttl_deadline": str(now + _ttl_seconds()),
        "recon.run_id": run_id,
        "recon.engagement_id": os.environ.get("RECON_ENGAGEMENT_ID", "").strip() or scan_id,
    }


def _expired(labels: dict[str, str], now: float) -> bool:
    try:
        return float(labels.get("recon.ttl_deadline", "")) < now
    except ValueError:
        return True


def sweep_stale(dc: Any, boundary_labels: dict[str, str]) -> None:
    """Remove staging helpers and volumes a crashed worker left behind.

    This engagement's leftovers always go. Another engagement's go only once past their TTL, so a
    live launch is never touched. Helpers are removed first: a stopped helper still holds its
    volume. Matching is on exact labels, never a name prefix.
    """
    scan_id = boundary_labels.get("recon.scan_id", "")
    now = time.time()
    for kind, listing, role in (
        ("helper", lambda f: dc.containers.list(all=True, filters=f), HELPER_ROLE),
        ("volume", lambda f: dc.volumes.list(filters=f), STAGE_ROLE),
    ):
        for item in listing({"label": [f"recon.role={role}"]}):
            labels = _labels(item)
            if not ((scan_id and labels.get("recon.scan_id") == scan_id) or _expired(labels, now)):
                continue
            logger.warning("Removing stale gateway staging %s %s", kind, getattr(item, "name", "?"))
            with contextlib.suppress(Exception):
                item.remove(force=True)


def _labels(item: Any) -> dict[str, str]:
    attrs = getattr(item, "attrs", None) or {}
    labels = attrs.get("Labels") or (attrs.get("Config") or {}).get("Labels") or {}
    return dict(labels)


def stage(
    dc: Any,
    *,
    image: str,
    boundary_labels: dict[str, str],
    spec_path: str | Path,
    token_path: str | Path,
    uid: int | None = None,
) -> Any:
    """Create a fresh per-launch volume holding both files for the gateway's UID."""
    uid = uid if uid is not None else gateway_uid()
    run_id = uuid.uuid4().hex[:12]
    name = f"recon-gwstage-{boundary_labels.get('recon.scan_id') or 'default'}-{run_id}"
    volume = None
    helper = None
    try:
        volume = dc.volumes.create(name=name, labels=volume_labels(boundary_labels, run_id))
        helper = dc.containers.run(
            image,
            entrypoint=["/bin/sh", "-c"],
            command=[_STAGE_SCRIPT, "stage", str(uid)],
            user="0",
            network_mode="none",
            cap_drop=["ALL"],
            cap_add=list(_HELPER_CAPS),
            security_opt=["no-new-privileges"],
            read_only=True,
            detach=True,
            labels={**volume_labels(boundary_labels, run_id), "recon.role": HELPER_ROLE},
            volumes={
                str(spec_path): {"bind": f"/src/{SPEC_NAME}", "mode": "ro"},
                str(token_path): {"bind": f"/src/{TOKEN_NAME}", "mode": "ro"},
                name: {"bind": "/stage", "mode": "rw"},
            },
        )
        status = helper.wait().get("StatusCode")
        if status != 0:
            raise RuntimeError(f"staging helper exited with status {status}")  # noqa: TRY301
    except BaseException as exc:
        if helper is not None:
            with contextlib.suppress(Exception):
                helper.remove(force=True)
        if volume is not None:
            with contextlib.suppress(Exception):
                volume.remove(force=True)
        # The helper's output can echo file names, never contents, but keep the cause terse.
        raise StagingError(
            f"could not stage the signed spec and reporter token for gateway UID {uid}: "
            f"{type(exc).__name__}; refusing to start (fail-closed)"
        ) from exc
    with contextlib.suppress(Exception):
        helper.remove(force=True)
    return volume
