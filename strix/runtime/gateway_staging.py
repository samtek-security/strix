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


def needs_staging() -> bool:
    """True when the worker's files cannot be read by the gateway's user in place."""
    return os.geteuid() != gateway_uid()


def volume_labels(boundary_labels: dict[str, str], run_id: str) -> dict[str, str]:
    scan_id = boundary_labels.get("recon.scan_id", "")
    return {
        **boundary_labels,
        "recon.role": STAGE_ROLE,
        "recon.run_id": run_id,
        "recon.engagement_id": os.environ.get("RECON_ENGAGEMENT_ID", "").strip() or scan_id,
    }


def sweep_stale(dc: Any, boundary_labels: dict[str, str]) -> None:
    """Remove staging volumes a crashed worker left for this engagement.

    Matches the exact ``recon.scan_id`` and role labels, never a name prefix, so no other
    engagement's volume is touched.
    """
    scan_id = boundary_labels.get("recon.scan_id", "")
    if not scan_id:
        return
    filters = {"label": [f"recon.role={STAGE_ROLE}", f"recon.scan_id={scan_id}"]}
    for volume in dc.volumes.list(filters=filters):
        logger.warning("Removing stale gateway staging volume %s", getattr(volume, "name", "?"))
        with contextlib.suppress(Exception):
            volume.remove(force=True)


def stage(
    dc: Any,
    *,
    image: str,
    boundary_labels: dict[str, str],
    spec_path: str | Path,
    token_path: str | Path,
) -> Any:
    """Create a fresh per-launch volume holding both files for the gateway's UID."""
    uid = gateway_uid()
    run_id = uuid.uuid4().hex[:12]
    name = f"recon-gwstage-{boundary_labels.get('recon.scan_id') or 'default'}-{run_id}"
    volume = None
    try:
        volume = dc.volumes.create(name=name, labels=volume_labels(boundary_labels, run_id))
        dc.containers.run(
            image,
            entrypoint=["/bin/sh", "-c"],
            command=[_STAGE_SCRIPT, "stage", str(uid)],
            user="0",
            network_mode="none",
            cap_drop=["ALL"],
            cap_add=list(_HELPER_CAPS),
            security_opt=["no-new-privileges"],
            read_only=True,
            remove=True,
            detach=False,
            labels={**boundary_labels, "recon.role": "gateway-staging-helper"},
            volumes={
                str(spec_path): {"bind": f"/src/{SPEC_NAME}", "mode": "ro"},
                str(token_path): {"bind": f"/src/{TOKEN_NAME}", "mode": "ro"},
                name: {"bind": "/stage", "mode": "rw"},
            },
        )
    except BaseException as exc:
        if volume is not None:
            with contextlib.suppress(Exception):
                volume.remove(force=True)
        # The helper's output can echo file names, never contents, but keep the cause terse.
        raise StagingError(
            f"could not stage the signed spec and reporter token for gateway UID {uid}: "
            f"{type(exc).__name__}; refusing to start (fail-closed)"
        ) from exc
    return volume
