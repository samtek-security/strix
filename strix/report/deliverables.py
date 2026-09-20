# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""Deliverables bus (Wave 3.4-lean) — a clean, manifested output surface per run.

A scan scatters its outputs across the run dir (vulnerabilities.json, findings.sarif, the
executive report) and the internal ``.state/`` scratch (exploitation queue, coverage probes,
notes, todos, the SDK session db). This assembles the CUSTOMER/AUDIT-facing artifacts into one
``deliverables/`` directory with stable names + a hashed ``manifest.json`` — so:

- **Clean separation**: consumers read ``deliverables/``; the noisy ``.state/`` internals stay
  out of the deliverable (Shannon's "customer sees only the report; internals nested away").
- **Machine-consumable + audit-grade**: the manifest indexes each artifact with its byte size
  and SHA-256, so a downstream (the control plane, an auditor, a future pipeline phase) can
  verify exactly what a run produced.
- **Forward-compatible**: when the workflow is phase-split, phases write/read named deliverables
  here instead of reaching into each other's run dirs.

Best-effort: assembling deliverables never raises (it runs at end-of-run cleanup); a missing or
unreadable source is simply skipped and noted absent in the manifest.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

from strix.core.paths import runtime_state_dir

logger = logging.getLogger(__name__)

DELIVERABLES_DIR_NAME = "deliverables"
MANIFEST_FILENAME = "manifest.json"

# (source-relative-to run_dir | state_dir, deliverable name, kind, from_state?). Order is the
# manifest order. Only sources that exist are copied; the rest are recorded as absent.
_SOURCES = [
    ("vulnerabilities.json", "findings.json", "findings", False),
    ("findings.sarif", "findings.sarif", "sarif", False),
    ("penetration_test_report.md", "report.md", "report", False),
    ("vulnerabilities.csv", "findings.csv", "findings-index", False),
    ("role_probes.json", "coverage.json", "coverage", True),
    ("exploitation_queue.json", "exploitation_queue.json", "exploitation-queue", True),
]


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_deliverables(run_dir: Path, scan_id: str) -> Path | None:
    """Assemble ``run_dir/deliverables/`` from the run's canonical artifacts + a hashed
    manifest. Returns the deliverables dir, or None if nothing could be assembled. Never raises."""
    try:
        run_dir = Path(run_dir)
        state_dir = runtime_state_dir(run_dir)
        out_dir = run_dir / DELIVERABLES_DIR_NAME
        out_dir.mkdir(parents=True, exist_ok=True)

        items: list[dict] = []
        for src_name, deliv_name, kind, from_state in _SOURCES:
            src = (state_dir if from_state else run_dir) / src_name
            dest = out_dir / deliv_name
            entry: dict = {"name": deliv_name, "kind": kind}
            try:
                # Never write THROUGH an existing symlink at the destination (a planted
                # deliverables/findings.json -> ../vulnerabilities.json would otherwise clobber
                # the source). Always remove the prior dest first, then write a fresh regular file.
                if dest.is_symlink() or dest.exists():
                    dest.unlink()
                if src.is_file():
                    data = src.read_bytes()
                    dest.write_bytes(data)
                    entry.update(present=True, bytes=len(data), sha256=_sha256_bytes(data))
                else:
                    entry.update(present=False)  # dest already removed above -> no stale copy
            except OSError:
                logger.exception("deliverable %s could not be assembled from %s", deliv_name, src)
                entry.update(present=False, error="unreadable")
            items.append(entry)

        manifest = {
            "schema": "recon.deliverables.v1",
            "scan_id": scan_id,
            "deliverables": items,
        }
        (out_dir / MANIFEST_FILENAME).write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8",
        )
        present = sum(1 for i in items if i.get("present"))
        logger.info("deliverables assembled: %d/%d present in %s", present, len(items), out_dir)
        return out_dir
    except Exception:  # noqa: BLE001 - end-of-run best-effort, never fatal
        logger.exception("deliverables assembly failed")
        return None


def read_manifest(run_dir: Path) -> dict | None:
    """Read a run's deliverables manifest (for the control plane / an auditor / a later phase)."""
    try:
        path = Path(run_dir) / DELIVERABLES_DIR_NAME / MANIFEST_FILENAME
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None
    except (OSError, json.JSONDecodeError):
        return None
