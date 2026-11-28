# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""Whether a report counts as a proven finding.

A report that carries a ``proof_status`` other than ``exploited`` (a downgraded promotion is
filed as a ``lead``) keeps the severity it claimed, so a reader can see it, but it does not
count at that severity: ``--fail-on``, the severity summaries and the SARIF level all treat it as
a lead. A report with no ``proof_status`` (a direct report) counts as before.
"""

from __future__ import annotations

from typing import Any


def is_validated(report: Any) -> bool:
    """True for a report that counts at its claimed severity."""
    if not isinstance(report, dict):
        return True
    status = str(report.get("proof_status") or "").strip().lower()
    return status in ("", "exploited")


def lead_count(reports: list[Any]) -> int:
    """How many reports are not validated and so are counted apart from the severity buckets."""
    return sum(1 for r in reports if not is_validated(r))
