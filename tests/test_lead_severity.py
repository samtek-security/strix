# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""A lead keeps the severity it claimed but never counts at it (recon#366)."""

from __future__ import annotations

import importlib
import json
from typing import TYPE_CHECKING, Any

from strix.interface.viewer.transcript import lead_count_of, severity_counts
from strix.report.proof import is_validated, lead_count
from strix.report.runs import _title
from strix.report.sarif import write_sarif
from strix.tools.reporting.tool import _severity_counts


if TYPE_CHECKING:
    from pathlib import Path

cli_main: Any = importlib.import_module("strix.interface.main")


def _report(severity: str, proof_status: str | None = None, **extra: Any) -> dict[str, Any]:
    report: dict[str, Any] = {
        "id": "vuln-0001",
        "title": "SQL injection",
        "severity": severity,
        "cvss": 9.8,
        "timestamp": "2026-11-26 10:00:00 UTC",
        "code_locations": [{"file": "app.py", "start_line": 4}],
        **extra,
    }
    if proof_status is not None:
        report["proof_status"] = proof_status
    return report


def test_only_exploited_or_unset_proof_status_is_validated() -> None:
    assert is_validated(_report("high"))
    assert is_validated(_report("high", "exploited"))
    assert not is_validated(_report("high", "lead"))
    assert lead_count([_report("high"), _report("high", "lead"), _report("low", "lead")]) == 2


def test_a_downgraded_lead_does_not_trip_fail_on() -> None:
    lead = _report("critical", "lead")
    assert not cli_main.findings_fail_build([lead], "high")
    assert not cli_main.findings_fail_build([lead], None)


def test_a_validated_finding_with_the_same_severity_trips_fail_on() -> None:
    assert cli_main.findings_fail_build([_report("critical", "exploited")], "high")
    assert cli_main.findings_fail_build([_report("critical")], "high")


def test_a_lead_beside_a_validated_finding_does_not_change_the_gate() -> None:
    reports = [_report("critical", "lead"), _report("low", "exploited")]
    assert not cli_main.findings_fail_build(reports, "high")
    assert cli_main.findings_fail_build(reports, "low")


def test_severity_counts_leave_leads_out_and_count_them_apart() -> None:
    reports = [_report("critical", "lead"), _report("critical", "exploited"), _report("low")]
    assert severity_counts(reports) == {"critical": 1, "high": 0, "medium": 0, "low": 1}
    assert lead_count_of(reports) == 1


def test_run_title_prefers_a_validated_finding() -> None:
    lead = _report("critical", "lead", title="Admin takeover via lead")
    proven = _report("low", "exploited", title="Verbose error via login")
    assert _title({}, [lead, proven]) == "Verbose error"
    assert _title({}, [lead]) == "Admin takeover"


def test_sarif_lead_is_a_note_and_keeps_its_claimed_severity(tmp_path: Path) -> None:
    reports = [_report("critical", "lead"), _report("critical", "exploited", id="vuln-0002")]
    write_sarif(tmp_path, reports)
    doc = json.loads((tmp_path / "findings.sarif").read_text(encoding="utf-8"))
    run = doc["runs"][0]
    results = run["results"]
    assert sorted(r["level"] for r in results) == ["error", "note"]
    lead = next(r for r in results if r["level"] == "note")
    proven = next(r for r in results if r["level"] == "error")
    assert lead["properties"]["security-severity"] == "1.0"
    assert lead["properties"]["claimed_severity"] == "critical"
    assert lead["properties"]["claimed_cvss"] == 9.8
    assert lead["properties"]["proof_status"] == "lead"
    assert "claimed_severity" not in proven["properties"]
    assert proven["properties"]["security-severity"] == "9.8"


def test_sarif_rule_shared_by_a_lead_and_a_validated_finding_takes_the_validated_level(
    tmp_path: Path,
) -> None:
    # The lead is filed first, so the rule would otherwise be built from it.
    reports = [
        _report("critical", "lead", cwe="CWE-89"),
        _report("critical", "exploited", id="vuln-0002", cwe="CWE-89"),
    ]
    write_sarif(tmp_path, reports)
    run = json.loads((tmp_path / "findings.sarif").read_text(encoding="utf-8"))["runs"][0]
    assert len(run["tool"]["driver"]["rules"]) == 1
    rule = run["tool"]["driver"]["rules"][0]
    assert rule["defaultConfiguration"]["level"] == "error"
    assert rule["properties"]["security-severity"] == "9.8"


def test_list_reports_counts_leads_apart() -> None:
    reports = [_report("critical", "lead"), _report("critical", "exploited"), _report("low")]
    assert _severity_counts(reports) == {"critical": 1, "low": 1}
