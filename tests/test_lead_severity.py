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
from strix.report.state import ReportState, set_global_report_state
from strix.tools.exploitation import tool as ex
from strix.tools.reporting.tool import _severity_counts, _to_report_summary_entry


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


def test_sarif_gives_a_lead_its_own_rule(tmp_path: Path) -> None:
    # Same CWE: without a separate rule the lead would show at the validated finding's severity.
    reports = [
        _report("critical", "lead", cwe="CWE-89"),
        _report("critical", "exploited", id="vuln-0002", cwe="CWE-89"),
    ]
    write_sarif(tmp_path, reports)
    run = json.loads((tmp_path / "findings.sarif").read_text(encoding="utf-8"))["runs"][0]
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    assert set(rules) == {"CWE-89", "CWE-89-lead"}
    assert rules["CWE-89"]["defaultConfiguration"]["level"] == "error"
    assert rules["CWE-89-lead"]["defaultConfiguration"]["level"] == "note"
    assert rules["CWE-89-lead"]["properties"]["security-severity"] == "1.0"
    # the suffix is only the rule id: tags and the help link stay on the canonical CWE
    assert rules["CWE-89-lead"]["properties"]["tags"] == rules["CWE-89"]["properties"]["tags"]
    assert rules["CWE-89-lead"]["helpUri"] == rules["CWE-89"]["helpUri"]


def test_report_summary_entry_carries_the_proof_status() -> None:
    assert _to_report_summary_entry(_report("high", "lead"))["proof_status"] == "lead"
    assert "proof_status" not in _to_report_summary_entry(_report("high"))


def test_list_reports_counts_leads_apart() -> None:
    reports = [_report("critical", "lead"), _report("critical", "exploited"), _report("low")]
    assert _severity_counts(reports) == {"critical": 1, "low": 1}


def test_queue_filed_leads_are_marked_so_they_stay_out_of_the_counts(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.chdir(tmp_path)  # ReportState writes recon_runs/ under the current directory
    rs = ReportState("run")
    set_global_report_state(rs)
    try:
        ex._queue.clear()
        ex._queue["q-0001"] = {
            "id": "q-0001", "title": "Queued lead", "guard_evidence": "g", "minimal_witness": "w",
            "confidence": "high", "endpoint": "/x", "status": "queued",
        }
        assert ex.drain_pending_to_leads("boundary") == 1
    finally:
        set_global_report_state(None)
        ex._queue.clear()
    assert [r.get("proof_status") for r in rs.vulnerability_reports] == ["lead"]
    assert sum(severity_counts(rs.vulnerability_reports).values()) == 0
