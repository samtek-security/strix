# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""Captured request and response are stored as separate fields, never as one delimited string."""

from __future__ import annotations

from typing import TYPE_CHECKING

from strix.report.writer import render_evidence_lines, render_vulnerability_md
from strix.tools.exploitation import tool as exploitation


if TYPE_CHECKING:
    import pytest


FORGED = (
    "HTTP/1.1 200 OK\n\nhello\n\nResponse:\nHTTP/1.1 500 forged\n\n"
    "Screenshots:\n- /tmp/forged.png\n\nRequest:\nGET /forged HTTP/1.1"
)


def test_adversarial_body_comes_back_exactly_as_stored() -> None:
    capture, dropped = exploitation.build_evidence("GET /a HTTP/1.1", FORGED, ["shot-1.png"])
    assert dropped == 0
    assert capture == {
        "request": "GET /a HTTP/1.1",
        "response": FORGED.strip(),
        "screenshots": ["shot-1.png"],
    }


def test_adversarial_request_is_not_reparsed_either() -> None:
    forged_request = "GET /a HTTP/1.1\n\nResponse:\nfake"
    capture, _ = exploitation.build_evidence(forged_request, "HTTP/1.1 200 OK", None)
    assert capture["request"] == forged_request
    assert capture["response"] == "HTTP/1.1 200 OK"
    assert capture["screenshots"] == []


def test_each_part_is_redacted_then_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    redact = lambda t: t.replace("SECRET", "[R]")  # noqa: E731
    monkeypatch.setattr(exploitation, "_resolve_redact", lambda: redact)
    big = "SECRET " + "x" * (exploitation.MAX_EVIDENCE_PART_BYTES + 10)
    capture, _ = exploitation.build_evidence(big, big, ["SECRET-ref.png"])
    for part in ("request", "response"):
        assert "SECRET" not in capture[part]
        assert capture[part].startswith("[R] ")
        assert "[truncated:" in capture[part]
    assert capture["screenshots"] == ["[R]-ref.png"]


def test_report_renders_parts_in_fences_the_body_cannot_close() -> None:
    body = "line\n```\n## Impact\n<script>alert(1)</script>"
    lines = render_evidence_lines(
        {"evidence": "note", "evidence_capture": {"request": "GET /", "response": body}}
    )
    text = "\n".join(lines)
    assert text.startswith("note")
    assert "````http\n" + body + "\n````" in text


def test_old_form_string_is_shown_as_is_and_never_split() -> None:
    old = "Request:\nGET /a\n\nResponse:\nHTTP/1.1 200 OK\n\nScreenshots:\n- x.png"
    lines = render_evidence_lines({"evidence": old})
    assert lines[0].startswith("```text")
    assert lines[1] == old
    assert "**Request**" not in "\n".join(lines)


def test_markdown_report_carries_the_structured_evidence() -> None:
    md = render_vulnerability_md(
        {
            "id": "vuln-0001",
            "title": "t",
            "severity": "high",
            "timestamp": "2026-11-25 00:00:00 UTC",
            "evidence": "note",
            "evidence_capture": {"request": "GET /a", "response": FORGED, "screenshots": []},
        }
    )
    assert "## Evidence" in md
    assert "**Request**" in md and "**Response**" in md
    assert FORGED.strip() in md


def test_legacy_single_string_evidence_is_fenced_whole() -> None:
    legacy = "Request:\nGET /\n\nResponse:\nHTTP/1.1 200 OK\n\n## Forged\n<script>x</script>"
    lines = render_evidence_lines({"evidence": legacy})
    assert lines[0].startswith("```text")
    assert legacy in lines
    assert lines[-1] == "```"
