# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""``assess_proof`` is the one proof decision both report-filing tools share."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from agents.tool_context import ToolContext

from strix.tools.exploitation.tool import (
    NO_EXCHANGE_SOURCE_REASON,
    PROOF_FAILED_PREFIX,
    assess_proof,
    assess_proof_with_integrity,
)


_GOOD = "gw-0123456789ab-" + "a" * 32
_OTHER = "gw-0123456789ab-" + "b" * 32


class _Capture:
    _is_gateway_capture = True

    def __init__(self, known: set[str]) -> None:
        self.known = known

    async def capture_exists(self, request_id: str) -> bool:
        return request_id in self.known

    async def view_request(self, request_id: str, *, part: str = "request") -> Any:
        del request_id, part
        return SimpleNamespace(
            request=SimpleNamespace(raw="GET / HTTP/1.1"),
            response=SimpleNamespace(raw="HTTP/1.1 200 OK"),
            integrity_sha256="a" * 64,
            integrity_verified=True,
            captured_at="2026-11-26T10:00:00Z",
        )


def _ctx(client: Any) -> Any:
    context = {"caido_client": client} if client is not None else {}
    return ToolContext(context=context, tool_name="t", tool_call_id="c", tool_arguments="{}")


@pytest.mark.asyncio
async def test_a_verified_id_is_exploited_with_its_source() -> None:
    out = await assess_proof(_ctx(_Capture({_GOOD})), [_GOOD])
    assert out == ([_GOOD], "exploited", None, "gateway_capture")


@pytest.mark.asyncio
async def test_no_source_is_a_lead_with_its_own_reason() -> None:
    assert await assess_proof(_ctx(None), [_GOOD]) == (
        None,
        "lead",
        NO_EXCHANGE_SOURCE_REASON,
        None,
    )


@pytest.mark.asyncio
async def test_unknown_or_missing_ids_are_leads() -> None:
    for ids in ([_OTHER], []):
        _, status, reason, source = await assess_proof(_ctx(_Capture({_GOOD})), ids)
        assert (status, source) == ("lead", None)
        assert reason is not None
        assert reason.startswith(PROOF_FAILED_PREFIX)


@pytest.mark.asyncio
async def test_require_all_fails_when_the_control_is_unknown() -> None:
    ctx = _ctx(_Capture({_GOOD}))
    assert (await assess_proof(ctx, [_GOOD, _OTHER]))[1] == "lead"
    assert (await assess_proof(ctx, [_GOOD, _OTHER], require_all=False))[1] == "exploited"


@pytest.mark.asyncio
async def test_unbound_evidence_is_a_lead() -> None:
    _, status, reason, _ = await assess_proof(_ctx(_Capture({_GOOD})), [_GOOD], captured=False)
    assert status == "lead"
    assert reason is not None
    assert "not bound" in reason


@pytest.mark.asyncio
async def test_source_comes_from_the_id_that_verified() -> None:
    # Unknown numeric id first, then a gateway capture that verifies: the source is the capture's.
    ids, status, _, source = await assess_proof(
        _ctx(_Capture({_GOOD})), ["4242", _GOOD], require_all=False
    )
    assert (ids, status, source) == ([_GOOD], "exploited", "gateway_capture")


@pytest.mark.asyncio
async def test_require_all_verifies_every_cited_id() -> None:
    third = "gw-0123456789ab-" + "c" * 32
    _, status, reason, _ = await assess_proof(
        _ctx(_Capture({_GOOD, _OTHER})), [_GOOD, _OTHER, third]
    )
    assert status == "lead" and reason is not None and reason.startswith(PROOF_FAILED_PREFIX)
    ids, status, _, _ = await assess_proof(
        _ctx(_Capture({_GOOD, _OTHER, third})), [_GOOD, _OTHER, third]
    )
    assert (ids, status) == ([_GOOD, _OTHER, third], "exploited")


class _Signed(_Capture):
    def __init__(self, known: set[str], *, verified: bool | None) -> None:
        super().__init__(known)
        self.verified = verified

    async def view_request(self, request_id: str, *, part: str = "request") -> Any:
        del request_id, part
        out = {
            "request": SimpleNamespace(raw="GET / HTTP/1.1"),
            "response": SimpleNamespace(raw="HTTP/1.1 200 OK"),
            "integrity_sha256": "d" * 64,
            "captured_at": "2026-11-26T10:00:00Z",
        }
        if self.verified is not None:
            out["integrity_verified"] = self.verified
        return SimpleNamespace(**out)


@pytest.mark.asyncio
async def test_a_verified_capture_returns_its_hash_and_time() -> None:
    out = await assess_proof_with_integrity(_ctx(_Signed({_GOOD}, verified=True)), [_GOOD])
    assert out == ([_GOOD], "exploited", None, "gateway_capture", "d" * 64, "2026-11-26T10:00:00Z")


@pytest.mark.asyncio
@pytest.mark.parametrize("verified", [False, None])
async def test_assess_proof_itself_refuses_a_capture_that_does_not_verify(
    verified: bool | None,
) -> None:
    # The integrity check lives behind assess_proof, so every caller gets it.
    ids, status, reason, source = await assess_proof(
        _ctx(_Signed({_GOOD}, verified=verified)), [_GOOD], require_all=False
    )
    assert status == "lead" and source is None and ids is None
    assert reason is not None and "integrity" in reason


class _Mixed(_Capture):
    """Two captures: the first fails its hash check, the second verifies."""

    async def view_request(self, request_id: str, *, part: str = "request") -> Any:
        del part
        ok = request_id == _OTHER
        return SimpleNamespace(
            request=SimpleNamespace(raw="GET / HTTP/1.1"),
            response=SimpleNamespace(raw="HTTP/1.1 200 OK"),
            integrity_sha256="e" * 64,
            integrity_verified=ok,
            captured_at="2026-11-26T10:00:00Z",
        )


@pytest.mark.asyncio
async def test_a_direct_report_needs_one_capture_that_verifies() -> None:
    ctx = _ctx(_Mixed({_GOOD, _OTHER}))
    _, status, _, source, sha, _ = await assess_proof_with_integrity(
        ctx, [_GOOD, _OTHER], require_all=False
    )
    assert (status, source, sha) == ("exploited", "gateway_capture", "e" * 64)
    ids, *_ = await assess_proof_with_integrity(ctx, [_GOOD, _OTHER], require_all=False)
    assert ids == [_OTHER]  # the capture that failed its hash is not kept as evidence
    # the promotion gate wants every cited capture to verify
    _, status, reason, _, _, _ = await assess_proof_with_integrity(ctx, [_GOOD, _OTHER])
    assert status == "lead" and reason is not None and "integrity" in reason
