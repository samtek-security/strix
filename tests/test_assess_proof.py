# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""``assess_proof`` is the one proof decision both report-filing tools share."""

from __future__ import annotations

from typing import Any

import pytest
from agents.tool_context import ToolContext

from strix.tools.exploitation.tool import (
    NO_EXCHANGE_SOURCE_REASON,
    PROOF_FAILED_PREFIX,
    assess_proof,
)


_GOOD = "gw-0123456789ab-" + "a" * 32
_OTHER = "gw-0123456789ab-" + "b" * 32


class _Capture:
    _is_gateway_capture = True

    def __init__(self, known: set[str]) -> None:
        self.known = known

    async def capture_exists(self, request_id: str) -> bool:
        return request_id in self.known


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
