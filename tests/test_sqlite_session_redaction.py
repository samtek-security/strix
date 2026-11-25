# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""Redaction scoping at the agents.db write boundary (issue #209).

Every write to the SDK's SQLite session store funnels through
``Session.add_items()`` on recon's own ``_PooledConnectionSession`` (the SDK's
own per-turn persistence included), so that is where redaction is applied -
scoped by which tool produced the item, never by secret shape alone. A target
secret captured by a raw-carrier tool (the proxy, the shell, an MCP call, the
exploitation workflow's live-proof evidence) is the finding, not noise, and
must reach storage untouched even if it happens to look like one of Recon's
own secret shapes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from strix.core.sessions import _PooledConnectionSession


if TYPE_CHECKING:
    from pathlib import Path


_SECRET = "sk-ant-abc123def456ghi789"  # noqa: S105 - fixture token


def _session(tmp_path: Path) -> _PooledConnectionSession:
    return _PooledConnectionSession(session_id="t", db_path=tmp_path / "agents.db")


def _call(name: str, call_id: str, **arguments: Any) -> dict[str, Any]:
    return {"type": "function_call", "name": name, "call_id": call_id, "arguments": arguments}


def _output(call_id: str, output: Any) -> dict[str, Any]:
    return {"type": "function_call_output", "call_id": call_id, "output": output}


async def test_unredacted_tool_call_and_output_pass_through_verbatim(tmp_path: Path) -> None:
    session = _session(tmp_path)
    await session.add_items(
        [
            _call("view_request", "c1", request_id="r1"),
            _output("c1", f"GET /admin\nAuthorization: Bearer {_SECRET}\n"),
        ]
    )
    stored = await session.get_items()
    assert stored[0]["arguments"] == {"request_id": "r1"}
    assert _SECRET in stored[1]["output"]
    assert "Bearer" in stored[1]["output"]


async def test_non_denylisted_tool_output_is_redacted(tmp_path: Path) -> None:
    session = _session(tmp_path)
    await session.add_items(
        [
            _call("queue_finding", "c2", title="t"),
            _output("c2", f"found a key: {_SECRET}"),
        ]
    )
    stored = await session.get_items()
    assert _SECRET not in stored[1]["output"]
    assert "[redacted]" in stored[1]["output"]


async def test_plain_message_item_is_redacted(tmp_path: Path) -> None:
    session = _session(tmp_path)
    await session.add_items([{"role": "user", "content": f"token={_SECRET}"}])
    stored = await session.get_items()
    assert _SECRET not in stored[0]["content"]


async def test_promote_finding_evidence_never_redacted_even_with_secret_shape(
    tmp_path: Path,
) -> None:
    session = _session(tmp_path)
    await session.add_items(
        [
            _call(
                "promote_finding",
                "c3",
                item_id="q-0001",
                status="exploited",
                request=f"Authorization: Bearer {_SECRET}",
                response="200 OK",
            ),
        ]
    )
    stored = await session.get_items()
    assert stored[0]["arguments"]["request"] == f"Authorization: Bearer {_SECRET}"


async def test_output_correlates_to_a_call_from_an_earlier_add_items_batch(
    tmp_path: Path,
) -> None:
    """A resume replays the call and its output in separate batches; the
    correlation must hold across that split, not just within one call."""
    session = _session(tmp_path)
    await session.add_items([_call("exec_command", "c4", cmd="curl ...")])
    await session.add_items([_output("c4", f"token: {_SECRET}")])
    stored = await session.get_items()
    assert _SECRET in stored[1]["output"]


async def test_output_for_unknown_call_id_is_redacted_not_passed_through(
    tmp_path: Path,
) -> None:
    """Failing closed: an output whose call is not found anywhere in the
    session (never persisted, or from a tool not in the denylist) is treated
    as ordinary content, not given the benefit of the doubt."""
    session = _session(tmp_path)
    await session.add_items([_output("unknown-call", f"token: {_SECRET}")])
    stored = await session.get_items()
    assert _SECRET not in stored[0]["output"]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
