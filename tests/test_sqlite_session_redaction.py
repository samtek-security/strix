# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""Redaction scoping at the agents.db write boundary (issue #209).

Every write to the SDK's SQLite session store funnels through
``Session.add_items()`` on recon's own ``_PooledConnectionSession`` (the SDK's
own per-turn persistence included), so that is where redaction is applied -
scoped by which tool produced the item, never by secret shape alone. A target
secret captured by a raw-carrier tool (the proxy, the shell, an MCP call, the
exploitation workflow's live-proof evidence) is the finding, not noise, and
must reach storage untouched even if it happens to look like one of Recon's
own secret shapes. ``arguments``/``output`` are JSON-encoded strings on a real
session item (not parsed dicts), so the fixtures below match that shape.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from strix.core import sessions as sessions_module
from strix.core.sessions import _PooledConnectionSession
from strix.llm import redaction


if TYPE_CHECKING:
    from pathlib import Path


_SECRET = "sk-ant-abc123def456ghi789"  # noqa: S105 - fixture token


def _session(tmp_path: Path) -> _PooledConnectionSession:
    return _PooledConnectionSession(session_id="t", db_path=tmp_path / "agents.db")


def _call(name: str, call_id: str, **arguments: Any) -> dict[str, Any]:
    return {
        "type": "function_call",
        "name": name,
        "call_id": call_id,
        "arguments": json.dumps(arguments),
    }


def _output(call_id: str, output: str) -> dict[str, Any]:
    return {"type": "function_call_output", "call_id": call_id, "output": output}


@pytest.fixture(autouse=True)
def _no_registered_literals() -> None:
    # register_secret's set is process-global; keep tests isolated from
    # whatever another test (or a prior run in this process) registered.
    redaction._literal_secrets.clear()


async def test_unredacted_tool_call_and_output_pass_through_verbatim(tmp_path: Path) -> None:
    session = _session(tmp_path)
    await session.add_items(
        [
            _call("view_request", "c1", request_id="r1"),
            _output("c1", f"GET /admin\nAuthorization: Bearer {_SECRET}\n"),
        ]
    )
    stored = await session.get_items()
    assert json.loads(stored[0]["arguments"]) == {"request_id": "r1"}
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


async def test_plain_message_with_shape_matched_secret_is_not_redacted(tmp_path: Path) -> None:
    """A plain user/mailbox message may be operator-supplied content the
    scan depends on verbatim - a seeded ``--instruction`` test credential
    for an authenticated scan looks exactly like this. Only Recon's own
    registered literals are safe to remove here, never a shape match."""
    session = _session(tmp_path)
    await session.add_items([{"role": "user", "content": f"Authorization: Bearer {_SECRET}"}])
    stored = await session.get_items()
    assert _SECRET in stored[0]["content"]


async def test_plain_message_with_registered_literal_is_redacted(tmp_path: Path) -> None:
    secret = "recon-own-broker-token-0123456789"  # noqa: S105 - fixture token
    redaction.register_secret(secret)
    session = _session(tmp_path)
    await session.add_items([{"role": "user", "content": f"token={secret}"}])
    stored = await session.get_items()
    assert secret not in stored[0]["content"]


async def test_non_denylisted_tool_call_itself_is_still_shape_redacted(tmp_path: Path) -> None:
    """Fix 1 narrows the shape-based path to Recon's own tool calls/outputs,
    not away from them: a non-denylisted tool's own arguments are still
    Recon/LLM-synthesized content, safe to scan for a shape match."""
    session = _session(tmp_path)
    await session.add_items([_call("queue_finding", "c17", guard_evidence=_SECRET)])
    stored = await session.get_items()
    assert _SECRET not in stored[0]["arguments"]


async def test_promote_finding_evidence_never_shape_redacted(tmp_path: Path) -> None:
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
    assert json.loads(stored[0]["arguments"])["request"] == f"Authorization: Bearer {_SECRET}"


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


async def test_registered_literal_is_scrubbed_even_from_an_unredacted_tool(
    tmp_path: Path,
) -> None:
    """An exact registered literal (Recon's own credential) has no shape
    ambiguity, so it is scrubbed everywhere, including the raw-carrier tools
    that are otherwise left completely untouched."""
    redaction.register_secret("recon-own-broker-token-0123456789")
    session = _session(tmp_path)
    await session.add_items(
        [
            _call("exec_command", "c5", cmd="env"),
            _output("c5", "BROKER_TOKEN=recon-own-broker-token-0123456789\nOTHER=fine"),
        ]
    )
    stored = await session.get_items()
    assert "recon-own-broker-token-0123456789" not in stored[1]["output"]
    assert "[redacted]" in stored[1]["output"]
    assert "OTHER=fine" in stored[1]["output"]


async def test_shape_redaction_preserves_json_structure_in_arguments(tmp_path: Path) -> None:
    """A credential-header-named key inside a JSON-encoded ``arguments``
    string must not corrupt the surrounding JSON: the header-line scrubber
    consumes "to end of line" by design, which on a single-line JSON blob
    would otherwise swallow every sibling field after the match."""
    session = _session(tmp_path)
    await session.add_items(
        [
            _call(
                "queue_finding",
                "c6",
                title="t",
                Authorization=f"Bearer {_SECRET}",
                endpoint="/api/accounts",
            ),
        ]
    )
    stored = await session.get_items()
    parsed = json.loads(stored[0]["arguments"])  # raises if corrupted
    assert parsed["endpoint"] == "/api/accounts"
    assert _SECRET not in parsed["Authorization"]


async def test_oversized_json_number_does_not_crash_persistence(tmp_path: Path) -> None:
    """A huge integer literal in captured content makes ``json.loads`` raise
    ``ValueError`` (CPython's int-string-conversion guard), not
    ``JSONDecodeError`` - persistence must degrade to plain-text redaction,
    not propagate and abort the write."""
    session = _session(tmp_path)
    huge_number_output = f'{{"id": {"9" * 5000}, "token": "{_SECRET}"}}'
    await session.add_items(
        [
            _call("queue_finding", "c9", title="t"),
            _output("c9", huge_number_output),
        ]
    )
    stored = await session.get_items()
    assert _SECRET not in stored[1]["output"]


async def test_deeply_nested_secret_is_redacted_not_passed_through(tmp_path: Path) -> None:
    """Past the shape-based recursion cutoff, a compound value must not be
    returned unchanged - that would silently skip redacting whatever secret
    lives in the unvisited subtree."""
    session = _session(tmp_path)
    nested: Any = _SECRET
    for _ in range(12):
        nested = {"nested": nested}
    await session.add_items(
        [
            _call("queue_finding", "c10", title="t"),
            {"type": "function_call_output", "call_id": "c10", "output": json.dumps(nested)},
        ]
    )
    stored = await session.get_items()
    assert _SECRET not in stored[1]["output"]


async def test_deeply_nested_literal_in_an_unredacted_tool_is_not_destroyed(
    tmp_path: Path,
) -> None:
    """The literal-only pass on raw-carrier tool data must never fall back to
    a blunt REDACTED past its recursion cutoff - that would destroy target
    evidence, which this scoping exists specifically to preserve."""
    session = _session(tmp_path)
    nested: Any = "target evidence at the bottom"
    for _ in range(12):
        nested = {"nested": nested}
    await session.add_items(
        [
            _call("exec_command", "c11", cmd="curl ..."),
            {"type": "function_call_output", "call_id": "c11", "output": json.dumps(nested)},
        ]
    )
    stored = await session.get_items()
    assert "target evidence at the bottom" in stored[1]["output"]


async def test_registered_literal_with_special_chars_is_found_inside_json(
    tmp_path: Path,
) -> None:
    """A registered literal containing a quote/backslash comes out
    JSON-escaped once embedded in a serialized blob; a plain substring
    search against the escaped text would never match the literal as
    registered, letting a fully reconstructable secret survive."""
    secret = 'sec"ret\\value-0123456789'  # noqa: S105 - fixture token
    redaction.register_secret(secret)
    session = _session(tmp_path)
    await session.add_items(
        [
            _call("exec_command", "c12", cmd="env"),
            _output("c12", json.dumps({"token": secret})),
        ]
    )
    stored = await session.get_items()
    assert secret not in stored[1]["output"]
    scrubbed_token = json.loads(stored[1]["output"])["token"]
    assert scrubbed_token == redaction.REDACTED


async def test_web_recon_results_are_not_shape_redacted(tmp_path: Path) -> None:
    """A fetched page or search result is target-sourced the same way a
    proxy capture is - a leaked credential on it is the finding."""
    session = _session(tmp_path)
    await session.add_items(
        [
            _call("web_get_contents", "c13", urls=["https://example.com"]),
            _output("c13", f"leaked in page source: {_SECRET}"),
        ]
    )
    stored = await session.get_items()
    assert _SECRET in stored[1]["output"]


async def test_recursion_error_from_json_loads_does_not_crash_persistence(
    tmp_path: Path,
) -> None:
    """A pathologically nested JSON string makes ``json.loads`` raise
    ``RecursionError`` on some builds; persistence must degrade to
    plain-text redaction rather than propagate and abort the write."""
    session = _session(tmp_path)
    pathological = "[" * 100_000 + "]" * 100_000
    await session.add_items(
        [
            _call("queue_finding", "c14", title="t"),
            _output("c14", f"{pathological} token {_SECRET}"),
        ]
    )
    stored = await session.get_items()
    assert _SECRET not in stored[1]["output"]


async def test_registered_literal_used_as_a_json_key_is_redacted(tmp_path: Path) -> None:
    secret = "recon-own-broker-token-0123456789"  # noqa: S105 - fixture token
    redaction.register_secret(secret)
    session = _session(tmp_path)
    await session.add_items(
        [
            _call("exec_command", "c15", cmd="env"),
            _output("c15", json.dumps({secret: "some-value", "other": "fine"})),
        ]
    )
    stored = await session.get_items()
    assert secret not in stored[1]["output"]
    parsed = json.loads(stored[1]["output"])
    assert parsed["other"] == "fine"


async def test_decoded_json_scalar_string_literal_is_redacted(tmp_path: Path) -> None:
    """``output`` can itself be a bare JSON-encoded string, not an object -
    the decoded value (not its still-escaped source) must be checked for a
    registered literal, same as the dict/list case."""
    secret = 'sec"ret\\value-0123456789'  # noqa: S105 - fixture token
    redaction.register_secret(secret)
    session = _session(tmp_path)
    await session.add_items(
        [
            _call("exec_command", "c16", cmd="env"),
            _output("c16", json.dumps(secret)),
        ]
    )
    stored = await session.get_items()
    assert secret not in stored[1]["output"]


async def test_no_literal_match_preserves_raw_json_byte_for_byte(tmp_path: Path) -> None:
    """When nothing is registered (or nothing registered appears), a
    JSON-encoded carrier output must survive exactly as captured - a
    reparse+reserialize round-trip would silently drop a duplicate key and
    renormalize number/non-ASCII formatting, corrupting target evidence
    that was never touched."""
    session = _session(tmp_path)
    raw = '{"a": 1, "a": 2, "val": 1.50, "name": "café"}'
    await session.add_items(
        [
            _call("exec_command", "c18", cmd="curl ..."),
            _output("c18", raw),
        ]
    )
    stored = await session.get_items()
    assert stored[1]["output"] == raw


async def test_full_history_read_skipped_when_batch_resolves_itself(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The common case - a call and its matching output land in the same
    ``add_items`` batch, as a normal turn's own persistence does - must not
    pay for a full-session read just to classify the output."""
    session = _session(tmp_path)
    calls = []
    original = sessions_module._PooledConnectionSession.get_items

    async def _tracking_get_items(self: Any, *a: Any, **kw: Any) -> Any:
        calls.append((a, kw))
        return await original(self, *a, **kw)

    monkeypatch.setattr(
        sessions_module._PooledConnectionSession, "get_items", _tracking_get_items
    )

    await session.add_items(
        [
            _call("view_request", "c7", request_id="r1"),
            _output("c7", f"token {_SECRET}"),
        ]
    )
    assert calls == []

    await session.add_items([_output("c8", f"token {_SECRET}")])
    assert len(calls) == 1


async def test_escaped_literal_is_redacted_in_malformed_json(tmp_path: Path) -> None:
    """When the whole blob fails to parse as JSON (truncated, partial
    output), a registered literal's JSON-escaped substring form must still
    be found, not just its raw form - the escaped bytes alone are enough
    to fully reconstruct the secret."""
    secret = 'sec"ret\\value-0123456789'  # noqa: S105 - fixture token
    redaction.register_secret(secret)
    escaped_fragment = json.dumps(secret)[1:-1]  # drop the surrounding quotes
    malformed = f'{{"token": "{escaped_fragment}'  # truncated, not valid JSON
    session = _session(tmp_path)
    await session.add_items(
        [
            _call("exec_command", "c19", cmd="env"),
            _output("c19", malformed),
        ]
    )
    stored = await session.get_items()
    assert escaped_fragment not in stored[1]["output"]


async def test_escaped_literal_is_redacted_in_shape_based_malformed_text(
    tmp_path: Path,
) -> None:
    """The same escaped-form gap exists in the shape-based path's fallback
    (redact_text), reached by a non-denylisted tool's malformed-JSON
    output."""
    secret = 'sec"ret\\value-0123456789'  # noqa: S105 - fixture token
    redaction.register_secret(secret)
    escaped_fragment = json.dumps(secret)[1:-1]
    malformed = f'{{"token": "{escaped_fragment}'
    session = _session(tmp_path)
    await session.add_items(
        [
            _call("queue_finding", "c20", title="t"),
            _output("c20", malformed),
        ]
    )
    stored = await session.get_items()
    assert escaped_fragment not in stored[1]["output"]


async def test_colliding_keys_in_literal_only_pass_do_not_drop_a_value(
    tmp_path: Path,
) -> None:
    """Two different registered secrets used as JSON keys both redact to
    the same placeholder; the second must not silently overwrite the
    first's value."""
    secret_a = "recon-own-broker-token-aaaaaaaaaa"  # noqa: S105 - fixture token
    secret_b = "recon-own-broker-token-bbbbbbbbbb"  # noqa: S105 - fixture token
    redaction.register_secret(secret_a)
    redaction.register_secret(secret_b)
    session = _session(tmp_path)
    await session.add_items(
        [
            _call("exec_command", "c21", cmd="env"),
            _output("c21", json.dumps({secret_a: "value-for-a", secret_b: "value-for-b"})),
        ]
    )
    stored = await session.get_items()
    parsed = json.loads(stored[1]["output"])
    assert sorted(parsed.values()) == ["value-for-a", "value-for-b"]


async def test_colliding_keys_in_shape_based_pass_do_not_drop_a_value(
    tmp_path: Path,
) -> None:
    """The same key-collision risk exists in the shape-based walker
    (reached by a non-denylisted tool), one shape match per key."""
    session = _session(tmp_path)
    key_a = f"{_SECRET}-a"
    key_b = f"{_SECRET}-b"
    await session.add_items(
        [
            _call("queue_finding", "c22", title="t"),
            _output("c22", json.dumps({key_a: "value-for-a", key_b: "value-for-b"})),
        ]
    )
    stored = await session.get_items()
    parsed = json.loads(stored[1]["output"])
    assert sorted(parsed.values()) == ["value-for-a", "value-for-b"]


async def test_proxy_index_and_sitemap_tools_are_not_shape_redacted(
    tmp_path: Path,
) -> None:
    """list_requests/list_sitemap/view_sitemap_entry return target-reflecting
    request/response fields (a token in a query string) the same way
    view_request does."""
    session = _session(tmp_path)
    for tool, call_id in (
        ("list_requests", "c23"),
        ("list_sitemap", "c24"),
        ("view_sitemap_entry", "c25"),
    ):
        await session.add_items(
            [
                _call(tool, call_id, scope_id="s1"),
                _output(call_id, f"?token={_SECRET}"),
            ]
        )
    stored = await session.get_items()
    outputs = [item["output"] for item in stored if item.get("type") == "function_call_output"]
    assert all(_SECRET in output for output in outputs)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
