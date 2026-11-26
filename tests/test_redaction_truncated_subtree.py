# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""Literal redaction past the depth bound must not merge sibling keys."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from strix.llm import redaction
from strix.llm.redaction import REDACTED, REDACTED_SUBTREE, redact_literals_in_structure


if TYPE_CHECKING:
    from collections.abc import Iterator


SECRET_A = "recon-own-broker-token-aaaa0123456789"  # noqa: S105 - fixture token
SECRET_B = "recon-own-broker-token-bbbb0123456789"  # noqa: S105 - fixture token
SECRET_C = "recon-own-broker-token-cccc0123456789"  # noqa: S105 - fixture token


@pytest.fixture(autouse=True)
def _secrets() -> Iterator[None]:
    before = set(redaction._literal_secrets)
    redaction._literal_secrets.clear()
    for secret in (SECRET_A, SECRET_B, SECRET_C):
        redaction.register_secret(secret)
    try:
        yield
    finally:
        redaction._literal_secrets.clear()
        redaction._literal_secrets.update(before)


def _nest(levels: int, leaf: Any, top: dict[str, Any] | None = None) -> dict[str, Any]:
    node: Any = leaf
    for _ in range(levels):
        node = {"n": node}
    if top:
        node = {**top, **node}
    return node


def _walk_leaf(parsed: Any) -> Any:
    while isinstance(parsed, dict) and "n" in parsed:
        parsed = parsed["n"]
    return parsed


def _assert_clean(text: str) -> None:
    for secret in (SECRET_A, SECRET_B, SECRET_C):
        assert secret not in text


def _assert_no_silent_loss(result: str, leaf: dict[str, Any]) -> None:
    _assert_clean(result)
    if REDACTED_SUBTREE in result:
        return
    reparsed = _walk_leaf(json.loads(result))
    assert sorted(reparsed.values()) == sorted(leaf.values())


@pytest.mark.parametrize("levels", [64, 66])
def test_changed_branch_keeps_both_colliding_keys(levels: int) -> None:
    leaf = {SECRET_A: 1, SECRET_B: 2}
    text = json.dumps(_nest(levels, leaf, top={SECRET_C: "top"}))

    result = redact_literals_in_structure(text)

    _assert_no_silent_loss(result, leaf)
    deep = _walk_leaf(json.loads(result))
    assert set(deep) == {REDACTED, f"{REDACTED}#2"}


@pytest.mark.parametrize("levels", [64, 70])
def test_unchanged_branch_keeps_both_colliding_keys(levels: int) -> None:
    leaf = {SECRET_A: 1, SECRET_B: 2}
    text = json.dumps(_nest(levels, leaf))

    result = redact_literals_in_structure(text)

    _assert_no_silent_loss(result, leaf)
    deep = _walk_leaf(json.loads(result))
    assert set(deep) == {REDACTED, f"{REDACTED}#2"}


def test_truncated_secret_values_are_redacted() -> None:
    text = json.dumps(_nest(70, {"k": SECRET_A, "list": [SECRET_B]}))

    result = redact_literals_in_structure(text)

    _assert_clean(result)
    assert json.loads(result) != json.loads(text)
    assert _walk_leaf(json.loads(result)) == {"k": REDACTED, "list": [REDACTED]}


def test_direct_deep_structure_is_scrubbed_without_collisions() -> None:
    value = _nest(70, {SECRET_A: 1, SECRET_B: 2})

    result = redact_literals_in_structure(value)

    _assert_clean(json.dumps(result))
    deep = _walk_leaf(result)
    assert deep == {REDACTED: 1, f"{REDACTED}#2": 2}


def test_unresolvable_collision_uses_the_subtree_marker() -> None:
    # The first "a" member is shadowed by the second, so the walk never sees
    # its two secret keys; a blind text scrub would merge them.
    shadowed = json.dumps({SECRET_A: 1, SECRET_B: 2})
    deep = json.dumps(_nest(70, {"x": 1}))[1:-1]
    text = f'{{"a": {shadowed}, "a": {{}}, {deep}}}'
    assert json.loads(text)

    result = redact_literals_in_structure(text)

    _assert_clean(result)
    assert json.loads(result)
    assert REDACTED_SUBTREE in result


def test_without_truncation_the_shadowed_member_is_still_scrubbed() -> None:
    text = f'{{"k": "{SECRET_A}", "k": "ok"}}'

    result = redact_literals_in_structure(text)

    _assert_clean(result)
    assert json.loads(result) == {"k": "ok"}


def test_input_with_duplicate_keys_and_no_secret_is_unchanged() -> None:
    text = json.dumps(_nest(70, {"x": 1}))
    text = text.replace('{"n"', '{"d": 1, "d": 2, "n"', 1)

    assert redact_literals_in_structure(text) == text


def test_truncated_input_with_nothing_to_redact_is_unchanged() -> None:
    text = json.dumps(_nest(70, {"x": 1, "y": [1, 2]}), indent=2)

    assert redact_literals_in_structure(text) == text


def test_walk_reports_truncation() -> None:
    walk = redaction._redact_literals_in_structure
    assert walk(_nest(10, {"x": 1}), 0)[2] is False
    assert walk(_nest(70, {"x": 1}), 0)[2] is True
    assert walk(_nest(70, {"x": 1}), 0, mark_truncated=True)[0]["n"] is not None


def test_duplicate_members_survive_a_deep_redaction() -> None:
    deep = json.dumps(_nest(70, {"k": SECRET_A}))[1:-1]
    text = f'{{"d": 1, "d": 2, {deep}}}'

    result = redact_literals_in_structure(text)

    _assert_clean(result)
    assert '"d": 1, "d": 2' in result


def test_json_string_below_the_cutoff_keeps_colliding_keys() -> None:
    inner = json.dumps({SECRET_A: 1, SECRET_B: 2})
    text = json.dumps(_nest(70, {"payload": inner}))

    result = redact_literals_in_structure(text)

    _assert_clean(result)
    payload = _walk_leaf(json.loads(result))["payload"]
    assert payload == REDACTED_SUBTREE or json.loads(payload) == {
        REDACTED: 1,
        f"{REDACTED}#2": 2,
    }


def test_colliding_keys_with_a_repeated_member_become_the_marker() -> None:
    deep = json.dumps(_nest(70, {SECRET_A: 1, SECRET_B: 2}))[1:-1]
    text = f'{{"d": 1, "d": 2, {deep}}}'

    result = redact_literals_in_structure(text)

    _assert_clean(result)
    assert json.loads(result) == REDACTED_SUBTREE


def test_doubly_encoded_payload_below_the_cutoff_keeps_colliding_keys() -> None:
    inner = json.dumps({"p": json.dumps({SECRET_A: 1, SECRET_B: 2})})
    text = json.dumps(_nest(70, {"payload": inner}))

    result = redact_literals_in_structure(text)

    _assert_clean(result)
    payload = _walk_leaf(json.loads(result))["payload"]
    assert payload == REDACTED_SUBTREE or json.loads(json.loads(payload)["p"]) == {
        REDACTED: 1,
        f"{REDACTED}#2": 2,
    }


def test_repeated_member_in_a_string_below_the_cutoff_is_not_dropped() -> None:
    inner = f'{{"d": 1, "d": 2, "{SECRET_A}": 3, "{SECRET_B}": 4}}'
    text = json.dumps(_nest(70, {"payload": inner}))

    result = redact_literals_in_structure(text)

    _assert_clean(result)
    assert _walk_leaf(json.loads(result))["payload"] == REDACTED_SUBTREE


def test_json_string_wrapping_json_below_the_cutoff_keeps_colliding_keys() -> None:
    wrapped = json.dumps(json.dumps({SECRET_A: 1, SECRET_B: 2}))
    text = json.dumps(_nest(70, {"payload": wrapped}))

    result = redact_literals_in_structure(text)

    _assert_clean(result)
    payload = _walk_leaf(json.loads(result))["payload"]
    assert payload == REDACTED_SUBTREE or json.loads(json.loads(payload)) == {
        REDACTED: 1,
        f"{REDACTED}#2": 2,
    }


@pytest.mark.parametrize("levels", [62, 63, 64, 65])
def test_json_string_at_the_depth_boundary_keeps_colliding_keys(levels: int) -> None:
    inner = json.dumps({SECRET_A: 1, SECRET_B: 2})
    text = json.dumps(_nest(levels, inner))

    result = redact_literals_in_structure(text)

    _assert_clean(result)
    leaf = _walk_leaf(json.loads(result))
    assert leaf == REDACTED_SUBTREE or json.loads(leaf) == {REDACTED: 1, f"{REDACTED}#2": 2}


def test_json_string_at_the_boundary_in_a_direct_structure() -> None:
    inner = json.dumps({SECRET_A: 1, SECRET_B: 2})

    result = redact_literals_in_structure(_nest(64, inner))

    _assert_clean(json.dumps(result))
    leaf = _walk_leaf(result)
    assert json.loads(leaf) == {REDACTED: 1, f"{REDACTED}#2": 2}


def test_boundary_string_with_extreme_nesting_becomes_the_marker() -> None:
    inner = "[" * 900 + "]" * 900

    result = redact_literals_in_structure(_nest(64, inner))

    assert _walk_leaf(result) in (inner, REDACTED_SUBTREE)


def test_unparseable_json_string_below_the_cutoff_fails_closed() -> None:
    inner = '{"n": %s, "%s": 1, "%s": 2}' % ("9" * 5000, SECRET_A, SECRET_B)  # noqa: UP031
    text = json.dumps(_nest(70, {"payload": inner}))

    result = redact_literals_in_structure(text)

    _assert_clean(result)
    assert _walk_leaf(json.loads(result))["payload"] == REDACTED_SUBTREE
