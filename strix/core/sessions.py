# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
"""SDK session helpers for Recon agents."""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, cast
from weakref import WeakKeyDictionary

from agents.items import ItemHelpers
from agents.memory import SQLiteSession

from strix.llm import redaction


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

    from agents.items import TResponseInputItem
    from agents.memory import Session


logger = logging.getLogger(__name__)

# Tools whose call arguments or output reflect the target or an external
# system verbatim: the exploitation workflow's Level-3 live-request proof, raw
# HTTP captures from the proxy, and arbitrary MCP results. A call to one of
# these is never redacted, whatever it contains - a target's own leaked
# credential is the finding, not noise to scrub, and shape-based matching
# can't tell "Recon's own token" from "a target's token" when both happen to
# be a JWT or a Bearer string. Scoped at the whole-call granularity (not
# per-field) since splitting a single call's arguments into redact/don't-
# redact halves is itself a correctness risk this isn't worth taking for the
# few surrounding fields (title/description context) it would spare.
_UNREDACTED_TOOL_NAMES = frozenset(
    {
        "view_request",
        "repeat_request",
        "call_mcp",
        "promote_finding",
        "exec_command",
        "write_stdin",
    }
)


class _PooledConnectionSession(SQLiteSession):
    @contextmanager
    def _locked_connection(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            if self._closed:
                raise RuntimeError("SQLiteSession is closed")
            if self._is_memory_db:
                yield self._shared_connection
                return
            connection = sqlite3.connect(str(self.db_path), check_same_thread=False)
            try:
                yield connection
            finally:
                connection.close()

    async def add_items(self, items: list[TResponseInputItem]) -> None:
        await super().add_items(await self._redact_for_storage(items))

    async def _redact_for_storage(
        self, items: list[TResponseInputItem]
    ) -> list[TResponseInputItem]:
        unredacted_call_ids = await self._unredacted_call_ids(items)
        return [
            cast(
                "TResponseInputItem",
                self._redact_item(cast("dict[str, Any]", item), unredacted_call_ids),
            )
            for item in items
        ]

    async def _unredacted_call_ids(self, new_items: list[Any]) -> set[str]:
        """``call_id`` values whose originating call was an unredacted tool.

        Resolved against the whole session, not just ``new_items``: a call
        and its output can land in separate ``add_items`` batches (a resume
        replays the call from a prior process), and getting this the wrong
        way - treating an unredacted tool's output as unknown and redacting
        it - is the one mistake this exists to prevent.
        """
        call_ids = {
            item["call_id"]
            for item in new_items
            if _is_unredacted_call(item) and isinstance(item.get("call_id"), str)
        }
        has_output_item = any(
            isinstance(item, dict) and item.get("type") == "function_call_output"
            for item in new_items
        )
        if not has_output_item:
            return call_ids
        # Explicit ``limit=None``: this lookup must see the whole history
        # regardless of any session-settings default limit, or a call made
        # far enough back could be missed and its output wrongly redacted.
        existing: list[Any] = await self.get_items(limit=None)
        call_ids.update(
            item["call_id"]
            for item in existing
            if _is_unredacted_call(item) and isinstance(item.get("call_id"), str)
        )
        return call_ids

    def _redact_item(self, item: Any, unredacted_call_ids: set[str]) -> Any:
        if not isinstance(item, dict):
            return item
        item_type = item.get("type")
        if item_type == "function_call" and item.get("name") in _UNREDACTED_TOOL_NAMES:
            return item
        if item_type == "function_call_output" and item.get("call_id") in unredacted_call_ids:
            return item
        return redaction.redact_structure(item)


def _is_unredacted_call(item: Any) -> bool:
    return (
        isinstance(item, dict)
        and item.get("type") == "function_call"
        and item.get("name") in _UNREDACTED_TOOL_NAMES
    )


def open_agent_session(agent_id: str, path: Path) -> SQLiteSession:
    path.parent.mkdir(parents=True, exist_ok=True)
    return _PooledConnectionSession(session_id=agent_id, db_path=path)


async def seed_initial_input(session: Session, initial_input: Any) -> bool:
    """Commit an agent's opening identity/task input before its first run cycle."""
    items = ItemHelpers.input_to_new_input_list(initial_input)
    if not items:
        return False
    async with session_write_lock(session):
        if await session.get_items():
            return False
        await session.add_items(items)
    return True


_IMAGE_REJECTED_TEXT = "[image rejected by the model]"
_IMAGE_ELIDED_TEXT = "[older screenshot elided to bound context memory]"
_INHERITED_IMAGE_TEXT = "[screenshot omitted from inherited context]"


def _output_has_image(item_dict: dict[str, Any]) -> bool:
    return (
        item_dict.get("type") == "function_call_output"
        and isinstance(item_dict.get("output"), list)
        and any(isinstance(b, dict) and b.get("type") == "input_image" for b in item_dict["output"])
    )


def _elided_output(item_dict: dict[str, Any], text: str) -> dict[str, Any]:
    # Replace only image blocks; sibling text blocks are preserved.
    output = item_dict.get("output")
    blocks = output if isinstance(output, list) else []
    return {
        "type": "function_call_output",
        "call_id": item_dict.get("call_id"),
        "output": [
            {"type": "input_text", "text": text}
            if isinstance(block, dict) and block.get("type") == "input_image"
            else block
            for block in blocks
        ],
    }


_session_write_locks: WeakKeyDictionary[Session, asyncio.Lock] = WeakKeyDictionary()


def session_write_lock(session: Session) -> asyncio.Lock:
    """Lock serialising all out-of-band writes to ``session``."""
    lock = _session_write_locks.get(session)
    if lock is None:
        lock = asyncio.Lock()
        _session_write_locks[session] = lock
    return lock


async def _rewrite_session(
    session: Session,
    transform: Callable[[list[Any]], tuple[list[Any], bool]],
) -> bool:
    """Read-modify-write a session under its write lock, restoring on failure."""
    async with session_write_lock(session):
        items = await session.get_items()
        if not items:
            return False
        rebuilt, changed = transform(list(items))
        if not changed:
            return False
        rebuilt_items = cast("list[TResponseInputItem]", rebuilt)
        original_items = cast("list[TResponseInputItem]", list(items))
        await session.clear_session()
        try:
            await session.add_items(rebuilt_items)
        except Exception:
            logger.exception("session rewrite failed; restoring original items")
            await session.clear_session()
            await session.add_items(original_items)
            raise
        return True


async def replace_session_items(
    session: Session,
    new_items: list[Any],
    *,
    expected_len: int | None = None,
) -> bool:
    """Overwrite the session's items, restoring the originals on failure.

    When ``expected_len`` is given, the rewrite is skipped if the session no
    longer has that many items (a concurrent writer changed it), so a slow
    compaction summary can't clobber newer turns.
    """
    async with session_write_lock(session):
        original = list(await session.get_items())
        if expected_len is not None and len(original) != expected_len:
            logger.warning(
                "skipping session rewrite: expected %d items, found %d",
                expected_len,
                len(original),
            )
            return False
        rebuilt = cast("list[TResponseInputItem]", new_items)
        await session.clear_session()
        try:
            await session.add_items(rebuilt)
        except Exception:
            logger.exception("session rewrite failed; restoring original items")
            await session.clear_session()
            await session.add_items(original)
            raise
        return True


async def strip_all_images_from_session(session: Session) -> bool:
    """Replace every image tool output with a text placeholder (rejection recovery)."""

    def _transform(items: list[Any]) -> tuple[list[Any], bool]:
        rebuilt: list[Any] = []
        changed = False
        for item in items:
            item_dict = cast("dict[str, Any]", item) if isinstance(item, dict) else None
            if item_dict is not None and _output_has_image(item_dict):
                rebuilt.append(_elided_output(item_dict, _IMAGE_REJECTED_TEXT))
                changed = True
            else:
                rebuilt.append(item)
        return rebuilt, changed

    return await _rewrite_session(session, _transform)


async def enforce_image_budget(session: Session, max_images: int) -> bool:
    """Keep only the most recent ``max_images`` image outputs; elide older ones."""
    if max_images < 0:
        return False

    def _transform(items: list[Any]) -> tuple[list[Any], bool]:
        image_indices = [
            i
            for i, item in enumerate(items)
            if isinstance(item, dict) and _output_has_image(cast("dict[str, Any]", item))
        ]
        if len(image_indices) <= max_images:
            return items, False
        to_elide = set(image_indices[: len(image_indices) - max_images])
        rebuilt = [
            _elided_output(cast("dict[str, Any]", item), _IMAGE_ELIDED_TEXT)
            if i in to_elide
            else item
            for i, item in enumerate(items)
        ]
        return rebuilt, True

    return await _rewrite_session(session, _transform)


def scrub_images_from_items(items: list[Any], *, text: str = _INHERITED_IMAGE_TEXT) -> list[Any]:
    """Return a copy of ``items`` with every image block replaced by text."""

    def _scrub(obj: Any) -> Any:
        if isinstance(obj, dict):
            if obj.get("type") == "input_image":
                return {"type": "input_text", "text": text}
            return {k: _scrub(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_scrub(v) for v in obj]
        return obj

    return [_scrub(item) for item in items]
