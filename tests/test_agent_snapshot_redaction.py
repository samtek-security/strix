"""The coordinator's resume snapshot scrubs agent-controlled free text.

``agents.json`` persists for the life of a scan (and for ``--resume``), so a
spawned agent's name/task and inter-agent mailbox messages - explicitly meant
to carry a discovered credential, per ``send_message_to_agent``'s own
docstring - must not reach disk unredacted.
"""

from __future__ import annotations

from strix.core.agents import AgentCoordinator
from strix.llm import redaction


SECRET = "sk-ant-api03-LEAK0123456789abcdef"  # noqa: S105 - fixture token


async def test_snapshot_redacts_a_secret_shaped_task() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "agent", parent_id=None, task=f"use {SECRET} on the target")

    snap = await coordinator.snapshot()

    assert SECRET not in snap["metadata"]["root"]["task"]
    assert redaction.REDACTED in snap["metadata"]["root"]["task"]


async def test_snapshot_redacts_a_secret_shaped_mailbox_message() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "agent", parent_id=None)
    await coordinator.register("child", "agent", parent_id="root")
    await coordinator.send("child", {"from": "root", "content": f"found {SECRET}, use it"})

    snap = await coordinator.snapshot()

    [message] = snap["mailboxes"]["child"]
    assert SECRET not in message["content"]
    assert redaction.REDACTED in message["content"]


async def test_snapshot_redacts_a_secret_shaped_agent_name() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", f"agent holding {SECRET}", parent_id=None)

    snap = await coordinator.snapshot()

    assert SECRET not in snap["names"]["root"]


async def test_snapshot_leaves_the_live_coordinator_state_unredacted() -> None:
    """A live agent keeps acting on the real value; only the disk copy is scrubbed."""
    coordinator = AgentCoordinator()
    await coordinator.register("root", "agent", parent_id=None, task=f"use {SECRET}")
    await coordinator.register("child", "agent", parent_id="root")
    await coordinator.send("child", {"from": "root", "content": SECRET})

    await coordinator.snapshot()

    assert coordinator.metadata["root"]["task"] == f"use {SECRET}"
    assert coordinator.runtimes["child"].mailbox[0]["content"] == SECRET


async def test_snapshot_does_not_touch_ordinary_prose() -> None:
    """Shape-based only: a plain discovered password with no recognizable shape survives.

    Resuming a scan after a crash still needs the real value to keep working
    with it; only a credential-shaped or credential-named value is scrubbed.
    """
    coordinator = AgentCoordinator()
    plain_task = "check /admin with the password hunter2 found in config.yml"
    await coordinator.register("root", "agent", parent_id=None, task=plain_task)

    snap = await coordinator.snapshot()

    assert snap["metadata"]["root"]["task"] == plain_task


async def test_restore_round_trips_a_redacted_snapshot() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "agent", parent_id=None, task=f"use {SECRET}")

    snap = await coordinator.snapshot()

    restored = AgentCoordinator()
    await restored.restore(snap)

    assert restored.metadata["root"]["task"] == snap["metadata"]["root"]["task"]
    assert SECRET not in restored.metadata["root"]["task"]
