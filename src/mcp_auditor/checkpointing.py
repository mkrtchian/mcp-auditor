"""The identity of an audit's thread, and the checkpoint database it is stored in."""

import hashlib
from pathlib import Path
from typing import Any

from mcp_auditor.adapters.server_launch import ServerLaunch
from mcp_auditor.domain.models import ExecutionRegime


def compute_thread_id(launch: ServerLaunch) -> str:
    # Every audit run before confinement was unconfined, and its id hashed the command
    # alone: keeping that form is what lets an audit interrupted then still resume. The
    # NUL separator is a character no argv element can contain, so no command can hash
    # like another regime's.
    full = " ".join([launch.command, *launch.args])
    if launch.regime != ExecutionRegime.UNCONFINED:
        full += "\0" + launch.regime
    return hashlib.sha256(full.encode()).hexdigest()[:16]


def checkpoint_db_path() -> str:
    checkpoint_dir = Path.home() / ".mcp-auditor"
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    return str(checkpoint_dir / "checkpoints.db")


async def resume_or_reset(graph: Any, thread_id: str, requested: bool) -> bool:
    """True to resume an interrupted audit, False after wiping the thread.

    A reused thread must be wiped: the operator.add reducers on tool_reports and
    provider_usage would otherwise fold the previous audit into this report.
    """
    # This read must precede the wipe: adelete_thread is the one saver method
    # that skips setup(), so on a virgin database it fails on a missing table.
    snapshot = await graph.aget_state({"configurable": {"thread_id": thread_id}})
    # `next` holds the nodes still to run, and discriminates where the mere
    # existence of a checkpoint cannot: it is empty both for a thread never
    # audited and for one whose audit ran to the end, which are exactly the two
    # unresumable cases. Resuming a completed thread runs no node at all and
    # replays its stored report as if it were a fresh audit.
    if requested and snapshot.next:
        return True
    await graph.checkpointer.adelete_thread(thread_id)
    return False
