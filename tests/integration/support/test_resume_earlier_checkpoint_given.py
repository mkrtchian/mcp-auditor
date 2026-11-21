import io
import pathlib
import sys

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.base import empty_checkpoint
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver  # type: ignore[import-untyped]

from mcp_auditor.adapters.server_launch import ServerLaunch
from mcp_auditor.audit import Audit
from mcp_auditor.checkpointing import checkpoint_db_path, compute_thread_id
from tests.integration.support.support_servers import a_read_server
from tests.integration.support.unconfined_audit import AuditVariant, an_unconfined_audit

SERVER_PATH = pathlib.Path(__file__).resolve().parent.parent.parent / "honeypot_server.py"
HONEYPOT = ServerLaunch.unconfined(sys.executable, [str(SERVER_PATH)])
NOISY_SHUTDOWN_SERVER = a_read_server("noisy_shutdown")


async def a_checkpoint_from_an_earlier_version(launch: ServerLaunch) -> None:
    checkpoint = empty_checkpoint()
    checkpoint["channel_values"] = {"refused_steps": []}
    checkpoint["channel_versions"] = {"refused_steps": "1"}
    config: RunnableConfig = {
        "configurable": {"thread_id": compute_thread_id(launch), "checkpoint_ns": ""}
    }
    async with AsyncSqliteSaver.from_conn_string(checkpoint_db_path()) as checkpointer:
        await checkpointer.aput(config, checkpoint, {}, {"refused_steps": "1"})


def an_audit_resuming(launch: ServerLaunch, output: io.StringIO) -> Audit:
    return an_unconfined_audit(launch, AuditVariant(output=output, resume=True))
