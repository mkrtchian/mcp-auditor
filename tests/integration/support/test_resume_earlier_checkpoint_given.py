import io
import pathlib
import sys

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.base import empty_checkpoint
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver  # type: ignore[import-untyped]
from rich.console import Console

from mcp_auditor.adapters.server_launch import ServerLaunch
from mcp_auditor.audit import Analysts, Audit, AuditConfig, CIOptions, ExecutionConfig
from mcp_auditor.checkpointing import checkpoint_db_path, compute_thread_id
from mcp_auditor.config import Settings
from mcp_auditor.console import AuditDisplay
from mcp_auditor.report_files import ReportPaths
from mcp_auditor.target_execution import LaunchOptions, TargetExecution
from tests.fakes import FakeContainerRuntime, FakeLLM

SERVER_PATH = pathlib.Path(__file__).resolve().parent.parent.parent / "honeypot_server.py"
HONEYPOT = ServerLaunch.unconfined(sys.executable, [str(SERVER_PATH)])


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
    config = AuditConfig(
        execution=ExecutionConfig(budget=1, chains=0, resume=True, dry_run=False),
        report_paths=ReportPaths(),
        ci=CIOptions(),
        launch=LaunchOptions(unconfined=True, image=None, mounts=()),
    )
    return Audit(
        config=config,
        execution=TargetExecution(launch, FakeContainerRuntime(untouchable=True)),
        analysts=Analysts(llm=FakeLLM([]), judge=FakeLLM([]), settings=Settings()),
        display=AuditDisplay(console=Console(file=output, width=200)),
    )
