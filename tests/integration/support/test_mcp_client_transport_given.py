import io
import pathlib
import sys

from rich.console import Console

import tests.unit.support.test_graph_given as graph
from mcp_auditor.adapters.server_launch import ServerLaunch
from mcp_auditor.audit import Analysts, Audit, AuditConfig, CIOptions, ExecutionConfig
from mcp_auditor.config import Settings
from mcp_auditor.console import AuditDisplay
from mcp_auditor.domain import AttackContext, TestCaseBatch
from mcp_auditor.report_files import ReportPaths
from mcp_auditor.target_execution import LaunchOptions, TargetExecution
from tests.fakes import FakeContainerRuntime, FakeLLM

STUB_PATH = pathlib.Path(__file__).resolve().parent / "cve_replay_stub_server.py"


def a_stub(*flags: str) -> ServerLaunch:
    return ServerLaunch.unconfined(sys.executable, [str(STUB_PATH), *flags])


def an_audit_of(launch: ServerLaunch) -> Audit:
    # One read case, judged and summarized by the same scripted model, no chain.
    batch = TestCaseBatch(cases=[graph.a_payload(arguments={"path": "/outside/flag"})])
    llm = FakeLLM([batch, graph.a_judgment(), AttackContext()])
    config = AuditConfig(
        execution=ExecutionConfig(budget=1, chains=0, resume=False, dry_run=False),
        report_paths=ReportPaths(),
        ci=CIOptions(),
        launch=LaunchOptions(unconfined=True, image=None, mounts=()),
    )
    return Audit(
        config=config,
        execution=TargetExecution(launch, FakeContainerRuntime(untouchable=True)),
        analysts=Analysts(llm=llm, judge=llm, settings=Settings()),
        display=AuditDisplay(console=Console(file=io.StringIO(), width=200)),
    )
