import io
from dataclasses import dataclass, field

from rich.console import Console

from mcp_auditor.adapters.server_launch import ServerLaunch
from mcp_auditor.audit import Analysts, Audit, AuditConfig, AuditRunOptions, CIOptions
from mcp_auditor.config import Settings
from mcp_auditor.console import AuditDisplay
from mcp_auditor.domain.ports import LLMPort
from mcp_auditor.report_files import ReportPaths
from mcp_auditor.server_execution import LaunchOptions, ServerExecution
from tests.fakes import FakeContainerRuntime, FakeLLM


@dataclass(frozen=True)
class AuditVariant:
    """What an integration test varies in an unconfined audit of one case per tool, no chain."""

    llm: LLMPort = field(default_factory=lambda: FakeLLM([]))
    output: io.StringIO = field(default_factory=io.StringIO)
    resume: bool = False
    tools: frozenset[str] | None = None


def an_unconfined_audit(launch: ServerLaunch, variant: AuditVariant) -> Audit:
    config = AuditConfig(
        run_options=AuditRunOptions(budget=1, chains=0, resume=variant.resume, dry_run=False),
        report_paths=ReportPaths(),
        ci=CIOptions(),
        launch=LaunchOptions(unconfined=True, image=None, mounts=()),
        tools_filter=variant.tools,
    )
    return Audit(
        config=config,
        execution=ServerExecution(launch, FakeContainerRuntime(untouchable=True)),
        analysts=Analysts(llm=variant.llm, judge=variant.llm, settings=Settings()),
        display=AuditDisplay(console=Console(file=variant.output, width=200)),
    )
