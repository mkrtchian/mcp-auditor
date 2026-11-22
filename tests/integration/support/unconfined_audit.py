import io
from dataclasses import dataclass, field

from rich.console import Console

from mcp_auditor.adapters.server_launch import ServerLaunch
from mcp_auditor.audit import Analysts, Audit, AuditConfig, AuditRunOptions
from mcp_auditor.config import Settings
from mcp_auditor.console import AuditDisplay
from mcp_auditor.domain.models import AttackContext, TestCaseBatch
from mcp_auditor.domain.ports import LLMPort
from mcp_auditor.server_execution import ServerExecution
from tests.fakes import FakeContainerRuntime, FakeLLM
from tests.unit.auditor.support.graph_builders import a_judgment, a_payload


@dataclass(frozen=True)
class AuditVariant:
    """What an integration test varies in an unconfined audit of one case per tool, no chain."""

    llm: LLMPort = field(default_factory=lambda: FakeLLM([]))
    output: io.StringIO = field(default_factory=io.StringIO)
    resume: bool = False
    tools: frozenset[str] | None = None
    checkpoint_db: str = ":memory:"


def a_scripted_audit_of(launch: ServerLaunch, tools: frozenset[str] | None = None) -> Audit:
    # One case per tool, judged and summarized by the same scripted model.
    batch = TestCaseBatch(cases=[a_payload(arguments={"path": "/outside/flag"})])
    llm = FakeLLM([batch, a_judgment(), AttackContext()])
    return an_unconfined_audit(launch, AuditVariant(llm=llm, tools=tools))


def an_unconfined_audit(launch: ServerLaunch, variant: AuditVariant) -> Audit:
    config = AuditConfig(
        AuditRunOptions(test_budget=1, chain_budget=0, resume=variant.resume, dry_run=False),
        variant.checkpoint_db,
        variant.tools,
    )
    return Audit(
        config=config,
        execution=ServerExecution(launch, FakeContainerRuntime(untouchable=True)),
        analysts=Analysts(llm=variant.llm, judge=variant.llm, settings=Settings()),
        display=AuditDisplay(console=Console(file=variant.output, width=200)),
    )
