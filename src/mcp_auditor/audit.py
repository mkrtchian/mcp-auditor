# pyright: reportUnknownMemberType=false
# One audit run: the server it probes, the models it reasons with, the budget it spends,
# and the report it yields. Outside the hexagon, like `cli.py`, which hands it a decided
# launch and reads back the report.
import tempfile
from dataclasses import dataclass
from typing import Any, NoReturn

from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver  # type: ignore[import-untyped]

from mcp_auditor.adapters.llm import create_judge_llm, create_llm
from mcp_auditor.adapters.mcp_client import StdioMCPClient
from mcp_auditor.checkpointing import checkpoint_db_path, compute_thread_id, resume_or_reset
from mcp_auditor.config import Settings, load_settings
from mcp_auditor.console import AuditDisplay, print_server_stderr, summarize_exception_group
from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.models import AttackContext, AuditReport, Severity
from mcp_auditor.domain.ports import LLMPort
from mcp_auditor.graph.builder import build_dry_run_graph, build_graph
from mcp_auditor.report_files import ReportPaths
from mcp_auditor.stream_handler import AuditProgressReporter
from mcp_auditor.target_execution import LaunchOptions, TargetExecution

DEFAULT_MAX_CHAIN_STEPS = 3


@dataclass(frozen=True)
class CIOptions:
    enabled: bool = False
    severity_threshold: Severity = Severity.MEDIUM


@dataclass(frozen=True)
class ExecutionConfig:
    budget: int
    chains: int
    resume: bool
    dry_run: bool


@dataclass(frozen=True)
class AuditConfig:
    execution: ExecutionConfig
    report_paths: ReportPaths
    ci: CIOptions
    launch: LaunchOptions
    tools_filter: frozenset[str] | None = None


@dataclass(frozen=True)
class Analysts:
    """The models an audit reasons with, and the settings they were hired under.

    `settings` is their provenance: which provider answers, under which model name the
    run is traced, and how long a tool call may take before the audit gives up on it.
    """

    llm: LLMPort
    judge: LLMPort
    settings: Settings

    @classmethod
    def hired(cls) -> "Analysts":
        settings = load_settings()
        return cls(
            llm=create_llm(settings),
            judge=create_judge_llm(settings),
            settings=settings,
        )


class Audit:
    """One run against one target, from the launched container to the finished report."""

    def __init__(
        self,
        config: AuditConfig,
        execution: TargetExecution,
        analysts: Analysts,
        display: AuditDisplay,
    ):
        self._config = config
        self._execution = execution
        self._analysts = analysts
        self._display = display

    async def run(self) -> AuditReport | None:
        """The report, or None for a dry run, which shows payloads and audits nothing."""
        server_stderr = tempfile.SpooledTemporaryFile(max_size=1024 * 1024, mode="w+")  # noqa: SIM115
        try:
            report = await self._probe_the_target(server_stderr)
        except ConnectionError as exc:
            self._give_up(f"could not connect to MCP server: {exc}", server_stderr, exc)
        except OSError as exc:
            self._give_up(str(exc), server_stderr, exc)
        except BaseExceptionGroup as exc:
            self._give_up(
                f"MCP server failed: {summarize_exception_group(exc)}", server_stderr, exc
            )
        if report is None:
            return None
        # The container's kill state is known only once the execution's block has exited.
        return report.model_copy(update={"execution": self._execution.record})

    async def _probe_the_target(
        self, server_stderr: "tempfile.SpooledTemporaryFile[str]"
    ) -> AuditReport | None:
        async with (
            self._execution,
            AsyncSqliteSaver.from_conn_string(checkpoint_db_path()) as checkpointer,
            StdioMCPClient.connect(
                self._execution.launch,
                errlog=server_stderr,
                tool_call_timeout=self._analysts.settings.tool_call_timeout,
            ) as mcp_client,
        ):
            server = AuditedServer(mcp_client)
            if self._config.execution.dry_run:
                await self._show_payloads(server)
                return None
            return await self._audit(server, checkpointer)

    async def _audit(self, server: AuditedServer, checkpointer: Any) -> AuditReport:
        graph = build_graph(
            self._analysts.llm,
            server,
            judge_llm=self._analysts.judge,
            checkpointer=checkpointer,
            tools_filter=self._config.tools_filter,
        )
        thread_id = compute_thread_id(self._execution.launch)
        resuming = await resume_or_reset(graph, thread_id, self._config.execution.resume)
        if self._config.execution.resume and not resuming:
            self._display.print_info("nothing to resume for this target, starting a fresh audit")
        return await self._stream(graph, thread_id, None if resuming else self._initial_state())

    async def _stream(
        self, graph: Any, thread_id: str, initial_state: dict[str, Any] | None
    ) -> AuditReport:
        config = self._graph_config(thread_id)
        reporter = AuditProgressReporter(self._display)
        async for event in graph.astream(
            initial_state, config, stream_mode="updates", subgraphs=True
        ):
            reporter.on_stream_event(event)

        final_state = await graph.aget_state(config)
        report: AuditReport | None = final_state.values.get("audit_report")
        if report is None:
            self._display.print_error("audit did not produce a report")
            raise SystemExit(1)
        return report

    def _initial_state(self) -> dict[str, Any]:
        return {
            "target": self._execution.launch.target,
            "test_budget": self._config.execution.budget,
            "chain_budget": self._config.execution.chains,
            "max_chain_steps": DEFAULT_MAX_CHAIN_STEPS,
            "attack_context": AttackContext(),
        }

    def _graph_config(self, thread_id: str) -> dict[str, Any]:
        settings = self._analysts.settings
        return {
            "configurable": {"thread_id": thread_id},
            "metadata": {
                "target": self._execution.launch.target,
                "budget": self._config.execution.budget,
                "provider": settings.provider,
                "model": settings.resolve_model(),
            },
        }

    async def _show_payloads(self, server: AuditedServer) -> None:
        graph = build_dry_run_graph(
            self._analysts.llm, server, tools_filter=self._config.tools_filter
        )
        result = await graph.ainvoke(
            {
                "target": "",
                "test_budget": self._config.execution.budget,
                "attack_context": AttackContext(),
            }
        )
        tools = result.get("discovered_tools", [])
        self._display.print_discovery(len(tools), [t.name for t in tools])
        for report in result.get("tool_reports", []):
            self._display.print_dry_run_payloads(
                report.tool.name, [c.payload for c in report.cases]
            )

    def _give_up(
        self,
        message: str,
        server_stderr: "tempfile.SpooledTemporaryFile[str]",
        exc: BaseException,
    ) -> NoReturn:
        self._display.print_error(message)
        print_server_stderr(server_stderr, self._display)
        raise SystemExit(1) from exc
