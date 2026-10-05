import asyncio
import os
from collections.abc import AsyncGenerator, Callable, Coroutine
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from evals.ground_truth import (
    CHAIN_HONEYPOT_GROUND_TRUTH,
    HONEYPOT_GROUND_TRUTH,
    SUBTLE_GROUND_TRUTH,
    GroundTruth,
)
from evals.metrics import VerdictMap, aggregate_verdicts
from mcp_auditor.adapters.llm import create_judge_llm, create_llm
from mcp_auditor.adapters.mcp_client import StdioMCPClient
from mcp_auditor.adapters.server_launch import ServerLaunch
from mcp_auditor.config import Settings
from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.models import AttackContext, AuditReport, ProviderUsage
from mcp_auditor.domain.ports import LLMPort, MCPClientPort
from mcp_auditor.graph.builder import build_graph

REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class HoneypotConfig:
    name: str
    server: Path
    ground_truth: GroundTruth
    chain_budget: int = 0
    max_chain_steps: int = 3

    @property
    def args(self) -> list[str]:
        return ["run", "python", str(self.server)]


HONEYPOTS = [
    HoneypotConfig("honeypot", REPO_ROOT / "tests" / "honeypot_server.py", HONEYPOT_GROUND_TRUTH),
    HoneypotConfig("subtle", REPO_ROOT / "tests" / "subtle_server.py", SUBTLE_GROUND_TRUTH),
    HoneypotConfig(
        "chain_honeypot",
        REPO_ROOT / "tests" / "chain_honeypot_server.py",
        CHAIN_HONEYPOT_GROUND_TRUTH,
        chain_budget=3,
        max_chain_steps=5,
    ),
]
MERGED_GROUND_TRUTH: GroundTruth = {
    cell: verdict for honeypot in HONEYPOTS for cell, verdict in honeypot.ground_truth.items()
}
TOOL_COUNT = len({tool for tool, _ in MERGED_GROUND_TRUTH})


@dataclass(frozen=True)
class AuditModels:
    llm: LLMPort
    judge_llm: LLMPort


@dataclass(frozen=True)
class ConnectedHoneypot:
    config: HoneypotConfig
    client: MCPClientPort


HoneypotAudit = Callable[[HoneypotConfig], Coroutine[Any, Any, AuditReport]]


async def audit_honeypots(audit: HoneypotAudit) -> tuple[VerdictMap, AuditReport]:
    """One run: every honeypot audited side by side, their verdicts and reports merged in a
    fixed order. A failed audit cancels the others, whose reports the run would discard."""
    try:
        async with asyncio.TaskGroup() as group:
            tasks = [group.create_task(audit(honeypot)) for honeypot in HONEYPOTS]
    except ExceptionGroup as failures:
        raise failures.exceptions[0] from None
    reports = [task.result() for task in tasks]
    verdicts: VerdictMap = {}
    merged = AuditReport(target="evals", tool_reports=[], provider_usage=ProviderUsage())
    for report in reports:
        verdicts.update(aggregate_verdicts(report))
        merged = AuditReport(
            target=merged.target,
            tool_reports=[*merged.tool_reports, *report.tool_reports],
            provider_usage=merged.provider_usage.add(report.provider_usage),
            refused_steps=[*merged.refused_steps, *report.refused_steps],
        )
    return verdicts, merged


def models_for(settings: Settings) -> AuditModels:
    return AuditModels(llm=create_llm(settings), judge_llm=create_judge_llm(settings))


async def audit_honeypot(models: AuditModels, honeypot: HoneypotConfig, budget: int) -> AuditReport:
    async with connected(honeypot) as server:
        return await audit_connected(models, server, budget)


@asynccontextmanager
async def connected(honeypot: HoneypotConfig) -> AsyncGenerator[ConnectedHoneypot]:
    devnull = open(os.devnull, "w")  # noqa: SIM115
    try:
        async with StdioMCPClient.connect(
            ServerLaunch.unconfined("uv", honeypot.args), errlog=devnull
        ) as mcp_client:
            yield ConnectedHoneypot(honeypot, mcp_client)
    finally:
        devnull.close()


async def audit_connected(
    models: AuditModels, honeypot: ConnectedHoneypot, budget: int
) -> AuditReport:
    config = honeypot.config
    graph = build_graph(models.llm, AuditedServer(honeypot.client), judge_llm=models.judge_llm)
    result = await graph.ainvoke(  # pyright: ignore[reportUnknownMemberType]
        {
            "target": f"uv {' '.join(config.args)}",
            "test_budget": budget,
            "attack_context": AttackContext(),
            "chain_budget": config.chain_budget,
            "max_chain_steps": config.max_chain_steps,
        }
    )
    return result["audit_report"]
