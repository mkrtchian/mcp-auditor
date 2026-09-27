import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

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
from mcp_auditor.domain.models import AttackContext, AuditReport, TokenUsage
from mcp_auditor.domain.ports import LLMPort
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


HoneypotAudit = Callable[[HoneypotConfig], Awaitable[AuditReport]]


async def audit_honeypots(audit: HoneypotAudit) -> tuple[VerdictMap, AuditReport]:
    """One run: every honeypot audited in turn, their verdicts and reports merged."""
    verdicts: VerdictMap = {}
    merged = AuditReport(target="evals", tool_reports=[], token_usage=TokenUsage())
    for honeypot in HONEYPOTS:
        report = await audit(honeypot)
        verdicts.update(aggregate_verdicts(report))
        merged = AuditReport(
            target=merged.target,
            tool_reports=[*merged.tool_reports, *report.tool_reports],
            token_usage=merged.token_usage.add(report.token_usage),
            refused_steps=[*merged.refused_steps, *report.refused_steps],
        )
    return verdicts, merged


def models_for(settings: Settings) -> AuditModels:
    return AuditModels(llm=create_llm(settings), judge_llm=create_judge_llm(settings))


async def audit_honeypot(models: AuditModels, honeypot: HoneypotConfig, budget: int) -> AuditReport:
    devnull = open(os.devnull, "w")  # noqa: SIM115
    try:
        async with StdioMCPClient.connect(
            ServerLaunch.unconfined("uv", honeypot.args), errlog=devnull
        ) as mcp_client:
            graph = build_graph(models.llm, AuditedServer(mcp_client), judge_llm=models.judge_llm)
            result = await graph.ainvoke(  # pyright: ignore[reportUnknownMemberType]
                {
                    "target": f"uv {' '.join(honeypot.args)}",
                    "test_budget": budget,
                    "attack_context": AttackContext(),
                    "chain_budget": honeypot.chain_budget,
                    "max_chain_steps": honeypot.max_chain_steps,
                }
            )
            return result["audit_report"]
    finally:
        devnull.close()
