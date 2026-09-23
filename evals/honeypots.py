import os
from dataclasses import dataclass
from pathlib import Path

from evals.ground_truth import (
    CHAIN_HONEYPOT_GROUND_TRUTH,
    HONEYPOT_GROUND_TRUTH,
    SUBTLE_GROUND_TRUTH,
    GroundTruth,
)
from mcp_auditor.adapters.llm import create_judge_llm, create_llm
from mcp_auditor.adapters.mcp_client import StdioMCPClient
from mcp_auditor.adapters.server_launch import ServerLaunch
from mcp_auditor.config import Settings
from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.models import AttackContext, AuditReport
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


async def audit_honeypot(settings: Settings, honeypot: HoneypotConfig, budget: int) -> AuditReport:
    llm = create_llm(settings)
    judge_llm = create_judge_llm(settings)
    devnull = open(os.devnull, "w")  # noqa: SIM115
    try:
        async with StdioMCPClient.connect(
            ServerLaunch.unconfined("uv", honeypot.args), errlog=devnull
        ) as mcp_client:
            graph = build_graph(llm, AuditedServer(mcp_client), judge_llm=judge_llm)
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
