"""Capture the probe corpus from one reference run (`uv run python -m evals.capture_probe_corpus`).

The prompts come from a real audit of the three honeypots, so the corpus holds
the calls the product makes, retries included, and from the tool definitions of
the CVE images, which widen the generation prompts beyond the honeypots. The
CVE servers are only listed: no audit runs against them here.
"""

import asyncio
import os
import subprocess
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from rich.console import Console

from evals.cve_environments import Launch
from evals.cve_targets import CVE_TARGETS
from evals.honeypots import HONEYPOTS, REPO_ROOT, AuditModels, audit_honeypot, models_for
from evals.probe_candidates import REFERENCE
from evals.probe_corpus import (
    ProbeCall,
    ProbeCorpus,
    RecordingLLM,
    ReferenceConditions,
    sample_judge_calls,
    write_corpus,
)
from evals.run_cve_benchmark import EXPECTED_IMAGES
from mcp_auditor.adapters.docker import docker_client_env
from mcp_auditor.adapters.mcp_client import StdioMCPClient
from mcp_auditor.adapters.server_launch import ServerLaunch
from mcp_auditor.config import Settings, load_settings
from mcp_auditor.domain.models import AuditCategory, TestCaseBatch, ToolDefinition
from mcp_auditor.domain.ports import MCPClientPort
from mcp_auditor.graph.prompts import build_attack_generation_prompt

CAPTURE_BUDGET = 10
JUDGE_SAMPLE_SIZE = 60
JUDGE_SAMPLE_SEED = 20260924
CORPUS_PATH = REPO_ROOT / "evals" / "fixtures" / "probe_corpus.json"

_BUILD_COMMAND = "docker compose -f evals/docker/compose.yml build"

console = Console()


def main() -> None:
    settings = load_settings()
    mismatches = _reference_mismatches(settings)
    if mismatches:
        _refuse("the settings are not the reference", mismatches)
    image_problems = _cve_image_problems()
    if image_problems:
        _refuse(f"the CVE images are not ready. To build them: {_BUILD_COMMAND}", image_problems)
    corpus = asyncio.run(_capture(settings))
    write_corpus(CORPUS_PATH, corpus)
    console.print(f"{len(corpus.calls)} calls written to {CORPUS_PATH}")


def _reference_mismatches(settings: Settings) -> list[str]:
    try:
        actual = _conditions_of(settings)
    except ValueError as error:
        return [str(error)]
    reference = _conditions_of(REFERENCE.settings)
    return [
        f"{field}: {getattr(actual, field)!r}, the reference is {getattr(reference, field)!r}"
        for field in ReferenceConditions.model_fields
        if getattr(actual, field) != getattr(reference, field)
    ]


def _conditions_of(settings: Settings) -> ReferenceConditions:
    model = settings.resolve_model()
    judge_model = settings.resolve_judge_model()
    return ReferenceConditions(
        provider=settings.provider,
        model=model,
        judge_model=judge_model,
        reasoning=settings.resolve_reasoning(model),
        judge_reasoning=settings.resolve_reasoning(judge_model),
    )


def _refuse(reason: str, details: list[str]) -> None:
    console.print(f"[red]Capture refused:[/red] {reason}.")
    for detail in details:
        console.print(f"  - {detail}")
    sys.exit(1)


def _cve_image_problems() -> list[str]:
    return [f"missing image {image}" for image in EXPECTED_IMAGES if not _image_exists(image)]


def _image_exists(image: str) -> bool:
    try:
        inspect = subprocess.run(["docker", "image", "inspect", image], capture_output=True)
    except OSError:
        return False
    return inspect.returncode == 0


async def _capture(settings: Settings) -> ProbeCorpus:
    # Listed first: a Docker failure here then costs no LLM call.
    cve_calls = _cve_generation_calls(await _cve_tools())
    honeypot_calls = await _capture_honeypot_calls(settings)
    return ProbeCorpus(
        captured_at=datetime.now(UTC).isoformat(timespec="seconds"),
        commit=_head_commit(),
        reference=_conditions_of(settings),
        budget=CAPTURE_BUDGET,
        judge_sample_seed=JUDGE_SAMPLE_SEED,
        judge_calls_captured=sum(call.role == "judge" for call in honeypot_calls),
        calls=[
            *sample_judge_calls(honeypot_calls, JUDGE_SAMPLE_SIZE, JUDGE_SAMPLE_SEED),
            *cve_calls,
        ],
    )


async def _capture_honeypot_calls(settings: Settings) -> list[ProbeCall]:
    sink: list[ProbeCall] = []
    models = models_for(settings)
    recording = AuditModels(
        llm=RecordingLLM(models.llm, "main", sink),
        judge_llm=RecordingLLM(models.judge_llm, "judge", sink),
    )
    for honeypot in HONEYPOTS:
        console.print(f"Auditing [bold]{honeypot.name}[/bold]...")
        await audit_honeypot(recording, honeypot, CAPTURE_BUDGET)
    return sink


async def _cve_tools() -> list[ToolDefinition]:
    tools: list[ToolDefinition] = []
    for target in CVE_TARGETS:
        console.print(f"Listing the tools of {target.cve_id}...")
        with target.environment() as launch:
            async with _silent_client(launch) as client:
                listed = await client.list_tools()
        tools.extend(tool for tool in listed if tool not in tools)
    return tools


@asynccontextmanager
async def _silent_client(launch: Launch) -> AsyncIterator[MCPClientPort]:
    devnull = open(os.devnull, "w")  # noqa: SIM115
    try:
        async with StdioMCPClient.connect(
            ServerLaunch.declared_container(
                launch.command, launch.args, docker_client_env(os.environ)
            ),
            errlog=devnull,
        ) as client:
            yield client
    finally:
        devnull.close()


def _cve_generation_calls(tools: list[ToolDefinition]) -> list[ProbeCall]:
    return [
        ProbeCall(
            call_id=f"cve/TestCaseBatch/{index:03d}",
            schema_name=TestCaseBatch.__name__,
            role="main",
            source="cve",
            prompt=build_attack_generation_prompt(
                tool=tool,
                budget=CAPTURE_BUDGET,
                categories=list(AuditCategory),
                attack_context=None,
            ),
        )
        for index, tool in enumerate(tools)
    ]


def _head_commit() -> str:
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    )
    return head.stdout.strip()


if __name__ == "__main__":
    main()
