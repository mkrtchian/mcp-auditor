"""The benign probe a re-admission agent runs on a server's patched image, free of mcp_auditor.

Parity note: the twin is `run_nuisance vet`, which makes the same benign calls through the run's
own launch. The record is the dossier's admission_record.json, or an agent's own record, read as
plain JSON, since nuisance_admission is not clean. The single-container launch is the run's
(nuisance_confinement.single_container_launch_args), serving the record's public names from this
tree's `evals/stand_ins/`, and a backend launch goes through kit_backend_launch, both pinned to
the run launch by tests.
"""

import argparse
import asyncio
import json
import os
import tempfile
from collections.abc import Generator, Mapping, Sequence
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from evals.cve_planting_base import PlantingHost, PublicNames, SymbolicUser
from evals.holdout_kit.kit_backend_launch import backend_launch, lifecycle_of
from evals.holdout_kit.kit_client import KitClient, KitMCPClient, KitResponse, docker_client_env
from evals.holdout_kit.kit_launch import Launch
from evals.nuisance_confinement import single_container_launch_args

_DEFAULT_TOOL_CALL_TIMEOUT = 60


@dataclass(frozen=True)
class ProbeCall:
    tool: str
    arguments: dict[str, Any]
    expect: str | None
    before: tuple[tuple[str, dict[str, Any]], ...]


@dataclass(frozen=True)
class ProbeOutcome:
    call: ProbeCall
    before: tuple[KitResponse, ...]
    response: KitResponse


@dataclass(frozen=True)
class ProbeReport:
    listed: frozenset[str]
    outcomes: tuple[ProbeOutcome, ...]


def main(argv: Sequence[str] | None = None) -> int:
    options = _parser().parse_args(argv)
    record = json.loads(Path(options.record).read_text())
    raw_calls = json.loads(Path(options.calls).read_text()) if options.calls else None
    calls = probe_calls(raw_calls if raw_calls is not None else record_calls(record))
    with probe_launch(record, options.image) as launch:
        report = asyncio.run(probe(launch, calls, options.tool_call_timeout))
    for line in report_lines(report):
        print(line)
    passes = all(_outcome_passes(outcome, report.listed) for outcome in report.outcomes)
    return 0 if passes else 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m evals.holdout_kit.benign_probe")
    parser.add_argument("--record", required=True, help="the dossier's admission_record.json")
    parser.add_argument("--image", required=True, help="the server's patched image tag")
    parser.add_argument("--calls", help="a JSON list of benign calls, the record's by default")
    parser.add_argument("--tool-call-timeout", type=int, default=_DEFAULT_TOOL_CALL_TIMEOUT)
    return parser


def record_calls(record: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    calls: list[Mapping[str, Any]] = []
    for flaw in record["flaws"]:
        for call in flaw["benign_calls"]:
            if call not in calls:
                calls.append(call)
    return calls


def probe_calls(calls: Sequence[Mapping[str, Any]]) -> list[ProbeCall]:
    return [_probe_call(call) for call in calls]


def _probe_call(call: Mapping[str, Any]) -> ProbeCall:
    steps = call.get("before") or ()
    if any("tool" not in step or "arguments" not in step for step in (call, *steps)):
        raise ValueError(
            f"a benign call and its before calls need a tool and arguments: {dict(call)!r}"
        )
    before = tuple((step["tool"], dict(step["arguments"])) for step in steps)
    return ProbeCall(call["tool"], dict(call["arguments"]), call.get("expect"), before)


def record_host(record: Mapping[str, Any]) -> PlantingHost:
    host = record["host"]
    names = host["public_names"]
    return PlantingHost(
        SymbolicUser(host["user"]),
        host["working_directory"],
        host["has_network"],
        PublicNames(
            tuple(names["stand_ins"]), tuple(names["trust"]), tuple(names["ip_label_domains"])
        ),
    )


@contextmanager
def single_container_launch(record: Mapping[str, Any], image: str) -> Generator[Launch]:
    with single_container_launch_args(image, record_host(record), record["launch"]) as args:
        yield Launch("docker", args)


def probe_launch(record: Mapping[str, Any], image: str) -> AbstractContextManager[Launch]:
    if record["backend"] is None:
        return single_container_launch(record, image)
    lifecycle = lifecycle_of(record["backend"]["provisioner"])
    return backend_launch(lifecycle, image, record_host(record), record["launch"])


async def probe(launch: Launch, calls: Sequence[ProbeCall], tool_call_timeout: int) -> ProbeReport:
    with tempfile.TemporaryFile("w+") as server_stderr:
        async with KitMCPClient.connect(
            launch.command,
            launch.args,
            env=docker_client_env(os.environ),
            errlog=server_stderr,
            tool_call_timeout=tool_call_timeout,
        ) as client:
            return await probe_client(client, calls)


async def probe_client(client: KitClient, calls: Sequence[ProbeCall]) -> ProbeReport:
    listed = frozenset(tool.name for tool in await client.list_tools())
    outcomes = [await _outcome(client, call) for call in calls]
    return ProbeReport(listed, tuple(outcomes))


async def _outcome(client: KitClient, call: ProbeCall) -> ProbeOutcome:
    before = [await client.call_tool(tool, dict(arguments)) for tool, arguments in call.before]
    response = await client.call_tool(call.tool, dict(call.arguments))
    return ProbeOutcome(call, tuple(before), response)


def report_lines(report: ProbeReport) -> list[str]:
    lines = [f"tools/list: {len(report.listed)} tools"]
    for outcome in report.outcomes:
        for (tool, _), response in zip(outcome.call.before, outcome.before, strict=True):
            lines.append(f"  before {_answer(tool, report.listed, response)}")
        lines.append(
            _answer(outcome.call.tool, report.listed, outcome.response, outcome.call.expect)
        )
    return lines


def _answer(
    tool: str, listed: frozenset[str], response: KitResponse, expect: str | None = None
) -> str:
    listing = "listed" if tool in listed else "NOT LISTED"
    verdict = "error" if response.is_error else "ok"
    if expect is not None:
        verdict += ", expect found" if expect in response.content else ", expect MISSING"
    return f"{tool} [{listing}] -> {verdict} {response.content!r}"


def _outcome_passes(outcome: ProbeOutcome, listed: frozenset[str]) -> bool:
    call = outcome.call
    answers = [
        (tool, response) for (tool, _), response in zip(call.before, outcome.before, strict=True)
    ]
    answers.append((call.tool, outcome.response))
    expected = call.expect is None or call.expect in outcome.response.content
    return expected and all(tool in listed and not response.is_error for tool, response in answers)


if __name__ == "__main__":
    raise SystemExit(main())
