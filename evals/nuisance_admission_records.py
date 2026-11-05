"""The admission records rule v3 and v4 add: whether a tool's real software answers, what the
fixture seeds, the real software's releases, a tool's declared function and a copied holdout
calibration's fingerprint, and their load checks, which `nuisance_admission.admission_problems`
runs per server.

A field left `None` is not yet recorded and is never a load problem here: the run refuses it
(`nuisance_unrecorded`). Only the benign calls of the counted flaws are read, so a differing
call on a flaw that does not count stays loadable.
"""

from __future__ import annotations

import json
from collections import defaultdict
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel

from evals.fixture_provenance import software_release_problems, stand_in_problems
from evals.nuisance_counting import counted_flaws

if TYPE_CHECKING:
    from evals.nuisance_admission import AdmittedServer, BenignCall


class RealSoftwareRecord(BaseModel):
    answers: bool
    cause: Literal["software_error", "not_distributed", "container_unrepairable"] | None = None
    # The run, the capture or the source line, the missing channel, or why the container failure
    # cannot be repaired.
    evidence: str | None = None


class SeedRecord(BaseModel):
    item: str  # a path, a record, a launch or environment value, a name a benign call uses
    kind: Literal["published_sample", "generated", "project_document", "written"]
    citation: str | None = None
    pin: str | None = None  # a commit, a version or a digest


def record_problems(server: AdmittedServer) -> list[str]:
    problems = [
        *_real_software_problems(server),
        *_removed_declared_functions(server),
        *_fix_check_fingerprints(server),
        *_verdict_conflicts(server),
        *_expectation_problems(server),
        *_duplicate_benign_calls(server),
        *_seed_problems(server),
        *_stand_in_problems(server),
        *_software_release_problems(server),
    ]
    return [f"{server.server_package}: {problem}" for problem in problems]


def _real_software_problems(server: AdmittedServer) -> list[str]:
    problems: list[str] = []
    for flaw in server.flaws:
        for tool in flaw.tools:
            verdict = tool.real_software
            if verdict is None:
                continue
            where = f"flaw {flaw.flaw} tool {tool.patched_name or tool.vulnerable_name!r}"
            explained = bool(verdict.cause) and bool(verdict.evidence and verdict.evidence.strip())
            if tool.status == "removed":
                problems.append(f"{where} is removed but carries a real_software record")
            elif not verdict.answers and not explained:
                problems.append(f"{where} does not answer and lacks its cause or evidence")
            elif verdict.answers and (verdict.cause is not None or verdict.evidence is not None):
                problems.append(f"{where} answers but records a cause or evidence")
    return problems


def _removed_declared_functions(server: AdmittedServer) -> list[str]:
    return [
        f"flaw {flaw.flaw} tool {tool.vulnerable_name!r} is removed "
        "but carries a declared_function_is_effect record"
        for flaw in server.flaws
        for tool in flaw.tools
        if tool.status == "removed" and tool.declared_function_is_effect is not None
    ]


def _fix_check_fingerprints(server: AdmittedServer) -> list[str]:
    return [
        f"flaw {flaw.flaw} runs its own fix check but carries a holdout_fingerprint"
        for flaw in server.flaws
        if flaw.fix_check.source == "fix_check" and flaw.fix_check.holdout_fingerprint is not None
    ]


def _verdict_conflicts(server: AdmittedServer) -> list[str]:
    verdicts: dict[str, dict[str, RealSoftwareRecord | None]] = defaultdict(dict)
    for flaw in server.flaws:
        for tool in flaw.tools:
            if tool.status != "removed" and tool.patched_name is not None:
                verdicts[tool.patched_name][flaw.flaw] = tool.real_software
    return [
        f"tool {name!r} has differing real_software verdicts across flaws {', '.join(by_flaw)}"
        for name, by_flaw in verdicts.items()
        if len({_verdict_key(verdict) for verdict in by_flaw.values()}) > 1
    ]


def _verdict_key(verdict: RealSoftwareRecord | None) -> str | None:
    return None if verdict is None else verdict.model_dump_json()


def _expectation_problems(server: AdmittedServer) -> list[str]:
    problems: list[str] = []
    for flaw in counted_flaws(server):
        for call in flaw.benign_calls:
            if call.expect is None:
                continue
            if not call.expect.strip():
                problems.append(f"benign call of {call.tool!r} expects an empty text")
            elif _quotes_its_arguments(call):
                problems.append(
                    f"benign call of {call.tool!r} expects {call.expect!r}, "
                    "which its arguments or its prerequisite calls already contain"
                )
    return problems


def _quotes_its_arguments(call: BenignCall) -> bool:
    expect = call.expect or ""
    calls = [call, *(call.before or [])]
    return any(expect in json.dumps(each.arguments, ensure_ascii=False) for each in calls)


def _duplicate_benign_calls(server: AdmittedServer) -> list[str]:
    calls: dict[str, list[BenignCall]] = defaultdict(list)
    for flaw in counted_flaws(server):
        for call in flaw.benign_calls:
            if call not in calls[call.tool]:
                calls[call.tool].append(call)
    return [
        f"tool {tool!r} has {len(differing)} different benign calls across the counted flaws"
        for tool, differing in calls.items()
        if len(differing) > 1
    ]


def _seed_problems(server: AdmittedServer) -> list[str]:
    problems: list[str] = []
    for seed in server.seeds or []:
        if seed.kind == "published_sample" and (not seed.citation or not seed.pin):
            problems.append(f"published sample {seed.item!r} lacks its citation or pin")
        elif seed.kind == "project_document" and not seed.citation:
            problems.append(f"project document {seed.item!r} lacks its citation")
    return problems


def _stand_in_problems(server: AdmittedServer) -> list[str]:
    return [
        problem for stand_in in server.stand_ins or [] for problem in stand_in_problems(stand_in)
    ]


def _software_release_problems(server: AdmittedServer) -> list[str]:
    return [
        problem
        for release in server.software_releases or []
        for problem in software_release_problems(release)
    ]
