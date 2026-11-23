"""The nuisance gate's baseline: the run conditions it records and, under
`evals/baselines/nuisance/`, one file per nuisance acceptance server, the counterpart of the
baseline half of `evals.cve.detection.baseline`.

The conditions are the nuisance holdout run's (the holdout test budget, no tools filter, the chain
settings and tool call timeout of `evals/holdout_conditions.json`), since the gate gates what the
holdout nuisance rate measures. The counter and grammar fingerprints are conditions, so a change to
either is a whole reset (nuisance-suite-rule.md, Versioning).
"""

import re
from collections.abc import Mapping
from pathlib import Path

from pydantic import BaseModel

from evals.baseline import BaselineStatus, RecordingRef, run_count_problems, write_json_atomically
from evals.cve.detection.baseline import grammar_fingerprint
from evals.cve.file_baselines import BaselineStore, condition_mismatches_by_file, whole_reset
from evals.cve.holdout_conditions import HOLDOUT_TEST_BUDGET, HoldoutConditions
from evals.cve.nuisance.counter import counter_fingerprint
from evals.gate import RetestRule
from evals.model_conditions import ModelConditions
from mcp_auditor.config import Settings

NUISANCE_GATE_RUNS = 3
NUISANCE_GATE_BASELINE_DIRECTORY = Path(__file__).parents[3] / "baselines" / "nuisance"
_BASELINE_DIRECTORY = "evals/baselines/nuisance"
WHOLE_RESET = whole_reset(_BASELINE_DIRECTORY)


class NuisanceGateConditions(BaseModel):
    runs: int
    budget: int
    # Always False (the rule fixes no tools filter), recorded because ADR 024 lists it.
    tools_filtered: bool
    provider: str
    model: str
    judge_model: str
    reasoning: str | None
    judge_reasoning: str | None
    chain_budget: int
    max_chain_steps: int
    tool_call_timeout: int
    grammar_fingerprint: str
    counter_fingerprint: str


def gate_conditions(
    settings: Settings, conditions: HoldoutConditions, runs: int
) -> NuisanceGateConditions:
    conditions.require_chain_settings()
    chain, steps = conditions.chain_budget, conditions.max_chain_steps
    timeout = conditions.tool_call_timeout
    assert chain is not None and steps is not None and timeout is not None
    return NuisanceGateConditions(
        runs=runs,
        budget=HOLDOUT_TEST_BUDGET,
        tools_filtered=False,
        **ModelConditions.of(settings).model_dump(),
        chain_budget=chain,
        max_chain_steps=steps,
        tool_call_timeout=timeout,
        grammar_fingerprint=grammar_fingerprint(),
        counter_fingerprint=counter_fingerprint(),
    )


class NuisanceServerBaseline(BaseModel):
    server_package: str
    status: BaselineStatus
    conditions: NuisanceGateConditions
    fixture_fingerprint: str
    retest_rule: RetestRule
    commit: str
    recorded_at: str
    runs: list[bool]  # flagged per run, True for an alarm
    confirms: RecordingRef | None = None
    replaces: RecordingRef | None = None
    # Image name to image ID at recording: provenance, not a condition (ADR 024).
    image_ids: dict[str, str]

    def alarmed(self) -> bool:
        return any(self.runs)

    def gated(self) -> bool:
        return self.status == BaselineStatus.CONFIRMED and not self.alarmed()


def load_baselines(directory: Path) -> dict[str, NuisanceServerBaseline]:
    baselines: dict[str, NuisanceServerBaseline] = {}
    for path in sorted(directory.glob("*.json")):
        baseline = NuisanceServerBaseline.model_validate_json(path.read_text())
        package = baseline.server_package
        if path.name != baseline_file_name(package):
            raise ValueError(f"{path.name} holds the baseline of {package}")
        baselines[package] = baseline
    return baselines


def baseline_file_name(server_package: str) -> str:
    # A package carries ":" and "/", which a file name cannot hold portably.
    return re.sub(r"[^A-Za-z0-9._-]", "_", server_package) + ".json"


def write_baseline(directory: Path, baseline: NuisanceServerBaseline) -> None:
    write_json_atomically(directory / baseline_file_name(baseline.server_package), baseline)


def baseline_integrity(baseline: NuisanceServerBaseline) -> list[str]:
    """What the file holds that its conditions do not claim, checked when the gate loads it."""
    problems = run_count_problems(len(baseline.runs), baseline.conditions.runs, baseline.confirms)
    return [f"{baseline.server_package}: {problem}" for problem in problems]


def condition_mismatches(
    baselines: Mapping[str, NuisanceServerBaseline], candidate: NuisanceGateConditions
) -> list[str]:
    by_file = {
        baseline_file_name(package): baseline.conditions
        for package, baseline in sorted(baselines.items())
    }
    return condition_mismatches_by_file(by_file, candidate)


def server_reset(server_package: str) -> str:
    return (
        f"fixture changed since the baseline: delete "
        f"{_BASELINE_DIRECTORY}/{baseline_file_name(server_package)} in the commit that changes "
        f"its fixture, then record it twice at one commit with --server {server_package}"
    )


NUISANCE_GATE_BASELINE_STORE = BaselineStore(load_baselines, baseline_integrity)
