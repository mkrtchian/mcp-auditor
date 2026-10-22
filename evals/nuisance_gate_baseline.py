"""The nuisance gate's baseline: the run conditions it records and one file per acceptance server
under `evals/baselines/nuisance/`, the sibling of `cve_baseline`'s baseline half.

The conditions are the nuisance figure's (the holdout budget, no tools filter, the chain settings
and tool call timeout of `evals/holdout_conditions.json`), since the gate gates what the figure
measures. The counter and grammar fingerprints are conditions, so a change to either is a whole
reset (nuisance-rule.md, Versioning).
"""

import os
import re
from collections.abc import Mapping
from pathlib import Path

from pydantic import BaseModel

from evals.baseline import BaselineStatus, RecordingRef
from evals.cve_baseline import grammar_fingerprint
from evals.gate import ReplayRule
from evals.holdout_conditions import HoldoutConditions
from evals.holdout_run import HOLDOUT_BUDGET
from evals.nuisance_counter import counter_fingerprint
from mcp_auditor.config import Settings

NUISANCE_GATE_RUNS = 3
NUISANCE_GATE_BASELINE_DIRECTORY = Path(__file__).parent / "baselines" / "nuisance"
_BASELINE_DIRECTORY = "evals/baselines/nuisance"
WHOLE_RESET = (
    f"Reset the whole baseline: delete {_BASELINE_DIRECTORY}/ in a commit of its own, "
    "then record twice at one commit (ADR 020)."
)


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
    model, judge_model = settings.resolve_model(), settings.resolve_judge_model()
    return NuisanceGateConditions(
        runs=runs,
        budget=HOLDOUT_BUDGET,
        tools_filtered=False,
        provider=settings.provider,
        model=model,
        judge_model=judge_model,
        reasoning=settings.resolve_reasoning(model),
        judge_reasoning=settings.resolve_reasoning(judge_model),
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
    replay_rule: ReplayRule
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


def baseline_file_name(server_package: str) -> str:
    # A package carries ":" and "/", which a file name cannot hold portably.
    return re.sub(r"[^A-Za-z0-9._-]", "_", server_package) + ".json"


def load_baselines(directory: Path) -> dict[str, NuisanceServerBaseline]:
    baselines: dict[str, NuisanceServerBaseline] = {}
    for path in sorted(directory.glob("*.json")):
        baseline = NuisanceServerBaseline.model_validate_json(path.read_text())
        package = baseline.server_package
        if path.name != baseline_file_name(package):
            raise ValueError(f"{path.name} holds the baseline of {package}")
        baselines[package] = baseline
    return baselines


def write_baseline(directory: Path, baseline: NuisanceServerBaseline) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / baseline_file_name(baseline.server_package)
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(baseline.model_dump_json(indent=2))
    os.replace(temporary, path)


def baseline_integrity(baseline: NuisanceServerBaseline) -> list[str]:
    """What the file holds that its conditions do not claim, checked when the gate loads it."""
    package, held = baseline.server_package, len(baseline.runs)
    if not held:
        return [f"{package}: the baseline holds no run"]
    if baseline.confirms is None:
        claimed, claimants = baseline.conditions.runs, "its conditions"
    else:  # a confirmation holds the runs of both recordings (ADR 023)
        claimed, claimants = baseline.conditions.runs * 2, "its conditions and its confirmation"
    if held == claimed:
        return []
    return [f"{package}: the baseline holds {held} runs, {claimants} claim {claimed}"]


def condition_mismatches(
    baselines: Mapping[str, NuisanceServerBaseline], candidate: NuisanceGateConditions
) -> list[str]:
    expected = candidate.model_dump()
    return [
        f"{baseline_file_name(package)}: {field} is {recorded!r}, the run has {expected[field]!r}"
        for package, baseline in sorted(baselines.items())
        for field, recorded in baseline.conditions.model_dump().items()
        if recorded != expected[field]
    ]


def server_reset(server_package: str) -> str:
    return (
        f"fixture changed since the baseline: delete "
        f"{_BASELINE_DIRECTORY}/{baseline_file_name(server_package)} in the commit that changes "
        f"its fixture, then record it twice at one commit with --server {server_package}"
    )
