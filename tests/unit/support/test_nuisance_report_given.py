from collections.abc import Sequence
from datetime import date

from evals.holdout_conditions import Cutoff
from evals.nuisance_results import (
    FigureExit,
    NotRunServer,
    NuisanceRunResult,
    NuisanceServerResult,
)

LUNA_CUTOFF = Cutoff(
    date=date(2026, 5, 18), type="training", source="https://example.test/luna", note=None
)
RECORDED_AT = "2026-10-22T09:30:00+00:00"
RUNS = 3


def a_run(
    servers: Sequence[NuisanceServerResult],
    *,
    not_run: Sequence[NotRunServer] = (),
    outside_figure: Sequence[FigureExit] = (),
    cutoffs: dict[str, Cutoff] | None = None,
) -> NuisanceRunResult:
    return NuisanceRunResult(
        runs=RUNS,
        budget=10,
        provider="openai",
        model="gpt-6-luna",
        judge_model="gpt-6-luna",
        reasoning="none",
        judge_reasoning="none",
        cutoffs={"gpt-6-luna": LUNA_CUTOFF} if cutoffs is None else cutoffs,
        chain_budget=3,
        max_chain_steps=5,
        tool_call_timeout=30,
        grammar_fingerprint="grammar-abc",
        counter_fingerprint="counter-abc",
        fixture_fingerprints={"npm:@acme/files": "fa"},
        commit="deadbeef",
        census_commit="cafe1234",
        image_ids={"patched": "sha256:1"},
        recorded_at=RECORDED_AT,
        servers=tuple(servers),
        not_run=tuple(not_run),
        outside_figure=tuple(outside_figure),
        incomplete_run_count=sum(server.incomplete_runs for server in servers),
        total_cost=0.06,
        prices_as_of=date(2026, 10, 15),
    )
