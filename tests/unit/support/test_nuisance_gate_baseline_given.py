from evals.baseline import BaselineStatus, RecordingRef
from evals.cve_baseline import grammar_fingerprint
from evals.gate import ReplayRule
from evals.holdout_run import HOLDOUT_BUDGET
from evals.nuisance_counter import counter_fingerprint
from evals.nuisance_gate_baseline import NuisanceGateConditions, NuisanceServerBaseline

SERVER_PACKAGE = "npm:@modelcontextprotocol/server-filesystem"
FIXTURE = "fixture"
RECORDED_COMMIT = "0123abc"


def conditions(runs: int = 3) -> NuisanceGateConditions:
    return NuisanceGateConditions(
        runs=runs,
        budget=HOLDOUT_BUDGET,
        tools_filtered=False,
        provider="openai",
        model="gpt-6-luna",
        judge_model="gpt-6-luna",
        reasoning="none",
        judge_reasoning="none",
        chain_budget=3,
        max_chain_steps=5,
        tool_call_timeout=30,
        grammar_fingerprint=grammar_fingerprint(),
        counter_fingerprint=counter_fingerprint(),
    )


def a_gated_baseline(package: str = SERVER_PACKAGE) -> NuisanceServerBaseline:
    return a_confirmed_baseline([False] * 6, package)


def a_confirmed_baseline(runs: list[bool], package: str = SERVER_PACKAGE) -> NuisanceServerBaseline:
    first = RecordingRef(commit=RECORDED_COMMIT, recorded_at="2026-10-22T09:00:00+00:00")
    return an_exploratory_baseline(runs, package).model_copy(
        update={"status": BaselineStatus.CONFIRMED, "confirms": first}
    )


def an_exploratory_baseline(
    runs: list[bool] | None = None,
    package: str = SERVER_PACKAGE,
    commit: str = RECORDED_COMMIT,
) -> NuisanceServerBaseline:
    return NuisanceServerBaseline(
        server_package=package,
        status=BaselineStatus.EXPLORATORY,
        conditions=conditions(),
        fixture_fingerprint=FIXTURE,
        replay_rule=ReplayRule(),
        commit=commit,
        recorded_at="2026-10-22T10:00:00+00:00",
        runs=runs if runs is not None else [False] * 3,
        image_ids={"filesystem-patched": "sha256:0123"},
    )
