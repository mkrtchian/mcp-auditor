"""One nuisance gate run on the acceptance servers (nuisance-rule.md, Run conditions and
statistic, under ADR 024): the benign call of every gate server, then its runs, the gate and the
replays of a gated server's alarm, with git, Docker, the clock, the audit and the baseline
directory injected. A server whose benign call fails is not audited, reads not_run and leaves the
gate not comparable. The value objects live in `nuisance_gate_session_model`, the recording in
`nuisance_gate_session_recording`."""

import asyncio
import functools
from collections.abc import Sequence
from datetime import UTC, datetime

from evals import nuisance_run
from evals.concurrency import bounded
from evals.cve_audit import RunOverrides, build_auditor
from evals.cve_baseline import image_ids
from evals.eval_session import RECORDING_REFUSED, REFUSED_BEFORE_ANY_LLM_CALL, Refused, read_tree
from evals.holdout_run import rebuild_images
from evals.metrics import SessionThrottles
from evals.nuisance_admission import AdmittedServer, NuisanceAdmission
from evals.nuisance_audit import (
    GateRun,
    NuisanceAuditor,
    audit_once,
    gate_run,
    nuisance_audit,
)
from evals.nuisance_gate import (
    NuisanceGateResult,
    ServerCandidate,
    ServerComparison,
    ServerOutcome,
    compare_server,
    exit_code,
    judge,
    settle,
)
from evals.nuisance_gate_baseline import (
    NUISANCE_GATE_BASELINE_DIRECTORY,
    NuisanceGateConditions,
    condition_mismatches,
)
from evals.nuisance_gate_session_model import (
    GateAudit,
    NuisanceGateHarness,
    NuisanceGateOptions,
    NuisanceGateSession,
    OpenedGate,
    ServerRuns,
)
from evals.nuisance_gate_session_recording import load_checked, record, recording_tree
from evals.nuisance_images import backend_image_ids, image_tag, nuisance_fixture_fingerprint
from evals.nuisance_population import standing_exit
from evals.nuisance_results import FigureExit
from evals.recording import RecordingRefused


def gate_servers(admission: NuisanceAdmission, current: set[str]) -> list[AdmittedServer]:
    """A current acceptance server that cannot launch would keep the gate not comparable for a
    standing reason, so it stays out of the gate set."""
    return [
        server
        for server in admission.servers
        if server.server_package in current and standing_exit(server) is None
    ]


def outside_gate(admission: NuisanceAdmission, current: set[str]) -> list[FigureExit]:
    return [
        FigureExit(server.server_package, reason)
        for server in admission.servers
        if server.server_package in current and (reason := standing_exit(server)) is not None
    ]


def not_admitted(admission: NuisanceAdmission, current: set[str]) -> list[str]:
    return sorted(current - {server.server_package for server in admission.servers})


def default_harness(conditions: NuisanceGateConditions, concurrency: int) -> NuisanceGateHarness:
    overrides = RunOverrides(
        conditions.chain_budget, conditions.max_chain_steps, conditions.tool_call_timeout
    )
    auditor = NuisanceAuditor(build_auditor(conditions.budget), overrides, SessionThrottles())

    async def audit(server: AdmittedServer) -> GateRun | None:
        return await gate_run(
            server, lambda: nuisance_audit(server, lambda: audit_once(server, auditor))
        )

    benign_call = functools.partial(nuisance_run.benign_call, timeout=conditions.tool_call_timeout)
    return NuisanceGateHarness(
        audit=bounded(audit, concurrency),
        benign_call=bounded(benign_call, concurrency),
        rebuild=rebuild_images,
        image_ids=functools.partial(image_ids, tag=image_tag),
        backend_image_ids=backend_image_ids,
        read_tree=read_tree,
        clock=lambda: datetime.now(UTC).isoformat(),
        baselines=NUISANCE_GATE_BASELINE_DIRECTORY,
    )


async def run_gate(
    options: NuisanceGateOptions, harness: NuisanceGateHarness
) -> NuisanceGateSession:
    """Raises Refused on a run that cannot be compared or recorded before it starts."""
    opened = _open(options, harness)
    not_run = await _vetted(opened)
    runs = await _run_servers(opened, not_run)
    gate = await _gate(opened, runs, not_run)
    recorded = record(opened, runs, gate)
    refused = recorded.reasons if isinstance(recorded, RecordingRefused) else []
    return NuisanceGateSession(
        audits=[audit for server_runs in runs for audit in server_runs.audits],
        gate=gate,
        not_run=not_run,
        orphans=opened.orphans(),
        written=[] if isinstance(recorded, RecordingRefused) else recorded,
        recording_refused=refused,
        # A green gate whose recording was refused never exits 0.
        exit_code=3 if refused else exit_code(gate.verdict),
    )


def _open(options: NuisanceGateOptions, harness: NuisanceGateHarness) -> OpenedGate:
    files = load_checked(harness.baselines, REFUSED_BEFORE_ANY_LLM_CALL)
    opened = OpenedGate(options, harness, files, tree=None)
    if not options.record_baseline:
        return opened
    return OpenedGate(options, harness, files, tree=recording_tree(opened))


async def _vetted(opened: OpenedGate) -> dict[str, str]:
    """The benign call gathered over every server before any audit. Under --record-baseline a
    failing server refuses the recording."""
    servers = opened.options.servers
    opened.harness.rebuild(list(dict.fromkeys(server.service for server in servers)))
    failures = await asyncio.gather(*(opened.harness.benign_call(server) for server in servers))
    not_run = {
        server.server_package: failure
        for server, failure in zip(servers, failures, strict=True)
        if failure is not None
    }
    if opened.options.record_baseline and not_run:
        reasons = [f"{package}: {failure}" for package, failure in not_run.items()]
        raise Refused(RECORDING_REFUSED, reasons)
    return not_run


async def _run_servers(opened: OpenedGate, not_run: dict[str, str]) -> list[ServerRuns]:
    count = opened.options.conditions.runs
    servers = [s for s in opened.options.servers if s.server_package not in not_run]
    # gather keeps submission order, so each server's runs keep the order of a sequence.
    outcomes = await asyncio.gather(
        *(opened.harness.audit(server) for server in servers for _ in range(count))
    )
    return [
        _server_runs(server, outcomes[index * count : (index + 1) * count])
        for index, server in enumerate(servers)
    ]


def _server_runs(server: AdmittedServer, outcomes: Sequence[GateRun | None]) -> ServerRuns:
    audits = [
        GateAudit(server.server_package, run_index, outcome.flagged, outcome.report)
        for run_index, outcome in enumerate(outcomes)
        if outcome is not None
    ]
    runs = [outcome for outcome in outcomes if outcome is not None]
    # A server with no run is never complete: an empty candidate would read as held.
    return ServerRuns(server, runs, bool(runs) and len(runs) == len(outcomes), audits)


async def _gate(
    opened: OpenedGate, runs: list[ServerRuns], not_run: dict[str, str]
) -> NuisanceGateResult:
    baselines = opened.baselines()
    mismatches = condition_mismatches(baselines, opened.options.conditions)
    audited = [
        compare_server(baselines.get(sr.server.server_package), _candidate(sr)) for sr in runs
    ]
    if not mismatches:
        audited = list(
            await asyncio.gather(
                *(
                    _settled(comparison, sr.server, opened)
                    for comparison, sr in zip(audited, runs, strict=True)
                )
            )
        )
    by_package = {comparison.server_package: comparison for comparison in audited}
    comparisons = [
        _not_run_comparison(server.server_package, not_run[server.server_package])
        if server.server_package in not_run
        else by_package[server.server_package]
        for server in opened.options.servers
    ]
    return judge(comparisons, mismatches)


def _candidate(server_runs: ServerRuns) -> ServerCandidate:
    return ServerCandidate(
        server_package=server_runs.server.server_package,
        fixture_fingerprint=nuisance_fixture_fingerprint(server_runs.server),
        runs=[run.flagged for run in server_runs.runs],
        completed=server_runs.completed,
    )


async def _settled(
    comparison: ServerComparison, server: AdmittedServer, opened: OpenedGate
) -> ServerComparison:
    """One replay at a time, until the baseline's replay rule decides or a replay does not
    complete."""
    if comparison.outcome != ServerOutcome.PENDING_REPLAY:
        return comparison
    rule = opened.baselines()[server.server_package].replay_rule
    replays: list[bool | None] = []
    settled = comparison
    while settled.outcome == ServerOutcome.PENDING_REPLAY:
        run = await opened.harness.audit(server)
        replays.append(None if run is None else run.flagged)
        settled = settle(comparison, replays, rule)
    return settled


def _not_run_comparison(server_package: str, failure: str) -> ServerComparison:
    return ServerComparison(
        server_package=server_package,
        outcome=ServerOutcome.NOT_RUN,
        candidate_runs=[],
        detail=failure,
    )
