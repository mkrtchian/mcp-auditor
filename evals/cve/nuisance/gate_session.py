"""One nuisance gate run on the nuisance acceptance servers (nuisance-rule.md, Run conditions and
statistic, under ADR 024): the benign call of every gate server, then its runs, the gate and the
retests of a gated server's alarm, with git, Docker, the clock, the audit and the baseline
directory injected. A server whose benign call fails is not audited, reads not_run and leaves the
gate not comparable. The value objects live in `gate_session_model`, the recording in
`gate_session_recording`."""

import asyncio
import functools
from collections.abc import Sequence
from datetime import UTC, datetime

from evals.closed_network import check_closed_network_support
from evals.concurrency import bounded
from evals.cve.detection.audit import RunOverrides, build_auditor
from evals.cve.detection.baseline import image_ids
from evals.cve.nuisance import vetting as nuisance_vetting
from evals.cve.nuisance.admission_walk import standing_exit
from evals.cve.nuisance.audit import (
    GateRun,
    NuisanceAuditor,
    audit_once,
    gate_run,
    nuisance_audit,
)
from evals.cve.nuisance.fingerprint import nuisance_fixture_fingerprint
from evals.cve.nuisance.gate import (
    NuisanceGateResult,
    ServerCandidate,
    ServerComparison,
    ServerOutcome,
    apply_retests,
    compare_server,
    decide,
    exit_code,
)
from evals.cve.nuisance.gate_baseline import (
    NUISANCE_GATE_BASELINE_DIRECTORY,
    NuisanceGateConditions,
    NuisanceServerBaseline,
    condition_mismatches,
)
from evals.cve.nuisance.gate_session_model import (
    GateAudit,
    NuisanceGateHarness,
    NuisanceGateOptions,
    NuisanceGateSession,
    OpenedGate,
    ServerRuns,
)
from evals.cve.nuisance.gate_session_recording import load_checked, record, recording_tree
from evals.cve.nuisance.images import backend_image_ids, image_tag
from evals.cve.nuisance.results import ServerExit
from evals.cve.nuisance.run_containers import (
    remove_backend_containers,
    run_images,
    sweep_run_containers,
)
from evals.cve.nuisance.solo import gathered_then_alone, played_alone
from evals.cve.run_images import DOCKER_SWEEP, rebuild_images, refuse_without_closed_networks
from evals.eval_session import RECORDING_REFUSED, REFUSED_BEFORE_ANY_LLM_CALL, Refused, read_tree
from evals.metrics import SessionThrottles
from evals.nuisance_admission import AdmittedServer, NuisanceAdmission
from evals.recording import RecordingRefused


def gate_servers(admission: NuisanceAdmission, current: set[str]) -> list[AdmittedServer]:
    """A nuisance acceptance server that cannot launch would keep the gate not comparable for a
    standing reason, so it stays out of the gate set."""
    return [
        server
        for server in admission.servers
        if server.server_package in current and standing_exit(server) is None
    ]


def outside_gate(admission: NuisanceAdmission, current: set[str]) -> list[ServerExit]:
    return [
        ServerExit(server.server_package, reason)
        for server in admission.servers
        if server.server_package in current and (reason := standing_exit(server)) is not None
    ]


def not_admitted(admission: NuisanceAdmission, current: set[str]) -> list[str]:
    return sorted(current - {server.server_package for server in admission.servers})


def default_harness(conditions: NuisanceGateConditions, concurrency: int) -> NuisanceGateHarness:
    overrides = RunOverrides(
        conditions.chain_budget, conditions.max_chain_steps, conditions.tool_call_timeout
    )
    throttles = SessionThrottles()
    auditor = NuisanceAuditor(build_auditor(conditions.budget), overrides, throttles)

    async def audit(server: AdmittedServer) -> GateRun | None:
        return await gate_run(
            server, lambda: nuisance_audit(server, lambda: audit_once(server, auditor))
        )

    benign_call = functools.partial(
        nuisance_vetting.benign_call, timeout=conditions.tool_call_timeout
    )
    return NuisanceGateHarness(
        audit=bounded(audit, concurrency),
        benign_call=bounded(benign_call, concurrency),
        announce_audits=lambda _: None,
        throttled_requests=lambda: throttles.requests,
        rebuild=rebuild_images,
        image_ids=functools.partial(image_ids, tag=image_tag),
        backend_image_ids=backend_image_ids,
        read_tree=read_tree,
        clock=lambda: datetime.now(UTC).isoformat(),
        baselines=NUISANCE_GATE_BASELINE_DIRECTORY,
        check_networks=check_closed_network_support,
        sweep=DOCKER_SWEEP,
    )


async def run_gate(
    options: NuisanceGateOptions, harness: NuisanceGateHarness
) -> NuisanceGateSession:
    """Raises Refused on a run that cannot be compared or recorded before it starts."""
    refuse_without_closed_networks(harness.check_networks)
    opened = _open(options, harness)
    images = run_images(options.servers)
    try:
        # A built backend left running by a killed command never serves a gate: its provisioner
        # stands it again from its image and its seed.
        remove_backend_containers(harness.sweep, images)
        return await _run_opened(opened)
    finally:
        sweep_run_containers(harness.sweep, images)


async def _run_opened(opened: OpenedGate) -> NuisanceGateSession:
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
        throttled_requests=opened.harness.throttled_requests(),
        # A green gate whose recording was refused never exits 0.
        exit_code=3 if refused else exit_code(gate.outcome),
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
    failures = await gathered_then_alone(servers, opened.harness.benign_call)
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
    opened.harness.announce_audits(len(servers) * count)
    outcomes = await gathered_then_alone(servers, lambda server: _runs(opened, server, count))
    return [_server_runs(server, runs) for server, runs in zip(servers, outcomes, strict=True)]


async def _runs(opened: OpenedGate, server: AdmittedServer, count: int) -> list[GateRun | None]:
    """In the order of a sequence, which gather keeps."""
    if played_alone(server):
        return [await opened.harness.audit(server) for _ in range(count)]
    return list(await asyncio.gather(*(opened.harness.audit(server) for _ in range(count))))


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
        pending = {comparison.server_package: comparison for comparison in audited}
        audited = await gathered_then_alone(
            [sr.server for sr in runs],
            lambda server: _retested(pending[server.server_package], server, opened),
        )
    by_package = {comparison.server_package: comparison for comparison in audited}
    comparisons = [
        _not_run_comparison(
            server.server_package,
            not_run[server.server_package],
            baselines.get(server.server_package),
        )
        if server.server_package in not_run
        else by_package[server.server_package]
        for server in opened.options.servers
    ]
    return decide(comparisons, mismatches)


def _candidate(server_runs: ServerRuns) -> ServerCandidate:
    return ServerCandidate(
        server_package=server_runs.server.server_package,
        fixture_fingerprint=nuisance_fixture_fingerprint(server_runs.server),
        runs=[run.flagged for run in server_runs.runs],
        completed=server_runs.completed,
    )


async def _retested(
    comparison: ServerComparison, server: AdmittedServer, opened: OpenedGate
) -> ServerComparison:
    """One retest at a time, until the baseline's retest rule decides or a retest does not
    complete."""
    if comparison.outcome != ServerOutcome.PENDING_RETEST:
        return comparison
    rule = opened.baselines()[server.server_package].retest_rule
    retests: list[bool | None] = []
    settled = comparison
    while settled.outcome == ServerOutcome.PENDING_RETEST:
        run = await opened.harness.audit(server)
        retests.append(None if run is None else run.flagged)
        settled = apply_retests(comparison, retests, rule)
    return settled


def _not_run_comparison(
    server_package: str, failure: str, baseline: NuisanceServerBaseline | None
) -> ServerComparison:
    return ServerComparison(
        server_package=server_package,
        outcome=ServerOutcome.NOT_RUN,
        candidate_runs=[],
        baseline_runs=[] if baseline is None else baseline.runs,
        detail=failure,
    )
