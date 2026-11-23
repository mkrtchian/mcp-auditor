from collections.abc import Awaitable, Callable, Mapping, Sequence
from pathlib import Path

import tests.unit.nuisance.gate.support.nuisance_gate_baselines as nuisance_gate_baselines
import tests.unit.support.nuisance_holdout_runs as holdout_runs
from evals.cve.nuisance.admission.admission import AdmittedServer
from evals.cve.nuisance.fingerprint import nuisance_fixture_fingerprint
from evals.cve.nuisance.gate.gate import ServerComparison, ServerOutcome
from evals.cve.nuisance.gate.gate_audit import GateRun
from evals.cve.nuisance.gate.gate_baseline import (
    NuisanceGateConditions,
    NuisanceServerBaseline,
    write_baseline,
)
from evals.cve.nuisance.gate.gate_session_model import (
    NuisanceGateHarness,
    NuisanceGateOptions,
    NuisanceGateSession,
)
from evals.eval_session import TreeState
from evals.gate_outcome import GateOutcome
from tests.fakes import FakeContainerSweep, ScriptedBenignCall

# Services whose Dockerfiles exist, since the session fingerprints each server's fixture.
FILESYSTEM = holdout_runs.a_server(
    "npm:@modelcontextprotocol/server-filesystem", service="filesystem-patched"
)
KUBERNETES = holdout_runs.a_server("npm:mcp-server-kubernetes", service="kubernetes-patched")
COMMIT = "c0ffee"
RECORDED_AT = "2026-10-22T12:00:00+00:00"
CLEAN_TREE = TreeState(COMMIT, False)

type GateAuditCall = Callable[[AdmittedServer], Awaitable[GateRun | None]]


def clean_runs(count: int = 3) -> list[GateRun | None]:
    return [a_gate_run(False) for _ in range(count)]


def a_gate_run(flagged: bool) -> GateRun:
    return GateRun(flagged=flagged, report=holdout_runs.a_report(flagged))


def scripted(scripts: Mapping[str, Sequence[GateRun | None]]) -> GateAuditCall:
    """Plays each server's script in order, and fails the test on an audit it does not script."""
    remaining = {package: list(script) for package, script in scripts.items()}

    async def audit(server: AdmittedServer) -> GateRun | None:
        script = remaining.get(server.server_package)
        if not script:
            raise AssertionError(f"unscripted audit of {server.server_package}")
        return script.pop(0)

    return audit


def a_harness(
    directory: Path,
    audit: GateAuditCall,
    *,
    benign_call: Mapping[str, str | Sequence[str | None]] | None = None,
    tree: TreeState = CLEAN_TREE,
    tree_after_runs: TreeState | None = None,
    announce: Callable[[int], None] = lambda _: None,
    throttled_requests: int = 0,
    containers: FakeContainerSweep | None = None,
) -> NuisanceGateHarness:
    """`benign_call` scripts each package's failure reasons as `ScriptedBenignCall` reads them.
    `tree_after_runs` is what every read of the tree after the first returns, `tree` by
    default."""
    docker = containers or FakeContainerSweep()
    reads: list[TreeState] = []

    def read_tree() -> TreeState:
        state = tree if not reads else (tree_after_runs or tree)
        reads.append(state)
        return state

    return NuisanceGateHarness(
        audit=audit,
        benign_call=ScriptedBenignCall(benign_call),
        announce_audits=announce,
        throttled_requests=lambda: throttled_requests,
        rebuild=lambda services: None,
        image_ids=lambda names: {name: f"sha256:{name}" for name in names},
        backend_image_ids=lambda tags: {tag: f"sha256:{tag}" for tag in tags},
        read_tree=read_tree,
        clock=lambda: RECORDED_AT,
        baselines=directory,
        check_networks=lambda: None,
        sweep=docker.sweep,
    )


def options(
    servers: Sequence[AdmittedServer],
    *,
    gate_packages: set[str] | None = None,
    record: bool = False,
    runs: int = 3,
) -> NuisanceGateOptions:
    packages = gate_packages or {server.server_package for server in servers}
    return NuisanceGateOptions(
        servers=list(servers),
        gate_packages=frozenset(packages),
        conditions=nuisance_gate_baselines.conditions(runs),
        record_baseline=record,
    )


def a_gated_file(
    directory: Path,
    server: AdmittedServer,
    recorded: NuisanceGateConditions | None = None,
) -> None:
    a_baseline_file(
        directory, server, nuisance_gate_baselines.a_gated_baseline(server.server_package), recorded
    )


def a_baseline_file(
    directory: Path,
    server: AdmittedServer,
    baseline: NuisanceServerBaseline,
    recorded: NuisanceGateConditions | None = None,
) -> None:
    update = {
        "fixture_fingerprint": nuisance_fixture_fingerprint(server),
        "conditions": recorded or nuisance_gate_baselines.conditions(),
    }
    write_baseline(directory, baseline.model_copy(update=update))


def the_one_server_ends(
    session: NuisanceGateSession, outcome: ServerOutcome, gate_outcome: GateOutcome
) -> ServerComparison:
    [comparison] = session.gate.servers
    assert comparison.outcome == outcome
    assert session.gate.outcome == gate_outcome
    return comparison
