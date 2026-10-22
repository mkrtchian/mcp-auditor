from collections.abc import Awaitable, Callable, Mapping, Sequence
from pathlib import Path

import tests.unit.support.test_nuisance_run_given as run_given
from evals.eval_session import TreeState
from evals.nuisance_admission import AdmittedServer, NuisanceAdmission
from evals.nuisance_audit import GateRun
from evals.nuisance_gate_baseline import (
    NuisanceGateConditions,
    NuisanceServerBaseline,
    baseline_file_name,
    write_baseline,
)
from evals.nuisance_gate_session_model import NuisanceGateHarness, NuisanceGateOptions
from evals.nuisance_images import nuisance_fixture_fingerprint
from tests.unit.support.test_nuisance_admission_given import an_admission
from tests.unit.support.test_nuisance_gate_baseline_given import a_gated_baseline, conditions

# Services whose Dockerfiles exist, since the session fingerprints each server's fixture.
FILESYSTEM = run_given.a_server(
    "npm:@modelcontextprotocol/server-filesystem", service="filesystem-patched"
)
KUBERNETES = run_given.a_server("npm:mcp-server-kubernetes", service="kubernetes-patched")
COMMIT = "c0ffee"
RECORDED_AT = "2026-10-22T12:00:00+00:00"
CLEAN_TREE = TreeState(COMMIT, False)

type GateAuditCall = Callable[[AdmittedServer], Awaitable[GateRun | None]]


def a_gate_run(flagged: bool) -> GateRun:
    return GateRun(flagged=flagged, report=run_given.a_report(flagged))


def clean_runs(count: int = 3) -> list[GateRun | None]:
    return [a_gate_run(False) for _ in range(count)]


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
    benign_call: Mapping[str, str] | None = None,
    tree: TreeState = CLEAN_TREE,
    tree_after_runs: TreeState | None = None,
) -> NuisanceGateHarness:
    """`benign_call` maps a package to its failure. `tree_after_runs` is what every read of the
    tree after the first returns, `tree` by default."""
    failures = benign_call or {}
    reads: list[TreeState] = []

    async def call(server: AdmittedServer) -> str | None:
        return failures.get(server.server_package)

    def read_tree() -> TreeState:
        state = tree if not reads else (tree_after_runs or tree)
        reads.append(state)
        return state

    return NuisanceGateHarness(
        audit=audit,
        benign_call=call,
        rebuild=lambda services: None,
        image_ids=lambda names: {name: f"sha256:{name}" for name in names},
        read_tree=read_tree,
        clock=lambda: RECORDED_AT,
        baselines=directory,
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
        conditions=conditions(runs),
        record_baseline=record,
    )


def a_gated_file(
    directory: Path,
    server: AdmittedServer,
    recorded: NuisanceGateConditions | None = None,
) -> None:
    _write(directory, server, a_gated_baseline(server.server_package), recorded)


def admitting(*servers: AdmittedServer) -> NuisanceAdmission:
    return an_admission().model_copy(update={"servers": list(servers)})


def other_conditions() -> NuisanceGateConditions:
    return conditions().model_copy(update={"model": "another-model"})


def an_orphaned_file(directory: Path) -> str:
    package = "npm:no-longer-current"
    write_baseline(directory, a_gated_baseline(package))
    return baseline_file_name(package)


def _write(
    directory: Path,
    server: AdmittedServer,
    baseline: NuisanceServerBaseline,
    recorded: NuisanceGateConditions | None,
) -> None:
    update = {
        "fixture_fingerprint": nuisance_fixture_fingerprint(server),
        "conditions": recorded or conditions(),
    }
    write_baseline(directory, baseline.model_copy(update=update))
