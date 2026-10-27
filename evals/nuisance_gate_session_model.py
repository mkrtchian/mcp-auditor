"""The value objects of one nuisance gate run: its options, its injected harness, the audits it
produces and the session fixed before any audit, the mirror of `cve_session_model`."""

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from evals.baseline import BaselineStatus
from evals.eval_session import TreeState
from evals.nuisance_admission import AdmittedServer
from evals.nuisance_audit import GateRun
from evals.nuisance_gate import NuisanceGateResult
from evals.nuisance_gate_baseline import (
    NuisanceGateConditions,
    NuisanceServerBaseline,
    baseline_file_name,
)
from mcp_auditor.domain.models import AuditReport

type Baselines = dict[str, NuisanceServerBaseline]


@dataclass(frozen=True)
class NuisanceGateHarness:
    # One run of one server, None when it did not complete. Called concurrently, it bounds
    # itself how many audits run at once.
    audit: Callable[[AdmittedServer], Awaitable[GateRun | None]]
    benign_call: Callable[[AdmittedServer], Awaitable[str | None]]  # its failure, or None
    announce_audits: Callable[[int], None]  # the main runs about to start, once vetted
    throttled_requests: Callable[[], int]  # the session's total so far
    rebuild: Callable[[Sequence[str]], None]
    image_ids: Callable[[Sequence[str]], dict[str, str]]
    backend_image_ids: Callable[[Sequence[str]], dict[str, str]]
    read_tree: Callable[[], TreeState]
    clock: Callable[[], str]  # ISO timestamp for recorded_at
    baselines: Path


@dataclass(frozen=True)
class NuisanceGateOptions:
    servers: list[AdmittedServer]  # already filtered by --server
    gate_packages: frozenset[str]  # the whole gate set, before --server
    conditions: NuisanceGateConditions
    record_baseline: bool


@dataclass(frozen=True)
class WrittenBaseline:
    server_package: str
    status: BaselineStatus
    leaves_gated_set: bool


@dataclass(frozen=True)
class GateAudit:
    """A completed main run, never a replay."""

    server_package: str
    run_index: int  # within its server, in submission order
    flagged: bool
    report: AuditReport


@dataclass(frozen=True)
class NuisanceGateSession:
    audits: list[GateAudit]
    gate: NuisanceGateResult
    not_run: dict[str, str]  # package to the benign call's failure
    orphans: list[str]  # baseline files of servers outside the gate set
    written: list[WrittenBaseline]
    recording_refused: list[str]  # why a recording was refused once the runs were paid for
    throttled_requests: int
    exit_code: int


@dataclass(frozen=True)
class ServerRuns:
    server: AdmittedServer
    runs: list[GateRun]  # the completed ones
    completed: bool
    audits: list[GateAudit]


@dataclass(frozen=True)
class OpenedGate:
    """Fixed before any audit. `tree` is set exactly when the run records."""

    options: NuisanceGateOptions
    harness: NuisanceGateHarness
    files: Baselines  # every file read at start, orphans included
    tree: TreeState | None

    def baselines(self) -> Baselines:
        gate = self.options.gate_packages
        return {package: b for package, b in self.files.items() if package in gate}

    def orphans(self) -> list[str]:
        gate = self.options.gate_packages
        return [baseline_file_name(p) for p in sorted(self.files) if p not in gate]
