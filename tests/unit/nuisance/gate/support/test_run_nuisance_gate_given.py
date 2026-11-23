from dataclasses import dataclass, field
from pathlib import Path

import pytest

import tests.unit.support.admission_mutations as mutations
import tests.unit.support.captured_console as captured_console
import tests.unit.support.nuisance_admissions as admissions
import tests.unit.support.nuisance_walks as walks
from evals.baseline import BaselineStatus
from evals.cve.census.census import Census
from evals.cve.nuisance.admission.admission import NuisanceAdmission
from evals.cve.nuisance.gate.gate import NuisanceGateResult
from evals.cve.nuisance.gate.gate_command_deps import GateCommandDeps
from evals.cve.nuisance.gate.gate_session_model import (
    NuisanceGateHarness,
    NuisanceGateOptions,
    NuisanceGateSession,
    WrittenBaseline,
)
from evals.cve.provider_errors import ProviderFatal
from evals.gate_outcome import GateOutcome
from evals.run_nuisance import NuisanceCommandDeps
from tests.unit.nuisance.gate.support.nuisance_gate_sessions import a_harness, scripted
from tests.unit.support import census_draws, censuses
from tests.unit.support.detection_holdout_runs import SETTINGS, ready_conditions

GATE_SERVER = admissions.ACCEPTANCE_PACKAGE
REVOKED_KEY = "sk-secret"


def without_any_llm_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """A safety net that keeps a regression past an early return from reaching a provider."""
    for key in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "OPENROUTER_API_KEY"):
        monkeypatch.delenv(key, raising=False)


def a_gate_set_of_one_server(
    tmp_path: Path, admitted: NuisanceAdmission | None = None
) -> list[str]:
    """The census, walk record and admission arguments of a gate whose one server is GATE_SERVER,
    admitted by `admitted`, by default fully recorded."""
    return _gate_arguments(
        tmp_path,
        admissions.a_census_with_an_acceptance_server(),
        admitted or admissions.admitting_the_acceptance_server(),
    )


OTHER_GATE_FLAW = "CVE-2025-65513"
OTHER_GATE_SERVER = "npm:other-acceptance"


def a_gate_set_beside_an_unrecorded_server(tmp_path: Path) -> list[str]:
    """The arguments of a gate of GATE_SERVER, fully recorded, and OTHER_GATE_SERVER, whose
    admission predates the fields nuisance suite rule v3 adds."""
    census = census_draws.with_a_walk_skipping(
        censuses.with_a_cve_of(
            censuses.with_a_cve_of(
                censuses.a_census(),
                admissions.ACCEPTANCE_FLAW,
                admissions.ACCEPTANCE_PACKAGE,
            ),
            OTHER_GATE_FLAW,
            OTHER_GATE_SERVER,
        ),
        admissions.FIRST_FLAW,
    )
    recorded = admissions.admitting_the_acceptance_server()
    other = mutations.with_every_new_field_unrecorded(
        admissions.admitting_the_server_of(OTHER_GATE_FLAW, OTHER_GATE_SERVER, "other-nuisance")
    )
    both = recorded.model_copy(update={"servers": [*recorded.servers, *other.servers]})
    return _gate_arguments(tmp_path, census, both)


def _gate_arguments(tmp_path: Path, census: Census, admitted: NuisanceAdmission) -> list[str]:
    return [
        *gate_arguments(tmp_path, census, admissions.written(tmp_path, admitted)),
        "--report",
        str(tmp_path / "nuisance_gate_report.json"),
    ]


def gate_arguments(tmp_path: Path, census: Census, admission_path: Path) -> list[str]:
    return [
        *walks.committed_census_arguments(tmp_path, censuses.written(tmp_path, census)),
        "--admission",
        str(admission_path),
    ]


def a_captured_console(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> captured_console.CapturedOutput:
    return captured_console.a_captured_console(capsys, monkeypatch, width=400)


@dataclass
class GreenRecording:
    """A gate run that audits nothing and records one baseline file with `status`, reaching no
    Docker and no LLM, through `deps`. It holds the options the session received."""

    directory: Path
    status: BaselineStatus
    received: list[NuisanceGateOptions] = field(default_factory=list[NuisanceGateOptions])

    @property
    def options(self) -> NuisanceGateOptions:
        [options] = self.received
        return options

    @property
    def deps(self) -> NuisanceCommandDeps:
        return NuisanceCommandDeps(
            gate=GateCommandDeps(
                conditions=ready_conditions,
                settings=lambda: SETTINGS,
                harness=self._harness,
                run_gate=self._session,
            )
        )

    def _harness(self, *_: object) -> NuisanceGateHarness:
        return a_harness(self.directory, scripted({}))

    async def _session(
        self, options: NuisanceGateOptions, _harness: NuisanceGateHarness
    ) -> NuisanceGateSession:
        self.received.append(options)
        return NuisanceGateSession(
            audits=[],
            gate=NuisanceGateResult(outcome=GateOutcome.GREEN, reasons=[], servers=[]),
            not_run={},
            orphans=[],
            written=[WrittenBaseline(GATE_SERVER, self.status, leaves_gated_set=False)],
            recording_refused=[],
            throttled_requests=0,
            exit_code=0,
        )


def a_gate_stopped_by_a_revoked_key(directory: Path) -> NuisanceCommandDeps:
    """A gate run that raises a fatal provider error chained, as an audit chains it, from a cause
    whose message quotes the key."""

    async def stopped(
        _options: NuisanceGateOptions, _harness: NuisanceGateHarness
    ) -> NuisanceGateSession:
        cause = PermissionError(f"the key {REVOKED_KEY} was revoked")
        raise ProviderFatal(cause) from cause

    return NuisanceCommandDeps(
        gate=GateCommandDeps(
            conditions=ready_conditions,
            settings=lambda: SETTINGS,
            harness=lambda *_: a_harness(directory, scripted({})),
            run_gate=stopped,
        )
    )
