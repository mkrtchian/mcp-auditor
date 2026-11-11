from dataclasses import dataclass, field
from io import StringIO
from pathlib import Path

import pytest

import tests.unit.support.test_census_given as census_given
import tests.unit.support.test_detection_draw_record_given as draw_given
import tests.unit.support.test_eval_display_given as display_given
import tests.unit.support.test_nuisance_admission_given as admission_given
import tests.unit.support.test_nuisance_admission_records_given as records_given
import tests.unit.support.test_nuisance_walk_given as walk_given
from evals.baseline import BaselineStatus
from evals.cve.census.census import Census
from evals.cve.nuisance import gate_command as nuisance_gate_command
from evals.cve.nuisance import gate_console as nuisance_gate_console
from evals.cve.nuisance.gate import NuisanceGateResult
from evals.cve.nuisance.gate_baseline import NuisanceGateConditions
from evals.cve.nuisance.gate_session_model import (
    NuisanceGateHarness,
    NuisanceGateOptions,
    NuisanceGateSession,
    WrittenBaseline,
)
from evals.gate_outcome import GateOutcome
from evals.nuisance_admission import NuisanceAdmission
from tests.unit.support.test_nuisance_gate_baseline_given import conditions
from tests.unit.support.test_nuisance_gate_session_given import a_harness, scripted

GATE_SERVER = admission_given.ACCEPTANCE_PACKAGE


def gate_arguments(tmp_path: Path, census: Census, admission_path: Path) -> list[str]:
    return [
        *walk_given.committed_census_arguments(tmp_path, census_given.written(tmp_path, census)),
        "--admission",
        str(admission_path),
    ]


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
        admission_given.a_census_with_an_acceptance_server(),
        admitted or admission_given.admitting_the_acceptance_server(),
    )


OTHER_GATE_FLAW = "CVE-2025-65513"
OTHER_GATE_SERVER = "npm:other-acceptance"


def a_gate_set_beside_an_unrecorded_server(tmp_path: Path) -> list[str]:
    """The arguments of a gate of GATE_SERVER, fully recorded, and OTHER_GATE_SERVER, whose
    admission predates the fields nuisance suite rule v3 adds."""
    census = draw_given.with_a_walk_skipping(
        census_given.with_a_cve_of(
            census_given.with_a_cve_of(
                census_given.a_census(),
                admission_given.ACCEPTANCE_FLAW,
                admission_given.ACCEPTANCE_PACKAGE,
            ),
            OTHER_GATE_FLAW,
            OTHER_GATE_SERVER,
        ),
        admission_given.FIRST_FLAW,
    )
    recorded = admission_given.admitting_the_acceptance_server()
    other = records_given.with_every_new_field_unrecorded(
        admission_given.admitting_the_server_of(
            OTHER_GATE_FLAW, OTHER_GATE_SERVER, "other-nuisance"
        )
    )
    both = recorded.model_copy(update={"servers": [*recorded.servers, *other.servers]})
    return _gate_arguments(tmp_path, census, both)


def _gate_arguments(tmp_path: Path, census: Census, admitted: NuisanceAdmission) -> list[str]:
    return [
        *gate_arguments(tmp_path, census, admission_given.written(tmp_path, admitted)),
        "--report",
        str(tmp_path / "nuisance_gate_report.json"),
    ]


def a_captured_console(monkeypatch: pytest.MonkeyPatch) -> StringIO:
    return display_given.a_captured_console(
        monkeypatch, nuisance_gate_command, nuisance_gate_console, width=400
    )


@dataclass
class SeenSession:
    received: list[NuisanceGateOptions] = field(default_factory=list[NuisanceGateOptions])

    @property
    def options(self) -> NuisanceGateOptions:
        [options] = self.received
        return options


def a_green_recording_writing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, status: BaselineStatus
) -> SeenSession:
    """A gate run that audits nothing and records one baseline file with this status, reaching
    no Docker and no LLM. What it returns holds the options the session received."""
    seen = SeenSession()

    async def session(
        options: NuisanceGateOptions, harness: NuisanceGateHarness
    ) -> NuisanceGateSession:
        seen.received.append(options)
        return NuisanceGateSession(
            audits=[],
            gate=NuisanceGateResult(outcome=GateOutcome.GREEN, reasons=[], servers=[]),
            not_run={},
            orphans=[],
            written=[WrittenBaseline(GATE_SERVER, status, leaves_gated_set=False)],
            recording_refused=[],
            throttled_requests=0,
            exit_code=0,
        )

    def gate_conditions(
        _settings: object, _conditions: object, runs: int
    ) -> NuisanceGateConditions:
        return conditions(runs)

    def default_harness(*_: object) -> NuisanceGateHarness:
        return a_harness(tmp_path, scripted({}))

    monkeypatch.setattr(nuisance_gate_command, "gate_conditions", gate_conditions)
    monkeypatch.setattr(nuisance_gate_command, "default_harness", default_harness)
    monkeypatch.setattr(nuisance_gate_command, "run_gate", session)
    return seen
