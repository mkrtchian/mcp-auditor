import threading
from collections.abc import Sequence
from datetime import date
from pathlib import Path
from typing import Literal

import tests.unit.support.nuisance_walks as walks
from evals.cve.backends.lifecycle import BackendLifecycle
from evals.cve.census.census import CLASSIFIERS, Census
from evals.cve.census.classification import Classification
from evals.cve.census.work import AgentRecord, AgentRole
from evals.cve.detection import baseline as detection_baseline
from evals.cve.grammar import FlawClass
from evals.cve.nuisance.admission.admission import (
    AdmittedServer,
    BenignCall,
    FieldAgreement,
    FixCheckRecord,
    FlawRecord,
    NuisanceAdmission,
    ToolRecord,
)
from evals.cve.nuisance.admission.admission_load import AdmissionReferences, admission_problems
from evals.cve.nuisance.admission.admission_records import RealSoftwareRecord
from evals.cve.nuisance.admission.walk_record import WalkInputs
from evals.cve.nuisance.backend_registry import RegisteredBackend
from evals.cve.nuisance.exits import ExitReason, RecordedExit
from evals.cve.planting_base import PlantingHost, SymbolicUser
from tests.unit.support import census_draws, censuses

OTHER_PACKAGE = "PyPI:context-forge"

SERVER_PACKAGE = "npm:@acme/files"
FIRST_FLAW = censuses.FLAW_WITH_A_CVE
SECOND_FLAW = censuses.OSV_ONLY_FLAW
PATCHED_VERSION = "1.2.0"


def problems_of(admission: NuisanceAdmission, census: WalkInputs | None = None) -> list[str]:
    references = AdmissionReferences(
        census if census is not None else walk_inputs_of(),
        detection_baseline.grammar_fingerprint(),
        a_backend_registry(),
    )
    return admission_problems(admission, references)


def walk_inputs_of() -> WalkInputs:
    return walks.walk_inputs_of(a_census())


def a_census() -> Census:
    """The census whose detection walk reaches SERVER_PACKAGE through FIRST_FLAW. Its other flaws
    of the package then add nothing to the queue."""
    return census_draws.with_a_walk_skipping(censuses.a_census(), FIRST_FLAW)


def a_backend_registry(lifecycle: BackendLifecycle | None = None) -> dict[str, RegisteredBackend]:
    """One backend, `fake-net` and `fake/backend:1.0`, under the lifecycle's key."""
    registered = lifecycle if lifecycle is not None else a_fake_lifecycle()
    return {
        registered.key: RegisteredBackend(
            lifecycle=registered,
            network="fake-net",
            images=("fake/backend:1.0",),
            built_services=(),
            served=(),
        )
    }


def a_fake_lifecycle(key: str = "fake") -> BackendLifecycle:
    return BackendLifecycle(key, threading.Lock(), _no_ensure, _fake_server_args, _no_remove)


def _no_ensure() -> None:
    pass


def _fake_server_args(
    name: str, image: str, host: PlantingHost, server_launch: Sequence[str]
) -> list[str]:
    return ["run", "fake"]


def _no_remove(name: str) -> None:
    pass


def written(tmp_path: Path, admission: NuisanceAdmission) -> Path:
    path = tmp_path / "nuisance_admission.json"
    path.write_text(admission.model_dump_json(indent=2))
    return path


def walk_inputs_with_the_second_flaw_under_another_package() -> WalkInputs:
    census = a_census()

    def relabel(own: list[Classification]) -> list[Classification]:
        return [
            each.model_copy(update={"server_package": OTHER_PACKAGE})
            if each.flaw == SECOND_FLAW
            else each
            for each in own
        ]

    classifications = {
        classifier: relabel(census.classifications[classifier]) for classifier in CLASSIFIERS
    }
    relabeled = census.model_copy(update={"classifications": classifications})
    return walks.walk_inputs_of(relabeled)


ACCEPTANCE_FLAW = walks.A_CURRENT_TARGET_FLAW
ACCEPTANCE_PACKAGE = "npm:an-acceptance-target-server"


def a_census_with_an_acceptance_server() -> Census:
    """A census that also classifies the acceptance target flaw ACCEPTANCE_FLAW, outside the draw
    order, under ACCEPTANCE_PACKAGE."""
    with_target = censuses.with_a_cve_of(censuses.a_census(), ACCEPTANCE_FLAW, ACCEPTANCE_PACKAGE)
    return census_draws.with_a_walk_skipping(with_target, FIRST_FLAW)


def admitting_the_acceptance_server() -> NuisanceAdmission:
    return admitting_the_server_of(ACCEPTANCE_FLAW, ACCEPTANCE_PACKAGE, "acceptance-nuisance")


def admitting_the_server_of(flaw: str, server_package: str, service: str) -> NuisanceAdmission:
    server = a_server([a_flaw_record(flaw, FlawClass.READ_OUTSIDE_SCOPE, PATCHED_VERSION)])
    return an_admission().model_copy(
        update={
            "servers": [
                server.model_copy(
                    update={
                        "server_package": server_package,
                        "reaching_flaw": flaw,
                        "service": service,
                    }
                )
            ]
        }
    )


def a_flaw_record(
    flaw: str,
    effect_class: FlawClass | None,
    patched_version: str | None,
    tools: list[ToolRecord] | None = None,
    fix_check: FixCheckRecord | None = None,
) -> FlawRecord:
    the_tools = (
        tools if tools is not None else [a_tool(f"{flaw}_read", f"{flaw}_read", "unchanged")]
    )
    return FlawRecord(
        flaw=flaw,
        tools=the_tools,
        effect_class=effect_class,
        patched_version=patched_version,
        patched_source="advisory",
        launch_option=None,
        benign_calls=[
            a_benign_call(tool.patched_name or tool.vulnerable_name or "") for tool in the_tools
        ],
        backend_need="none",
        declared_function_is_effect=False,
        fix_check=fix_check if fix_check is not None else a_passing_fix_check(),
    )


def a_passing_fix_check(server_patched_surfaces: bool | None = None) -> FixCheckRecord:
    return FixCheckRecord(
        source="fix_check",
        witness="nonce-0",
        exploit_calls=["read_file"],
        vulnerable_surfaces=True,
        patched_surfaces=False,
        server_patched_surfaces=server_patched_surfaces,
        patched_benign_errored=False,
        relies_on_relaying_stand_in=False,
    )


def a_benign_call(tool: str) -> BenignCall:
    return BenignCall(tool=tool, arguments={}, expect=expected_text(tool), before=[])


def expected_text(tool: str) -> str:
    return f"{tool} answered"


def a_tool(
    vulnerable: str | None,
    patched: str | None,
    status: Literal["unchanged", "renamed", "removed"],
) -> ToolRecord:
    removed = status == "removed"
    return ToolRecord(
        vulnerable_name=vulnerable,
        patched_name=patched,
        status=status,
        real_software=None if removed else RealSoftwareRecord(answers=True),
        declared_function_is_effect=None if removed else False,
    )


def an_admission() -> NuisanceAdmission:
    return NuisanceAdmission(
        rule_commit="0" * 40,
        grammar_fingerprint=detection_baseline.grammar_fingerprint(),
        servers=[an_admitted_server()],
        exits=[],
    )


def an_admitted_server() -> AdmittedServer:
    return AdmittedServer(
        server_package=SERVER_PACKAGE,
        reaching_flaw=FIRST_FLAW,
        flaws=[
            a_flaw_record(FIRST_FLAW, FlawClass.READ_OUTSIDE_SCOPE, PATCHED_VERSION),
            a_flaw_record(SECOND_FLAW, FlawClass.COMMAND_EXECUTION, PATCHED_VERSION),
        ],
        runs_over_stdio=True,
        runs_under_docker=True,
        host=PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=False),
        launch=["node", "server.js"],
        service="filesystem-nuisance",
        agents=[
            AgentRecord(role=AgentRole.ADMITTER, scope=SERVER_PACKAGE, model=model)
            for model in ("claude-opus-4-8", "claude-opus-5-5")
        ],
        agreement=[FieldAgreement(flaw=FIRST_FLAW, field="effect_class", agreed=True)],
        settlements=[],
        patched_version=PATCHED_VERSION,
        stand_ins=[],
        seeds=[],
        software_releases=[],
    )


def a_server(flaws: list[FlawRecord], patched_version: str = PATCHED_VERSION) -> AdmittedServer:
    server = an_admitted_server()
    return server.model_copy(update={"flaws": flaws, "patched_version": patched_version})


def a_recorded_exit(
    package: str, reason: ExitReason = ExitReason.NO_COUNTED_TOOL_LEFT
) -> RecordedExit:
    return RecordedExit(server_package=package, reason=reason, logged_on=date(2026, 11, 9))
