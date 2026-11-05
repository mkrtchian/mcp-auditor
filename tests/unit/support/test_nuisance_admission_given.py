import threading
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Literal

import tests.unit.support.test_census_draw_given as draw_given
import tests.unit.support.test_holdout_census_given as census_given
import tests.unit.support.test_nuisance_walk_given as walk_given
from evals import cve_baseline
from evals.backend_lifecycle import BackendLifecycle
from evals.census_classification import Classification
from evals.census_work import AgentRecord, AgentRole
from evals.cve_grammar import MechanismClass
from evals.cve_planting_base import PlantingHost, SymbolicUser
from evals.holdout_census import CLASSIFIERS, HoldoutCensus
from evals.nuisance_admission import (
    AdmissionSettlement,
    AdmittedServer,
    BackendFixture,
    BenignCall,
    FieldAgreement,
    FixCheckRecord,
    FlawRecord,
    NuisanceAdmission,
    ToolRecord,
)
from evals.nuisance_admission_records import RealSoftwareRecord
from evals.nuisance_backends import RegisteredBackend
from evals.nuisance_walk_record import NuisanceCensus

OTHER_PACKAGE = "PyPI:context-forge"

SERVER_PACKAGE = "npm:@acme/files"
FIRST_FLAW = census_given.FLAW_WITH_A_CVE
SECOND_FLAW = census_given.OSV_ONLY_FLAW
PATCHED_VERSION = "1.2.0"


def a_census() -> HoldoutCensus:
    """The holdout census whose walk reaches SERVER_PACKAGE through FIRST_FLAW. Its other flaws
    of the package then add nothing to the queue."""
    return draw_given.with_a_walk_skipping(census_given.a_census(), FIRST_FLAW)


def a_nuisance_census() -> NuisanceCensus:
    return walk_given.a_nuisance_census(a_census())


def an_admission() -> NuisanceAdmission:
    return NuisanceAdmission(
        rule_commit="0" * 40,
        grammar_fingerprint=cve_baseline.grammar_fingerprint(),
        servers=[_a_server()],
    )


def _a_server() -> AdmittedServer:
    return AdmittedServer(
        server_package=SERVER_PACKAGE,
        reaching_flaw=FIRST_FLAW,
        flaws=[
            a_flaw_record(FIRST_FLAW, MechanismClass.READ_OUTSIDE_SCOPE, PATCHED_VERSION),
            a_flaw_record(SECOND_FLAW, MechanismClass.COMMAND_EXECUTION, PATCHED_VERSION),
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


def a_flaw_record(
    flaw: str,
    effect_class: MechanismClass | None,
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
    return BenignCall(tool=tool, arguments={}, expect=f"{tool} answered", before=[])


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


def a_server(flaws: list[FlawRecord], patched_version: str = PATCHED_VERSION) -> AdmittedServer:
    server = _a_server()
    return server.model_copy(update={"flaws": flaws, "patched_version": patched_version})


def with_host(server: AdmittedServer, host: PlantingHost) -> AdmittedServer:
    return server.model_copy(update={"host": host})


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


def a_backend_registry() -> dict[str, RegisteredBackend]:
    return {
        "fake": RegisteredBackend(
            lifecycle=a_fake_lifecycle(),
            network="fake-net",
            image="fake/backend:1.0",
            built_services=(),
            served=(),
        )
    }


def with_a_backend(server: AdmittedServer, backend: BackendFixture) -> AdmittedServer:
    return server.model_copy(update={"backend": backend})


def with_a_registered_backend(admission: NuisanceAdmission) -> NuisanceAdmission:
    backend = BackendFixture(provisioner="fake", image="fake/backend:1.0", network="fake-net")
    return _with_server(admission, lambda server: with_a_backend(server, backend))


def with_an_unknown_backend_provisioner(admission: NuisanceAdmission) -> NuisanceAdmission:
    backend = BackendFixture(provisioner="ghost", image="fake/backend:1.0", network="fake-net")
    return _with_server(admission, lambda server: with_a_backend(server, backend))


def with_a_backend_fixture_differing_from_its_provisioner(
    admission: NuisanceAdmission,
) -> NuisanceAdmission:
    backend = BackendFixture(provisioner="fake", image="fake/backend:2.0", network="fake-net")
    return _with_server(admission, lambda server: with_a_backend(server, backend))


def with_a_networked_host_and_no_backend(admission: NuisanceAdmission) -> NuisanceAdmission:
    host = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=True)
    return _with_server(admission, lambda server: with_host(server, host))


def with_every_flaw_needing_the_fixture(admission: NuisanceAdmission) -> NuisanceAdmission:
    def changed(server: AdmittedServer) -> AdmittedServer:
        flaws = [flaw.model_copy(update={"backend_need": "fixture"}) for flaw in server.flaws]
        return server.model_copy(update={"flaws": flaws})

    return _with_server(admission, changed)


def written(tmp_path: Path, admission: NuisanceAdmission) -> Path:
    path = tmp_path / "nuisance_admission.json"
    path.write_text(admission.model_dump_json(indent=2))
    return path


def with_a_stale_grammar_fingerprint(admission: NuisanceAdmission) -> NuisanceAdmission:
    return admission.model_copy(update={"grammar_fingerprint": "stale"})


def with_an_unsettled_disagreement(admission: NuisanceAdmission) -> NuisanceAdmission:
    disagreement = FieldAgreement(flaw=None, field="runs_under_docker", agreed=False)
    return _with_server(
        admission,
        lambda server: server.model_copy(update={"agreement": [*server.agreement, disagreement]}),
    )


def with_a_flaw_of_another_server(admission: NuisanceAdmission) -> NuisanceAdmission:
    foreign = a_flaw_record("CVE-2099-9999", None, None)
    return _with_server(
        admission, lambda server: server.model_copy(update={"flaws": [*server.flaws, foreign]})
    )


def with_no_counted_tool(admission: NuisanceAdmission) -> NuisanceAdmission:
    return _with_server(
        admission,
        lambda server: server.model_copy(
            update={
                "flaws": [
                    flaw.model_copy(update={"backend_need": "external"}) for flaw in server.flaws
                ]
            }
        ),
    )


def with_a_server_patched_version_of_no_flaw(admission: NuisanceAdmission) -> NuisanceAdmission:
    def changed(server: AdmittedServer) -> AdmittedServer:
        flaws = [
            flaw.model_copy(
                update={
                    "fix_check": flaw.fix_check.model_copy(
                        update={"server_patched_surfaces": False}
                    )
                }
            )
            for flaw in server.flaws
        ]
        return server.model_copy(update={"flaws": flaws, "patched_version": "2.0.0"})

    return _with_server(admission, changed)


def with_a_server_patched_surfaces_set_on_the_servers_own_version(
    admission: NuisanceAdmission,
) -> NuisanceAdmission:
    def changed(server: AdmittedServer) -> AdmittedServer:
        first, *rest = server.flaws
        surfacing = first.model_copy(
            update={
                "fix_check": first.fix_check.model_copy(update={"server_patched_surfaces": False})
            }
        )
        return server.model_copy(update={"flaws": [surfacing, *rest]})

    return _with_server(admission, changed)


def with_an_acceptance_service(admission: NuisanceAdmission) -> NuisanceAdmission:
    return _with_server(
        admission, lambda server: server.model_copy(update={"service": "filesystem-patched"})
    )


def with_an_inconsistent_tool_record(admission: NuisanceAdmission) -> NuisanceAdmission:
    def changed(server: AdmittedServer) -> AdmittedServer:
        first, *rest = server.flaws
        bad = first.model_copy(
            update={
                "tools": [a_tool("read_file", "write_file", "unchanged")],
                "benign_calls": [a_benign_call("write_file")],
            }
        )
        return server.model_copy(update={"flaws": [bad, *rest]})

    return _with_server(admission, changed)


def with_a_counted_tool_missing_its_benign_call(admission: NuisanceAdmission) -> NuisanceAdmission:
    def changed(server: AdmittedServer) -> AdmittedServer:
        first, *rest = server.flaws
        return server.model_copy(
            update={"flaws": [first.model_copy(update={"benign_calls": []}), *rest]}
        )

    return _with_server(admission, changed)


def a_nuisance_census_with_the_second_flaw_under_another_package() -> NuisanceCensus:
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
    return walk_given.a_nuisance_census(relabeled)


def with_the_second_flaw_settled_here(admission: NuisanceAdmission) -> NuisanceAdmission:
    settlement = AdmissionSettlement(
        server_package=SERVER_PACKAGE,
        flaw=SECOND_FLAW,
        field="server_package",
        value=SERVER_PACKAGE,
        reason="the advisory names the same package under another spelling",
    )
    return _with_server(
        admission,
        lambda server: server.model_copy(update={"settlements": [*server.settlements, settlement]}),
    )


def _with_server(
    admission: NuisanceAdmission, change: Callable[[AdmittedServer], AdmittedServer]
) -> NuisanceAdmission:
    return admission.model_copy(update={"servers": [change(admission.servers[0])]})


def admitting_the_server_of(flaw: str, server_package: str, service: str) -> NuisanceAdmission:
    server = a_server([a_flaw_record(flaw, MechanismClass.READ_OUTSIDE_SCOPE, PATCHED_VERSION)])
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


ACCEPTANCE_FLAW = "CVE-2025-53355"
ACCEPTANCE_PACKAGE = "npm:mcp-server-kubernetes"


def a_census_with_an_acceptance_server() -> HoldoutCensus:
    """A census that also classifies the benchmark flaw ACCEPTANCE_FLAW, outside the draw order,
    under ACCEPTANCE_PACKAGE."""
    with_target = census_given.with_a_cve_of(
        census_given.a_census(), ACCEPTANCE_FLAW, ACCEPTANCE_PACKAGE
    )
    return draw_given.with_a_walk_skipping(with_target, FIRST_FLAW)


def admitting_the_acceptance_server() -> NuisanceAdmission:
    return admitting_the_server_of(ACCEPTANCE_FLAW, ACCEPTANCE_PACKAGE, "kubernetes-nuisance")
