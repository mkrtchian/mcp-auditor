from collections.abc import Callable
from pathlib import Path
from typing import Literal

import tests.unit.support.test_holdout_census_given as census_given
from evals import cve_baseline
from evals.census_classification import Classification
from evals.census_work import AgentRecord, AgentRole
from evals.cve_grammar import MechanismClass
from evals.cve_planting_base import PlantingHost, SymbolicUser
from evals.holdout_census import CLASSIFIERS, HoldoutCensus
from evals.nuisance_admission import (
    AdmissionSettlement,
    AdmittedServer,
    BenignCall,
    FieldAgreement,
    FixCheckRecord,
    FlawRecord,
    NuisanceAdmission,
    ToolRecord,
)

OTHER_PACKAGE = "PyPI:context-forge"

SERVER_PACKAGE = "npm:@acme/files"
FIRST_FLAW = census_given.FLAW_WITH_A_CVE
SECOND_FLAW = census_given.OSV_ONLY_FLAW
PATCHED_VERSION = "1.2.0"


def a_census() -> HoldoutCensus:
    return census_given.a_census()


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
            BenignCall(tool=tool.patched_name or tool.vulnerable_name or "", arguments={})
            for tool in the_tools
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
    )


def a_tool(
    vulnerable: str | None,
    patched: str | None,
    status: Literal["unchanged", "renamed", "removed"],
) -> ToolRecord:
    return ToolRecord(vulnerable_name=vulnerable, patched_name=patched, status=status)


def a_server(flaws: list[FlawRecord], patched_version: str = PATCHED_VERSION) -> AdmittedServer:
    server = _a_server()
    return server.model_copy(update={"flaws": flaws, "patched_version": patched_version})


def with_host(server: AdmittedServer, host: PlantingHost) -> AdmittedServer:
    return server.model_copy(update={"host": host})


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
                "benign_calls": [BenignCall(tool="write_file", arguments={})],
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


def a_census_with_the_second_flaw_under_another_package() -> HoldoutCensus:
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
    return census.model_copy(update={"classifications": classifications})


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
