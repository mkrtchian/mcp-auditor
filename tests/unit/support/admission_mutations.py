"""The admission mutators several test files of the nuisance and cve areas read: each returns a
changed copy of an admission or of one of its servers."""

import tests.unit.support.test_nuisance_admission_edits_given as edits
from evals.cve.nuisance.admission.admission import (
    AdmissionSettlement,
    AdmittedServer,
    BackendFixture,
    FieldAgreement,
    FlawRecord,
    NuisanceAdmission,
)
from evals.cve.planting_base import PlantingHost, PublicNames, SymbolicUser
from tests.unit.nuisance.admission.support.test_nuisance_admission_given import (
    SECOND_FLAW,
    SERVER_PACKAGE,
    a_benign_call,
    a_flaw_record,
    a_tool,
    an_admission,
)


def admitting(*servers: AdmittedServer) -> NuisanceAdmission:
    return an_admission().model_copy(update={"servers": list(servers)})


def with_a_registered_backend(admission: NuisanceAdmission) -> NuisanceAdmission:
    backend = BackendFixture(provisioner="fake", images=["fake/backend:1.0"], network="fake-net")
    return edits.with_the_server(admission, lambda server: with_a_backend(server, backend))


def with_a_backend(server: AdmittedServer, backend: BackendFixture) -> AdmittedServer:
    return server.model_copy(update={"backend": backend})


def with_an_unknown_backend_provisioner(admission: NuisanceAdmission) -> NuisanceAdmission:
    backend = BackendFixture(provisioner="ghost", images=["fake/backend:1.0"], network="fake-net")
    return edits.with_the_server(admission, lambda server: with_a_backend(server, backend))


def with_a_backend_fixture_differing_from_its_provisioner(
    admission: NuisanceAdmission,
) -> NuisanceAdmission:
    backend = BackendFixture(provisioner="fake", images=["fake/backend:2.0"], network="fake-net")
    return edits.with_the_server(admission, lambda server: with_a_backend(server, backend))


def with_a_networked_host_and_no_backend(admission: NuisanceAdmission) -> NuisanceAdmission:
    host = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=True)
    return edits.with_the_server(admission, lambda server: with_host(server, host))


def with_host(server: AdmittedServer, host: PlantingHost) -> AdmittedServer:
    return server.model_copy(update={"host": host})


def with_a_trust_setting_and_no_stand_in(admission: NuisanceAdmission) -> NuisanceAdmission:
    names = PublicNames(trust=("NODE_EXTRA_CA_CERTS",))
    host = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=False, public_names=names)
    return edits.with_the_server(admission, lambda server: with_host(server, host))


def with_every_flaw_needing_the_fixture(admission: NuisanceAdmission) -> NuisanceAdmission:
    def changed(server: AdmittedServer) -> AdmittedServer:
        flaws = [flaw.model_copy(update={"backend_need": "fixture"}) for flaw in server.flaws]
        return server.model_copy(update={"flaws": flaws})

    return edits.with_the_server(admission, changed)


def with_a_stale_grammar_fingerprint(admission: NuisanceAdmission) -> NuisanceAdmission:
    return admission.model_copy(update={"grammar_fingerprint": "stale"})


def with_an_unsettled_disagreement(admission: NuisanceAdmission) -> NuisanceAdmission:
    disagreement = FieldAgreement(flaw=None, field="runs_under_docker", agreed=False)
    return edits.with_the_server(
        admission,
        lambda server: server.model_copy(update={"agreement": [*server.agreement, disagreement]}),
    )


def with_a_flaw_of_another_server(admission: NuisanceAdmission) -> NuisanceAdmission:
    foreign = a_flaw_record("CVE-2099-9999", None, None)
    return edits.with_the_server(
        admission, lambda server: server.model_copy(update={"flaws": [*server.flaws, foreign]})
    )


def with_no_counted_tool(admission: NuisanceAdmission) -> NuisanceAdmission:
    return edits.with_the_server(
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

    return edits.with_the_server(admission, changed)


def with_a_server_patched_surfaces_set_on_the_servers_own_version(
    admission: NuisanceAdmission,
) -> NuisanceAdmission:
    def changed(flaw: FlawRecord) -> FlawRecord:
        check = flaw.fix_check.model_copy(update={"server_patched_surfaces": False})
        return flaw.model_copy(update={"fix_check": check})

    return edits.with_the_server(
        admission, lambda server: edits.with_the_first_flaw(server, changed)
    )


def with_an_acceptance_service(admission: NuisanceAdmission) -> NuisanceAdmission:
    return edits.with_the_server(
        admission, lambda server: server.model_copy(update={"service": "filesystem-patched"})
    )


def with_an_inconsistent_tool_record(admission: NuisanceAdmission) -> NuisanceAdmission:
    def changed(flaw: FlawRecord) -> FlawRecord:
        return flaw.model_copy(
            update={
                "tools": [a_tool("read_file", "write_file", "unchanged")],
                "benign_calls": [a_benign_call("write_file")],
            }
        )

    return edits.with_the_server(
        admission, lambda server: edits.with_the_first_flaw(server, changed)
    )


def with_a_counted_tool_missing_its_benign_call(admission: NuisanceAdmission) -> NuisanceAdmission:
    return edits.with_the_server(
        admission,
        lambda server: edits.with_the_first_flaw(
            server, lambda flaw: flaw.model_copy(update={"benign_calls": []})
        ),
    )


def with_the_second_flaw_settled_here(admission: NuisanceAdmission) -> NuisanceAdmission:
    settlement = AdmissionSettlement(
        server_package=SERVER_PACKAGE,
        flaw=SECOND_FLAW,
        field="server_package",
        value=SERVER_PACKAGE,
        reason="the advisory names the same package under another spelling",
    )
    return edits.with_the_server(
        admission,
        lambda server: server.model_copy(update={"settlements": [*server.settlements, settlement]}),
    )
