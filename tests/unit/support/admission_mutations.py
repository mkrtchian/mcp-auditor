"""The admission mutators several test files of the nuisance and cve areas read: each returns a
changed copy of an admission or of one of its servers."""

from collections.abc import Callable
from typing import Literal

import tests.unit.support.nuisance_admissions as admissions
from evals.cve.nuisance.admission.admission import (
    AdmissionSettlement,
    AdmittedServer,
    BackendFixture,
    FieldAgreement,
    FlawRecord,
    NuisanceAdmission,
)
from evals.cve.nuisance.backend_registry import BACKENDS
from evals.cve.nuisance.exits import RecordedExit
from evals.cve.planting_base import PlantingHost, PublicNames, SymbolicUser


def admitting(*servers: AdmittedServer) -> NuisanceAdmission:
    return admissions.an_admission().model_copy(update={"servers": list(servers)})


def with_a_registered_backend(admission: NuisanceAdmission) -> NuisanceAdmission:
    backend = BackendFixture(provisioner="fake", images=["fake/backend:1.0"], network="fake-net")
    return with_the_server(admission, lambda server: with_a_backend(server, backend))


def with_a_backend(server: AdmittedServer, backend: BackendFixture) -> AdmittedServer:
    return server.model_copy(update={"backend": backend})


def with_an_unknown_backend_provisioner(admission: NuisanceAdmission) -> NuisanceAdmission:
    backend = BackendFixture(provisioner="ghost", images=["fake/backend:1.0"], network="fake-net")
    return with_the_server(admission, lambda server: with_a_backend(server, backend))


def with_a_backend_fixture_differing_from_its_provisioner(
    admission: NuisanceAdmission,
) -> NuisanceAdmission:
    backend = BackendFixture(provisioner="fake", images=["fake/backend:2.0"], network="fake-net")
    return with_the_server(admission, lambda server: with_a_backend(server, backend))


def with_a_networked_host_and_no_backend(admission: NuisanceAdmission) -> NuisanceAdmission:
    host = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=True)
    return with_the_server(admission, lambda server: with_host(server, host))


def with_host(server: AdmittedServer, host: PlantingHost) -> AdmittedServer:
    return server.model_copy(update={"host": host})


def with_a_trust_setting_and_no_stand_in(admission: NuisanceAdmission) -> NuisanceAdmission:
    names = PublicNames(trust=("NODE_EXTRA_CA_CERTS",))
    host = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=False, public_names=names)
    return with_the_server(admission, lambda server: with_host(server, host))


def with_every_flaw_needing_the_fixture(admission: NuisanceAdmission) -> NuisanceAdmission:
    def changed(server: AdmittedServer) -> AdmittedServer:
        flaws = [flaw.model_copy(update={"backend_need": "fixture"}) for flaw in server.flaws]
        return server.model_copy(update={"flaws": flaws})

    return with_the_server(admission, changed)


def with_a_stale_grammar_fingerprint(admission: NuisanceAdmission) -> NuisanceAdmission:
    return admission.model_copy(update={"grammar_fingerprint": "stale"})


def with_an_unsettled_disagreement(admission: NuisanceAdmission) -> NuisanceAdmission:
    disagreement = FieldAgreement(flaw=None, field="runs_under_docker", agreed=False)
    return with_the_server(
        admission,
        lambda server: server.model_copy(update={"agreement": [*server.agreement, disagreement]}),
    )


def with_a_flaw_of_another_server(admission: NuisanceAdmission) -> NuisanceAdmission:
    foreign = admissions.a_flaw_record("CVE-2099-9999", None, None)
    return with_the_server(
        admission, lambda server: server.model_copy(update={"flaws": [*server.flaws, foreign]})
    )


def with_no_counted_tool(admission: NuisanceAdmission) -> NuisanceAdmission:
    return with_the_server(
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

    return with_the_server(admission, changed)


def with_a_server_patched_surfaces_set_on_the_servers_own_version(
    admission: NuisanceAdmission,
) -> NuisanceAdmission:
    def changed(flaw: FlawRecord) -> FlawRecord:
        check = flaw.fix_check.model_copy(update={"server_patched_surfaces": False})
        return flaw.model_copy(update={"fix_check": check})

    return with_the_server(admission, lambda server: with_the_first_flaw(server, changed))


def with_an_acceptance_service(admission: NuisanceAdmission) -> NuisanceAdmission:
    return with_the_server(
        admission, lambda server: server.model_copy(update={"service": "filesystem-patched"})
    )


def with_an_inconsistent_tool_record(admission: NuisanceAdmission) -> NuisanceAdmission:
    def changed(flaw: FlawRecord) -> FlawRecord:
        return flaw.model_copy(
            update={
                "tools": [admissions.a_tool("read_file", "write_file", "unchanged")],
                "benign_calls": [admissions.a_benign_call("write_file")],
            }
        )

    return with_the_server(admission, lambda server: with_the_first_flaw(server, changed))


def with_a_counted_tool_missing_its_benign_call(admission: NuisanceAdmission) -> NuisanceAdmission:
    return with_the_server(
        admission,
        lambda server: with_the_first_flaw(
            server, lambda flaw: flaw.model_copy(update={"benign_calls": []})
        ),
    )


def with_the_second_flaw_settled_here(admission: NuisanceAdmission) -> NuisanceAdmission:
    settlement = AdmissionSettlement(
        server_package=admissions.SERVER_PACKAGE,
        flaw=admissions.SECOND_FLAW,
        field="server_package",
        value=admissions.SERVER_PACKAGE,
        reason="the advisory names the same package under another spelling",
    )
    return with_the_server(
        admission,
        lambda server: server.model_copy(update={"settlements": [*server.settlements, settlement]}),
    )


def with_every_new_field_unrecorded(admission: NuisanceAdmission) -> NuisanceAdmission:
    def flaw_unrecorded(flaw: FlawRecord) -> FlawRecord:
        return flaw.model_copy(
            update={
                "tools": [
                    tool.model_copy(
                        update={"real_software": None, "declared_function_is_effect": None}
                    )
                    for tool in flaw.tools
                ],
                "benign_calls": [
                    call.model_copy(update={"expect": None, "before": None})
                    for call in flaw.benign_calls
                ],
                "fix_check": flaw.fix_check.model_copy(
                    update={"relies_on_relaying_stand_in": None}
                ),
            }
        )

    return with_the_server(
        admission,
        lambda server: server.model_copy(
            update={
                "flaws": [flaw_unrecorded(flaw) for flaw in server.flaws],
                "stand_ins": None,
                "seeds": None,
                "software_releases": None,
            }
        ),
    )


def recording(admission: NuisanceAdmission, *exits: RecordedExit) -> NuisanceAdmission:
    return admission.model_copy(update={"exits": list(exits)})


def a_server_with_a_holdout_calibration_copy_at(
    fingerprint: str | None,
    source: Literal["fix_check", "detection_holdout_calibration"] = "detection_holdout_calibration",
) -> AdmittedServer:
    """The admitted server whose first flaw record carries `fingerprint` under `source`."""

    def copied(flaw: FlawRecord) -> FlawRecord:
        check = flaw.fix_check.model_copy(
            update={"source": source, "holdout_fingerprint": fingerprint}
        )
        return flaw.model_copy(update={"fix_check": check})

    return with_the_first_flaw(admissions.an_admitted_server(), copied)


def with_the_server(
    admission: NuisanceAdmission, change: Callable[[AdmittedServer], AdmittedServer]
) -> NuisanceAdmission:
    """The admission with its first server changed and every other server dropped."""
    return admission.model_copy(update={"servers": [change(admission.servers[0])]})


def with_the_first_benign_call(server: AdmittedServer, **update: object) -> AdmittedServer:
    def changed(flaw: FlawRecord) -> FlawRecord:
        first, *rest = flaw.benign_calls
        return flaw.model_copy(update={"benign_calls": [first.model_copy(update=update), *rest]})

    return with_the_first_flaw(server, changed)


def with_the_first_flaw(
    server: AdmittedServer, change: Callable[[FlawRecord], FlawRecord]
) -> AdmittedServer:
    first, *rest = server.flaws
    return server.model_copy(update={"flaws": [change(first), *rest]})


def on_the_ckan_backend(server: AdmittedServer) -> AdmittedServer:
    return with_the_registered_backend(server, "ckan")


def with_the_registered_backend(server: AdmittedServer, key: str) -> AdmittedServer:
    registered = BACKENDS[key]
    backend = BackendFixture(
        provisioner=key, images=list(registered.images), network=registered.network
    )
    return server.model_copy(update={"backend": backend})


def without_stdio(admission: NuisanceAdmission, package: str) -> NuisanceAdmission:
    servers = [
        server.model_copy(update={"runs_over_stdio": False})
        if server.server_package == package
        else server
        for server in admission.servers
    ]
    return admission.model_copy(update={"servers": servers})
