"""The admission mutators several test files of the nuisance and cve areas read: each returns a
changed copy of an admission or of one of its servers."""

from collections.abc import Callable
from typing import Literal

import tests.unit.support.nuisance_admissions as admissions
from evals.cve.nuisance.admission.admission import (
    AdmittedServer,
    BackendFixture,
    FlawRecord,
    NuisanceAdmission,
)
from evals.cve.nuisance.backend_registry import BACKENDS
from evals.cve.nuisance.exits import RecordedExit
from evals.cve.planting_base import PlantingHost


def admitting(*servers: AdmittedServer) -> NuisanceAdmission:
    return admissions.an_admission().model_copy(update={"servers": list(servers)})


def with_a_backend(server: AdmittedServer, backend: BackendFixture) -> AdmittedServer:
    return server.model_copy(update={"backend": backend})


def with_host(server: AdmittedServer, host: PlantingHost) -> AdmittedServer:
    return server.model_copy(update={"host": host})


def with_a_stale_grammar_fingerprint(admission: NuisanceAdmission) -> NuisanceAdmission:
    return admission.model_copy(update={"grammar_fingerprint": "stale"})


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
