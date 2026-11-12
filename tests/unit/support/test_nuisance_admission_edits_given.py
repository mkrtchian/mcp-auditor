from collections.abc import Callable

from evals.cve.nuisance.admission import (
    AdmittedServer,
    BackendFixture,
    FlawRecord,
    NuisanceAdmission,
)
from evals.cve.nuisance.backend_registry import BACKENDS


def with_the_server(
    admission: NuisanceAdmission, change: Callable[[AdmittedServer], AdmittedServer]
) -> NuisanceAdmission:
    """The admission with its first server changed and every other server dropped."""
    return admission.model_copy(update={"servers": [change(admission.servers[0])]})


def with_the_first_flaw(
    server: AdmittedServer, change: Callable[[FlawRecord], FlawRecord]
) -> AdmittedServer:
    first, *rest = server.flaws
    return server.model_copy(update={"flaws": [change(first), *rest]})


def with_the_first_benign_call(server: AdmittedServer, **update: object) -> AdmittedServer:
    def changed(flaw: FlawRecord) -> FlawRecord:
        first, *rest = flaw.benign_calls
        return flaw.model_copy(update={"benign_calls": [first.model_copy(update=update), *rest]})

    return with_the_first_flaw(server, changed)


def with_the_registered_backend(server: AdmittedServer, key: str) -> AdmittedServer:
    registered = BACKENDS[key]
    backend = BackendFixture(provisioner=key, image=registered.image, network=registered.network)
    return server.model_copy(update={"backend": backend})


def on_the_ckan_backend(server: AdmittedServer) -> AdmittedServer:
    return with_the_registered_backend(server, "ckan")


def without_stdio(admission: NuisanceAdmission, package: str) -> NuisanceAdmission:
    servers = [
        server.model_copy(update={"runs_over_stdio": False})
        if server.server_package == package
        else server
        for server in admission.servers
    ]
    return admission.model_copy(update={"servers": servers})
