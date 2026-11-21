import tests.unit.nuisance.support.test_nuisance_run_given as run_given
from evals.cve.nuisance.admission.admission import AdmittedServer
from evals.cve.nuisance.admission.walk import NuisanceServer, ReachedServers, ServerMark


def a_listing(*walked: NuisanceServer) -> ReachedServers:
    return ReachedServers(list(walked), ())


def walked(package: str, mark: ServerMark | None) -> NuisanceServer:
    return NuisanceServer(
        server_package=package,
        reaching_flaw=run_given.FIRST_FLAW,
        reaching_position=1,
        in_addition=False,
        flaws=(run_given.FIRST_FLAW,),
        candidate_counted_flaws=(run_given.FIRST_FLAW,),
        mark=mark,
    )


def admitted(package: str, **update: bool) -> AdmittedServer:
    return run_given.a_server(package).model_copy(update=update)
