import tests.unit.support.nuisance_holdout_runs as holdout_runs
from evals.cve.nuisance.admission.admission import AdmittedServer
from evals.cve.nuisance.admission.walk import NuisanceServer, ReachedServers
from evals.cve.nuisance.exits import ExitReason


def a_listing(*walked: NuisanceServer) -> ReachedServers:
    return ReachedServers(list(walked), ())


def walked(package: str, mark: ExitReason | None) -> NuisanceServer:
    return NuisanceServer(
        server_package=package,
        reaching_flaw=holdout_runs.FIRST_FLAW,
        reaching_position=1,
        in_addition=False,
        flaws=(holdout_runs.FIRST_FLAW,),
        candidate_counted_flaws=(holdout_runs.FIRST_FLAW,),
        mark=mark,
    )


def admitted(package: str, **update: bool) -> AdmittedServer:
    return holdout_runs.a_server(package).model_copy(update=update)
