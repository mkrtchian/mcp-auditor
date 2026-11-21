"""The partition of the reached servers by the rule's exits: audited, out, or pending their
admission. Pure, no Docker, no LLM."""

import tests.unit.nuisance.admission.support.test_nuisance_admission_given as admission
import tests.unit.nuisance.admission.support.test_nuisance_admission_walk_given as admission_walk
import tests.unit.nuisance.support.test_nuisance_run_given as given
from evals.cve.nuisance.admission.admission import AdmittedServer, NuisanceAdmission
from evals.cve.nuisance.admission.walk import NuisanceServer, ReachedServers, ServerMark
from evals.cve.nuisance.exits import ExitReason
from evals.cve.nuisance.holdout_servers import run_population
from evals.cve.nuisance.results import ServerExit


def test_each_standing_exit_keeps_its_server_outside_the_figure():
    walked = [
        _walked("npm:excluded", ServerMark.EXCLUDED),
        _walked("npm:accepted", ServerMark.ACCEPTANCE_TARGET_SERVER),
    ]
    admitted = _admitting(
        _admitted("npm:no-stdio", runs_over_stdio=False),
        _admitted("npm:no-docker", runs_under_docker=False),
    )

    population = run_population(ReachedServers(walked, ()), admitted, set())

    assert population.audited == []
    assert sorted(population.exits, key=lambda row: row.server_package) == [
        ServerExit("npm:accepted", ExitReason.ACCEPTANCE_TARGET_SERVER),
        ServerExit("npm:excluded", ExitReason.EXCLUDED_SERVER),
        ServerExit("npm:no-docker", ExitReason.NOT_UNDER_DOCKER),
        ServerExit("npm:no-stdio", ExitReason.NOT_OVER_STDIO),
    ]


def test_an_unmarked_stdio_server_under_docker_is_audited():
    kept = _admitted("npm:kept")

    population = run_population(_listing(_walked("npm:kept", None)), _admitting(kept), set())

    assert population.audited == [kept]
    assert population.exits == []


def test_an_admitted_server_marked_by_the_walk_is_outside_the_figure_once():
    marked = _admitted("npm:marked", runs_over_stdio=False)

    population = run_population(
        _listing(_walked("npm:marked", ServerMark.EXCLUDED)), _admitting(marked), set()
    )

    assert population.audited == []
    assert population.exits == [ServerExit("npm:marked", ExitReason.EXCLUDED_SERVER)]


def test_an_admitted_acceptance_server_the_walk_did_not_mark_is_never_audited():
    accepted = _admitted("npm:accepted")

    population = run_population(_listing(), _admitting(accepted), {"npm:accepted"})

    assert population.audited == []
    assert population.exits == [ServerExit("npm:accepted", ExitReason.ACCEPTANCE_TARGET_SERVER)]


def test_an_acceptance_server_also_marked_by_the_walk_is_outside_the_figure_once():
    accepted = _admitted("npm:accepted")
    walked = [_walked("npm:accepted", ServerMark.ACCEPTANCE_TARGET_SERVER)]

    population = run_population(ReachedServers(walked, ()), _admitting(accepted), {"npm:accepted"})

    assert population.audited == []
    assert population.exits == [ServerExit("npm:accepted", ExitReason.ACCEPTANCE_TARGET_SERVER)]


def test_a_recorded_exit_keeps_its_server_outside_the_figure():
    kept = _admitted("npm:kept")
    admitted = admission_walk.recording(
        _admitting(kept), admission_walk.a_recorded_exit("npm:out", ExitReason.NO_COUNTED_FLAW)
    )
    listing = _listing(_walked("npm:kept", None), _walked("npm:out", None))

    population = run_population(listing, admitted, set())

    assert population.audited == [kept]
    assert population.exits == [ServerExit("npm:out", ExitReason.NO_COUNTED_FLAW)]
    assert population.pending == []


def test_a_server_reached_with_no_flaw_that_may_count_has_no_counted_flaw():
    population = run_population(ReachedServers([], ["npm:left"]), _admitting(), set())

    assert population.exits == [ServerExit("npm:left", ExitReason.NO_COUNTED_FLAW)]
    assert population.audited == []
    assert population.pending == []


def test_only_a_listed_server_neither_admitted_marked_nor_recorded_out_is_pending():
    listing = _listing(
        _walked("npm:admitted", None),
        _walked("npm:pending", None),
        _walked("npm:recorded", None),
        _walked("npm:marked", ServerMark.EXCLUDED),
    )
    admitted = admission_walk.recording(
        _admitting(_admitted("npm:admitted")), admission_walk.a_recorded_exit("npm:recorded")
    )

    population = run_population(listing, admitted, set())

    assert population.pending == ["npm:pending"]


def _listing(*walked: NuisanceServer) -> ReachedServers:
    return ReachedServers(list(walked), ())


def _walked(package: str, mark: ServerMark | None) -> NuisanceServer:
    return NuisanceServer(
        server_package=package,
        reaching_flaw=given.FIRST_FLAW,
        reaching_position=1,
        in_addition=False,
        flaws=(given.FIRST_FLAW,),
        candidate_counted_flaws=(given.FIRST_FLAW,),
        mark=mark,
    )


def _admitted(package: str, **update: bool) -> AdmittedServer:
    return given.a_server(package).model_copy(update=update)


def _admitting(*servers: AdmittedServer) -> NuisanceAdmission:
    return admission.an_admission().model_copy(update={"servers": list(servers)})
