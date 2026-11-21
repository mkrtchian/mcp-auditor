"""The partition of the reached servers by the rule's exits: audited, out, or pending their
admission. Pure, no Docker, no LLM."""

import tests.unit.nuisance.admission.support.test_nuisance_admission_walk_given as admission_walk
import tests.unit.nuisance.support.test_nuisance_holdout_servers_given as given
from evals.cve.nuisance.admission.walk import ReachedServers, ServerMark
from evals.cve.nuisance.exits import ExitReason
from evals.cve.nuisance.holdout_servers import run_population
from evals.cve.nuisance.results import ServerExit
from tests.unit.support.admission_mutations import admitting


def test_each_standing_exit_keeps_its_server_among_the_exits():
    walked = [
        given.walked("npm:excluded", ServerMark.EXCLUDED),
        given.walked("npm:accepted", ServerMark.ACCEPTANCE_TARGET_SERVER),
    ]
    admitted = admitting(
        given.admitted("npm:no-stdio", runs_over_stdio=False),
        given.admitted("npm:no-docker", runs_under_docker=False),
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
    kept = given.admitted("npm:kept")

    population = run_population(
        given.a_listing(given.walked("npm:kept", None)), admitting(kept), set()
    )

    assert population.audited == [kept]
    assert population.exits == []


def test_an_admitted_server_marked_by_the_walk_is_among_the_exits_once():
    marked = given.admitted("npm:marked", runs_over_stdio=False)

    population = run_population(
        given.a_listing(given.walked("npm:marked", ServerMark.EXCLUDED)), admitting(marked), set()
    )

    assert population.audited == []
    assert population.exits == [ServerExit("npm:marked", ExitReason.EXCLUDED_SERVER)]


def test_an_admitted_nuisance_acceptance_server_the_walk_did_not_mark_is_never_audited():
    accepted = given.admitted("npm:accepted")

    population = run_population(given.a_listing(), admitting(accepted), {"npm:accepted"})

    assert population.audited == []
    assert population.exits == [ServerExit("npm:accepted", ExitReason.ACCEPTANCE_TARGET_SERVER)]


def test_a_nuisance_acceptance_server_also_marked_by_the_walk_is_among_the_exits_once():
    accepted = given.admitted("npm:accepted")
    walked = [given.walked("npm:accepted", ServerMark.ACCEPTANCE_TARGET_SERVER)]

    population = run_population(ReachedServers(walked, ()), admitting(accepted), {"npm:accepted"})

    assert population.audited == []
    assert population.exits == [ServerExit("npm:accepted", ExitReason.ACCEPTANCE_TARGET_SERVER)]


def test_a_recorded_exit_keeps_its_server_among_the_exits():
    kept = given.admitted("npm:kept")
    admitted = admission_walk.recording(
        admitting(kept), admission_walk.a_recorded_exit("npm:out", ExitReason.NO_COUNTED_FLAW)
    )
    listing = given.a_listing(given.walked("npm:kept", None), given.walked("npm:out", None))

    population = run_population(listing, admitted, set())

    assert population.audited == [kept]
    assert population.exits == [ServerExit("npm:out", ExitReason.NO_COUNTED_FLAW)]
    assert population.pending == []


def test_a_server_reached_with_no_flaw_that_may_count_has_no_counted_flaw():
    population = run_population(ReachedServers([], ["npm:left"]), admitting(), set())

    assert population.exits == [ServerExit("npm:left", ExitReason.NO_COUNTED_FLAW)]
    assert population.audited == []
    assert population.pending == []


def test_only_a_listed_server_neither_admitted_marked_nor_recorded_out_is_pending():
    listing = given.a_listing(
        given.walked("npm:admitted", None),
        given.walked("npm:pending", None),
        given.walked("npm:recorded", None),
        given.walked("npm:marked", ServerMark.EXCLUDED),
    )
    admitted = admission_walk.recording(
        admitting(given.admitted("npm:admitted")), admission_walk.a_recorded_exit("npm:recorded")
    )

    population = run_population(listing, admitted, set())

    assert population.pending == ["npm:pending"]
