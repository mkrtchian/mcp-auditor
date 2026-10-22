"""The partition of the admitted servers by the rule's standing exits. Pure, no Docker, no LLM."""

import tests.unit.support.test_nuisance_admission_given as admission
import tests.unit.support.test_nuisance_run_given as given
from evals.nuisance_admission import AdmittedServer, NuisanceAdmission
from evals.nuisance_population import run_population
from evals.nuisance_results import FigureExit
from evals.nuisance_walk import NuisanceServer, ServerMark


def test_each_standing_exit_keeps_its_server_outside_the_figure():
    walked = [
        _walked("npm:excluded", ServerMark.EXCLUDED),
        _walked("npm:accepted", ServerMark.ACCEPTANCE),
    ]
    admitted = _admitting(
        _admitted("npm:no-stdio", runs_over_stdio=False),
        _admitted("npm:no-container", runs_in_container=False),
    )

    population = run_population(walked, admitted, set())

    assert population.audited == []
    assert sorted(population.outside_figure, key=lambda row: row.server_package) == [
        FigureExit("npm:accepted", "an acceptance server"),
        FigureExit("npm:excluded", "an excluded server"),
        FigureExit("npm:no-container", "its patched version does not run in a container"),
        FigureExit("npm:no-stdio", "does not run over stdio"),
    ]


def test_an_unmarked_stdio_containerised_server_is_audited():
    kept = _admitted("npm:kept")

    population = run_population([_walked("npm:kept", None)], _admitting(kept), set())

    assert population.audited == [kept]
    assert population.outside_figure == []


def test_an_admitted_server_marked_by_the_walk_is_outside_the_figure_once():
    marked = _admitted("npm:marked", runs_over_stdio=False)

    population = run_population(
        [_walked("npm:marked", ServerMark.EXCLUDED)], _admitting(marked), set()
    )

    assert population.audited == []
    assert population.outside_figure == [FigureExit("npm:marked", "an excluded server")]


def test_an_admitted_acceptance_server_the_walk_did_not_mark_is_never_audited():
    accepted = _admitted("npm:accepted")

    population = run_population([], _admitting(accepted), {"npm:accepted"})

    assert population.audited == []
    assert population.outside_figure == [FigureExit("npm:accepted", "an acceptance server")]


def test_an_acceptance_server_also_marked_by_the_walk_is_outside_the_figure_once():
    accepted = _admitted("npm:accepted")
    walked = [_walked("npm:accepted", ServerMark.ACCEPTANCE)]

    population = run_population(walked, _admitting(accepted), {"npm:accepted"})

    assert population.audited == []
    assert population.outside_figure == [FigureExit("npm:accepted", "an acceptance server")]


def _walked(package: str, mark: ServerMark | None) -> NuisanceServer:
    return NuisanceServer(package, given.FIRST_FLAW, (given.FIRST_FLAW,), (given.FIRST_FLAW,), mark)


def _admitted(package: str, **update: bool) -> AdmittedServer:
    return given.a_server(package).model_copy(update=update)


def _admitting(*servers: AdmittedServer) -> NuisanceAdmission:
    return admission.an_admission().model_copy(update={"servers": list(servers)})
