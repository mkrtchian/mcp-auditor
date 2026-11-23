import dataclasses
from typing import get_args

from pydantic import BaseModel

from evals.cve.nuisance.report import NuisanceReport, ServerRunLine
from evals.cve.nuisance.results import NuisanceHoldoutRunResult, NuisanceServerResult
from tests.unit.nuisance.support.nuisance_report_runs import a_run, a_server_result


def report_models() -> list[type[BaseModel]]:
    found: list[type[BaseModel]] = []
    _collect_models(NuisanceReport, found)
    return found


def _collect_models(annotation: object, found: list[type[BaseModel]]) -> None:
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        if annotation in found:
            return
        found.append(annotation)
        nested = [field.annotation for field in annotation.model_fields.values()]
    else:
        nested = get_args(annotation)
    for child in nested:
        _collect_models(child, found)


def a_clean_run_line(*, flagged: bool, incomplete: bool) -> ServerRunLine:
    return ServerRunLine(
        flagged=flagged,
        split_flagged=False,
        incomplete=incomplete,
        non_protocol_lines=0,
        lost_connection_responses=0,
        relaunches=0,
        unsent_calls=0,
        cut_responses=0,
        missed_call_causes=[],
    )


def a_run_with_incidents() -> NuisanceHoldoutRunResult:
    return a_run([with_incidents(a_server_result("A")), a_server_result("B")])


def with_incidents(server: NuisanceServerResult) -> NuisanceServerResult:
    lost, refused, clean = server.statuses
    return dataclasses.replace(
        server,
        statuses=(
            dataclasses.replace(
                lost,
                non_protocol_lines=2,
                lost_connection_responses=1,
                relaunches=1,
                unsent_calls=3,
                cut_responses=1,
            ),
            dataclasses.replace(
                refused,
                incomplete=True,
                missed_call_causes=["provider_refusal", "unreadable_answer"],
            ),
            clean,
        ),
    )


def a_run_with_a_server_only_relaunched() -> NuisanceHoldoutRunResult:
    server = a_server_result("A")
    relaunched = dataclasses.replace(server.statuses[0], relaunches=2)
    return a_run([dataclasses.replace(server, statuses=(relaunched, *server.statuses[1:]))])
