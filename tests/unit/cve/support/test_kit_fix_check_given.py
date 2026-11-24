"""Crafted exchanges for the fix-check result, free of Docker and any launch.

The result is a pure function of the exchanges each version records, so these helpers build
`Exercised` values directly: an exploit that surfaces the witness, one that stays clean, and one
that errors.
"""

from collections.abc import Sequence

from evals.cve.kit.client import KitResponse
from evals.cve.kit.fix_check import Exchange, Exercised
from evals.cve.planting import PlantedArgs, PlantingSpec, planted
from tests.fakes.planting_docker import FakePlantingDocker
from tests.unit.support.fix_check_fixtures import WITNESS_ID

WITNESS = "MCPAUDIT-fixcheckwitness"


def exchanges_surfacing(witness: str) -> list[Exchange]:
    response = KitResponse(f"contents: {witness}", is_error=False)
    return [("read_file", {"path": "cat /tmp/witness"}, response)]


def unaimed_exchanges_surfacing(witness: str) -> list[Exchange]:
    response = KitResponse(f"contents: {witness}", is_error=False)
    return [("read_file", {"path": "/tmp/witness"}, response)]


def clean_exchanges(tool: str = "read_file") -> list[Exchange]:
    return [(tool, {"path": "cat /tmp/witness"}, KitResponse("permission denied", is_error=False))]


def errored_exchanges() -> list[Exchange]:
    return [("list_dir", {"path": "/tmp"}, KitResponse("backend unavailable", is_error=True))]


def an_exercise(
    exploits: Sequence[list[Exchange]],
    benign: Sequence[Exchange] = (),
) -> Exercised:
    return Exercised(
        nonces={WITNESS_ID: WITNESS},
        exploits=[list(exploit) for exploit in exploits],
        benign=list(benign),
    )


def launch_args(spec: PlantingSpec) -> PlantedArgs:
    with planted(spec, "image:tag", FakePlantingDocker()) as args:
        return args
