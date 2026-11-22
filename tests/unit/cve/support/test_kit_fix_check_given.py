"""Crafted exchanges for the fix-check verdict, free of Docker and any launch.

The verdict is a pure function of the exchanges each version records, so these helpers build
`Exercised` values directly: an exploit that surfaces the witness nonce, one that stays clean,
and one that errors.
"""

from collections.abc import Sequence

from evals.cve.kit.client import KitResponse
from evals.cve.kit.fix_check import Exchange, Exercised
from evals.cve.planting import PlantedArgs, PlantingSpec, planted
from tests.fakes.planting_docker import FakePlantingDocker
from tests.unit.support.fix_check_fixtures import WITNESS_ID

NONCE = "MCPAUDIT-fixcheckwitnessnonce"


def exchanges_surfacing(nonce: str, tool: str = "read_file") -> list[Exchange]:
    return [(tool, {"path": "cat /tmp/witness"}, KitResponse(f"contents: {nonce}", is_error=False))]


def unaimed_exchanges_surfacing(nonce: str, tool: str = "read_file") -> list[Exchange]:
    return [(tool, {"path": "/tmp/witness"}, KitResponse(f"contents: {nonce}", is_error=False))]


def clean_exchanges(tool: str = "read_file") -> list[Exchange]:
    return [(tool, {"path": "cat /tmp/witness"}, KitResponse("permission denied", is_error=False))]


def errored_exchanges(tool: str = "list_dir") -> list[Exchange]:
    return [(tool, {"path": "/tmp"}, KitResponse("backend unavailable", is_error=True))]


def an_exercise(
    exploits: Sequence[list[Exchange]],
    benign: Sequence[Exchange] = (),
) -> Exercised:
    return Exercised(
        nonces={WITNESS_ID: NONCE},
        exploits=[list(exploit) for exploit in exploits],
        benign=list(benign),
    )


def launch_args(spec: PlantingSpec) -> PlantedArgs:
    with planted(spec, "image:tag", FakePlantingDocker()) as args:
        return args
