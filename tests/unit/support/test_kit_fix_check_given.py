"""Crafted exchanges and targets for the fix-check verdict, free of Docker and any launch.

The verdict is a pure function of the exchanges each version records, so these helpers build
`Exercised` values directly: an exploit that surfaces the witness nonce, one that stays clean,
one that errors, and a `FixCheckTarget` whose builder is never entered in a unit test.
"""

import re
from collections.abc import Sequence
from contextlib import AbstractContextManager

from evals.cve.kit.client import KitResponse
from evals.cve.kit.fix_check import Exchange, Exercised, FixCheckTarget
from evals.cve.kit.launch import Launch, LaunchShape
from evals.cve_grammar import MechanismClass
from evals.cve_places import Coordinates, Place, PlantKind
from evals.cve_planting import PlantedArgs, PlantingHost, PlantingSpec, SymbolicUser, planted
from tests.fakes.planting_docker import FakePlantingDocker

WITNESS_ID = "witness"
NONCE = "MCPAUDIT-fixcheckwitnessnonce"
AIM = re.compile(r"cat ")


def a_witness(path: str = "/tmp/witness") -> Place:
    return Place(
        id=WITNESS_ID,
        family="fix_check",
        reachable_by=frozenset({"arbitrary_read"}),
        kind=PlantKind.FILE,
        coordinates=Coordinates(PlantKind.FILE, path=path),
    )


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


def a_fix_check_target(
    server_patched_service: str | None = None,
    working_directory: str = "/srv",
    witness_path: str = "/tmp/witness",
) -> FixCheckTarget:
    return FixCheckTarget(
        flaw="CVE-2025-0001",
        mechanism=MechanismClass.READ_OUTSIDE_SCOPE,
        aim=AIM,
        witness=a_witness(witness_path),
        planting_host=PlantingHost(SymbolicUser.UNPRIVILEGED, working_directory, has_network=False),
        builder=_unused_builder,
        exploits=(),
        benign_calls=(),
        vulnerable_service="vuln",
        patched_service="patched",
        server_patched_service=server_patched_service,
    )


def launch_args(spec: PlantingSpec) -> PlantedArgs:
    with planted(spec, "image:tag", FakePlantingDocker()) as args:
        return args


def _unused_builder(
    image: str, spec: PlantingSpec, shape: LaunchShape
) -> AbstractContextManager[Launch]:
    raise RuntimeError("the fix-check unit tests never launch a container")
