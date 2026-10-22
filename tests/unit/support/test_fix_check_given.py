"""Crafted exchanges and targets for the fix-check verdict, free of Docker and any launch.

The verdict is a pure function of the exchanges each version records, so these helpers build
`Exercised` values directly: an exploit that surfaces the witness nonce, one that stays clean,
one that errors, and a `FixCheckTarget` whose builder is never entered in a unit test.
"""

import re
from collections.abc import Sequence
from contextlib import AbstractContextManager

from evals.cve_grammar import MechanismClass
from evals.cve_places import Coordinates, Place, PlantKind
from evals.cve_planting import PlantingHost, PlantingSpec, SymbolicUser
from evals.holdout_kit.fix_check import Exchange, Exercised, FixCheckTarget
from evals.holdout_kit.kit_client import KitResponse
from evals.holdout_kit.kit_launch import Launch, LaunchShape

WITNESS_ID = "witness"
NONCE = "MCPAUDIT-fixcheckwitnessnonce"
AIM = re.compile(r"cat ")


def a_witness() -> Place:
    return Place(
        id=WITNESS_ID,
        family="fix_check",
        reachable_by=frozenset({"arbitrary_read"}),
        kind=PlantKind.FILE,
        coordinates=Coordinates(PlantKind.FILE, path="/tmp/witness"),
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
    nonces: dict[str, str] | None = None,
) -> Exercised:
    return Exercised(
        nonces={WITNESS_ID: NONCE} if nonces is None else nonces,
        exploits=[list(exploit) for exploit in exploits],
        benign=list(benign),
    )


def a_fix_check_target(
    mechanism: MechanismClass | None = MechanismClass.READ_OUTSIDE_SCOPE,
    aim: re.Pattern[str] = AIM,
    server_patched_service: str | None = None,
) -> FixCheckTarget:
    return FixCheckTarget(
        flaw="CVE-2025-0001",
        mechanism=mechanism,
        aim=aim,
        witness=a_witness(),
        planting_host=PlantingHost(SymbolicUser.UNPRIVILEGED, "/srv", has_network=False),
        builder=_unused_builder,
        exploits=(),
        benign_calls=(),
        vulnerable_service="vuln",
        patched_service="patched",
        server_patched_service=server_patched_service,
    )


def _unused_builder(
    image: str, spec: PlantingSpec, shape: LaunchShape
) -> AbstractContextManager[Launch]:
    raise RuntimeError("the fix-check unit tests never launch a container")
