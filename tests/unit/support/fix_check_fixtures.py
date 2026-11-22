import re
from contextlib import AbstractContextManager

from evals.cve.grammar import FlawClass
from evals.cve.kit.fix_check import FixCheckFixture
from evals.cve.kit.launch import Launch, LaunchShape
from evals.cve.places import Coordinates, Place, PlaceKind
from evals.cve.planting import PlantingHost, PlantingSpec, SymbolicUser

WITNESS_ID = "witness"
AIM = re.compile(r"cat ")


def a_fix_check_fixture(
    server_patched_service: str | None = None,
    working_directory: str = "/srv",
    witness_path: str = "/tmp/witness",
) -> FixCheckFixture:
    return FixCheckFixture(
        flaw="CVE-2025-0001",
        effect_class=FlawClass.READ_OUTSIDE_SCOPE,
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


def a_witness(path: str = "/tmp/witness") -> Place:
    return Place(
        id=WITNESS_ID,
        family="fix_check",
        reaches=frozenset({"arbitrary_read"}),
        kind=PlaceKind.FILE,
        coordinates=Coordinates(PlaceKind.FILE, path=path),
    )


def _unused_builder(
    image: str, spec: PlantingSpec, shape: LaunchShape
) -> AbstractContextManager[Launch]:
    raise RuntimeError("the fix-check unit tests never launch a container")
