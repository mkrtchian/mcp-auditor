from evals.cve.places import Coordinates, Place, PlaceKind
from evals.cve.planting import (
    RANDOM_NONCES,
    PlantingHost,
    PlantingSpec,
    SymbolicUser,
    planting_spec,
)

_HOST = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=False)


def a_spec() -> PlantingSpec:
    return planting_spec((), _HOST, RANDOM_NONCES)


def a_spec_with_an_account() -> PlantingSpec:
    place = Place(
        id="account-1",
        family="fictional",
        reaches=frozenset({"command_execution"}),
        kind=PlaceKind.ACCOUNT,
        coordinates=Coordinates(PlaceKind.ACCOUNT),
    )
    return planting_spec((place,), _HOST, RANDOM_NONCES)


def options_running_as(*user_options: str) -> list[str]:
    return ["run", "-i", "--rm", "--cap-drop", "ALL", *user_options, "-e", "HOME=/tmp"]
