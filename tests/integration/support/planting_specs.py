from evals.cve.places import Coordinates, Place, PlaceKind
from evals.cve.planting import (
    RANDOM_NONCES,
    PlantingHost,
    PlantingSpec,
    SymbolicUser,
    planting_spec,
)

IP_LITERAL = "198.51.100.5"  # RFC 5737 documentation range: routes nowhere


def spec_of(
    host: str, path: str, *, has_network: bool = False, file_at: str | None = None
) -> PlantingSpec:
    places: list[Place] = []
    if file_at is not None:
        places.append(_place("file-1", Coordinates(PlaceKind.FILE, path=file_at)))
    places.append(_place("endpoint-1", Coordinates(PlaceKind.HTTP_ENDPOINT, host=host, path=path)))
    planting_host = PlantingHost(SymbolicUser.UNPRIVILEGED, "/srv/fictional", has_network)
    return planting_spec(places, planting_host, RANDOM_NONCES)


def a_work_spec(*, with_an_account: bool) -> PlantingSpec:
    places = [_place("account-1", Coordinates(PlaceKind.ACCOUNT))] if with_an_account else []
    planting_host = PlantingHost(SymbolicUser.UNPRIVILEGED, "/work", False)
    return planting_spec(places, planting_host, RANDOM_NONCES)


def _place(place_id: str, coordinates: Coordinates) -> Place:
    return Place(
        id=place_id,
        family="fictional-family",
        reaches=frozenset({"arbitrary_read"}),
        kind=coordinates.kind,
        coordinates=coordinates,
    )
