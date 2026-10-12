"""Fictional places, planting hosts and a deterministic nonce source for the survey tests.
No real coordinate is read here: every place is invented."""

from evals.cve_places import Coordinates, Place, PlantKind
from evals.cve_planting import PlantingHost, SymbolicUser

READ = frozenset({"arbitrary_read"})

NO_NETWORK = PlantingHost(SymbolicUser.UNPRIVILEGED, "/work", has_network=False)
WITH_NETWORK = PlantingHost(SymbolicUser.UNPRIVILEGED, "/work", has_network=True)
HOST_USER = PlantingHost(SymbolicUser.HOST, "/work", has_network=False)


class FakeNonces:
    """Deterministic tokens, inexhaustible so survey_groups may probe a group many times."""

    def __init__(self) -> None:
        self._count = 0

    def token(self) -> str:
        self._count += 1
        return f"MCPAUDIT-{self._count:032x}"

    def account_name(self) -> str:
        self._count += 1
        return f"mcpaudit-{self._count:022x}"


def a_file_place(place_id: str, path: str, reaches: frozenset[str] = READ) -> Place:
    return Place(
        place_id, "fictional", reaches, PlantKind.FILE, Coordinates(PlantKind.FILE, path=path)
    )


def an_env_place(place_id: str, reaches: frozenset[str] = READ) -> Place:
    return Place(
        place_id, "fictional", reaches, PlantKind.ENV, Coordinates(PlantKind.ENV, name="FLAG")
    )


def an_account_place(place_id: str, reaches: frozenset[str] = READ) -> Place:
    return Place(place_id, "fictional", reaches, PlantKind.ACCOUNT, Coordinates(PlantKind.ACCOUNT))


def a_hostname_place(place_id: str, reaches: frozenset[str] = READ) -> Place:
    return Place(
        place_id, "fictional", reaches, PlantKind.HOSTNAME, Coordinates(PlantKind.HOSTNAME)
    )


def an_endpoint_place(
    place_id: str, host: str, path: str = "/x", reaches: frozenset[str] = READ
) -> Place:
    return Place(
        place_id,
        "fictional",
        reaches,
        PlantKind.HTTP_ENDPOINT,
        Coordinates(PlantKind.HTTP_ENDPOINT, host=host, path=path),
    )


def an_unplaceable_place(place_id: str, reaches: frozenset[str] = READ) -> Place:
    return Place(
        place_id, "fictional", reaches, PlantKind.UNPLACEABLE, Coordinates(PlantKind.UNPLACEABLE)
    )
