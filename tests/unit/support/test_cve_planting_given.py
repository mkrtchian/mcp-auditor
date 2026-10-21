"""Fictional places and the two planting fakes. No real coordinate appears here: every path,
host and name is invented, and the IP literals are drawn from the documentation ranges, so
nothing can be mistaken for the imported data.
"""

from collections.abc import Sequence

from evals.cve_places import Coordinates, LayoutAnchor, Place, PlantKind
from evals.cve_planting import (
    NonceSource,
    PlantingHost,
    PlantingSpec,
    SymbolicUser,
    planting_spec,
)
from tests.fakes.planting_docker import FakePlantingDocker as FakePlantingDocker
from tests.fakes.planting_docker import HostFile as HostFile


def spec_of(
    places: list[Place], host: PlantingHost | None = None, nonces: NonceSource | None = None
) -> PlantingSpec:
    return planting_spec(places, host or unprivileged_host(), nonces or FakeNonces())


def unprivileged_host(
    *, has_network: bool = False, working_directory: str = "/srv/fictional"
) -> PlantingHost:
    return PlantingHost(SymbolicUser.UNPRIVILEGED, working_directory, has_network)


def host_user_host(*, has_network: bool = False, working_directory: str = "/work") -> PlantingHost:
    return PlantingHost(SymbolicUser.HOST, working_directory, has_network)


def file_place(
    entry_id: str = "file-1",
    *,
    path: str = "/etc/fictional/secret",
    paths: Sequence[str] | None = None,
) -> Place:
    coordinates = Coordinates(
        PlantKind.FILE,
        path=None if paths is not None else path,
        paths=tuple(paths) if paths is not None else None,
    )
    return _place(entry_id, PlantKind.FILE, coordinates)


def env_place(entry_id: str = "env-1", *, name: str = "FICTIONAL_TOKEN") -> Place:
    return _place(entry_id, PlantKind.ENV, Coordinates(PlantKind.ENV, name=name))


def account_place(entry_id: str = "account-1") -> Place:
    return _place(entry_id, PlantKind.ACCOUNT, Coordinates(PlantKind.ACCOUNT))


def hostname_place(entry_id: str = "hostname-1") -> Place:
    return _place(entry_id, PlantKind.HOSTNAME, Coordinates(PlantKind.HOSTNAME))


def endpoint_place(
    entry_id: str = "endpoint-1",
    *,
    host: str = "fictional-service",
    path: str = "/fictional/secret",
) -> Place:
    return _place(
        entry_id,
        PlantKind.HTTP_ENDPOINT,
        Coordinates(PlantKind.HTTP_ENDPOINT, host=host, path=path),
    )


def unplaceable_place(entry_id: str = "unplaceable-1") -> Place:
    return _place(entry_id, PlantKind.UNPLACEABLE, Coordinates(PlantKind.UNPLACEABLE))


def git_remote_url_place(entry_id: str = "bare-remote-url-fic") -> Place:
    return _place(
        entry_id,
        PlantKind.GIT_REMOTE_URL,
        Coordinates(PlantKind.GIT_REMOTE_URL, anchor=LayoutAnchor.PROJECT_BARE, relpath="config"),
    )


def git_history_place(entry_id: str = "bare-history-fic") -> Place:
    return _place(
        entry_id,
        PlantKind.GIT_HISTORY,
        Coordinates(PlantKind.GIT_HISTORY, anchor=LayoutAnchor.PROJECT_BARE, relpath=".env"),
    )


def dotenv_place(entry_id: str = "ws-dotenv-fic") -> Place:
    return _place(
        entry_id,
        PlantKind.DOTENV,
        Coordinates(PlantKind.DOTENV, anchor=LayoutAnchor.WORKSPACE, relpath=".env"),
    )


def _place(entry_id: str, kind: PlantKind, coordinates: Coordinates) -> Place:
    return Place(
        id=entry_id,
        family="fictional-family",
        reachable_by=frozenset({"arbitrary_read"}),
        kind=kind,
        coordinates=coordinates,
    )


class FakeNonces:
    """A deterministic source: each draw is distinct, so two locations never share a value."""

    def __init__(self) -> None:
        self._tokens = 0
        self._accounts = 0

    def token(self) -> str:
        self._tokens += 1
        return f"nonce-{self._tokens}"

    def account_name(self) -> str:
        self._accounts += 1
        return f"acct-{self._accounts}"


class FixedTokenNonces:
    """Yields one caller-chosen token, for the url-safety refusal of a git-remote-url place."""

    def __init__(self, token: str) -> None:
        self._token = token

    def token(self) -> str:
        return self._token

    def account_name(self) -> str:
        return "acct"


def only(registry: dict[str, list[str]]) -> str:
    assert len(registry) == 1
    return next(iter(registry))


def only_list(items: list[list[str]]) -> list[str]:
    assert len(items) == 1
    return items[0]


def following(args: list[str] | tuple[str, ...], flag: str, *, prefix: str | None = None) -> str:
    args = list(args)
    if prefix is not None:
        return next(value for value in args if value.startswith(prefix))
    return args[args.index(flag) + 1]
