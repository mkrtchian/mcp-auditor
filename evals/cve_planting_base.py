"""Planting vocabulary: the value objects, the ports and the container launch profile.

`PlantingSpec` is what `planting_spec` computes and `planted` carries out: container-side
intents only (a file and its content, an environment pair, an account entry, a hostname, a
sentinel serving a nonce), never a host path, a container or network name, or an argv.
`PlantedArgs` is the `docker run` arguments a planted launch takes. `PlantingDocker` and
`NonceSource` are the two injected ports; `RANDOM_NONCES` draws the production nonces.

`confinement_args` stays public so each builder carries the same container profile. The user
and network helpers stay public for `planted` to resolve the launch's host into arguments; a
builder no longer emits them itself, it takes them from the `PlantedArgs` planting yields.
"""

import logging
import os
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from evals.cve_places import Place

logger = logging.getLogger(__name__)

LABEL = "mcp-auditor-cve"
SENTINEL_SERVICE = "sentinel"  # the sentinel's compose service, image_tag(SENTINEL_SERVICE)
SENTINEL_IMAGE = "mcp-auditor-cve-sentinel:local"


class SymbolicUser(StrEnum):
    UNPRIVILEGED = "unprivileged"
    HOST = "host"


@dataclass(frozen=True)
class PlantingHost:
    user: SymbolicUser
    working_directory: str
    has_network: bool


class NonceSource(Protocol):
    def token(self) -> str: ...
    def account_name(self) -> str: ...


class _RandomNonces:
    def token(self) -> str:
        return f"MCPAUDIT-{secrets.token_hex(16)}"

    def account_name(self) -> str:
        return f"mcpaudit-{secrets.token_hex(11)}"


RANDOM_NONCES: NonceSource = _RandomNonces()


class PlantingFailed(Exception):
    """A planting setup step failed; its undo has run and the launch is skipped."""


@dataclass(frozen=True)
class ImageAccounts:
    passwd: str
    group: str


@dataclass(frozen=True)
class FileIntent:
    container_path: str
    content: str


@dataclass(frozen=True)
class EnvIntent:
    name: str
    content: str


@dataclass(frozen=True)
class AccountIntent:
    name: str
    uid: int
    gid: int
    home: str


@dataclass(frozen=True)
class SentinelIntent:
    host: str
    path: str
    content: str
    bind_address: str | None  # None => a DNS alias on the bridge; else bound inside a holder


@dataclass(frozen=True)
class PlantingSpec:
    host: PlantingHost
    places: tuple[Place, ...]
    nonces: Mapping[str, str]
    files: tuple[FileIntent, ...]
    env: tuple[EnvIntent, ...]
    account: AccountIntent | None
    hostname: str | None
    sentinels: tuple[SentinelIntent, ...]
    address_setups: tuple[str, ...]
    host_entries: tuple[tuple[str, str], ...]
    needs_network: bool
    needs_holder: bool
    unplaceable: int


@dataclass(frozen=True)
class PlantedArgs:
    user: tuple[str, ...]
    working_directory: tuple[str, ...]
    env: tuple[str, ...]
    mounts: tuple[str, ...]
    hostname: tuple[str, ...]
    network: tuple[str, ...]

    def run_args(self) -> list[str]:
        return [
            *self.user,
            *self.working_directory,
            *self.env,
            *self.mounts,
            *self.hostname,
            *self.network,
        ]


class PlantingDocker(Protocol):
    def image_accounts(self, image_tag: str) -> ImageAccounts: ...
    def write_host_file(self, content: str, mode: int) -> str: ...
    def remove_host_file(self, path: str) -> None: ...
    def create_network(self) -> str: ...
    def remove_network(self, name: str) -> None: ...
    def start_holder(self, run_args: Sequence[str]) -> str: ...
    def remove_holder(self, name: str) -> None: ...
    def start_sentinel(self, run_args: Sequence[str]) -> str: ...
    def stop_sentinel(self, name: str) -> None: ...
    def run_address_setup(self, run_args: Sequence[str]) -> None: ...


def quiet(action: object, *args: object) -> None:
    try:
        action(*args)  # type: ignore[operator]
    except Exception as error:
        logger.warning("planting teardown failed: %s", error)


def confinement_args() -> list[str]:
    # The process bound is about twenty times what these servers run at rest, and it fails
    # gracefully: fork returns EAGAIN and the server survives, so the bound cannot turn a run
    # into a false miss the way a memory kill would.
    return ["--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "256"]


def no_network_args() -> list[str]:
    return ["--network", "none"]


def unprivileged_user_args() -> list[str]:
    # An image without a USER runs as root inside the container. Behind an empty capability
    # bounding set that root is disarmed, but an escape that lands as nobody on the host is
    # still better than one that lands as root.
    return ["--user", "65534:65534", "-e", "HOME=/tmp"]


def host_user_args() -> list[str]:
    # Run the bind-mount containers as the host user so files the server writes into /work
    # (e.g. git_init's .git) are host-owned. The CVE is a scope/path bug, independent of the
    # container uid, so this preserves the exploit while letting teardown remove the files and
    # git operate on a repo it owns. HOME is set because git needs a writable home for a uid
    # absent from the image's passwd file.
    return ["--user", f"{os.getuid()}:{os.getgid()}", "-e", "HOME=/tmp"]
