"""Generic planting: a nonce dropped into one of the frozen list's locations, by kind.

`planted` carries a `PlantingSpec` out through the injected `PlantingDocker`: it writes the
host files, creates the network, stands the namespace holder and the sentinels up, and
yields the target's `docker run` arguments as `PlantedArgs`. Setup undoes itself and raises
`PlantingFailed` on any failure (a non-zero Docker call or a host file that cannot be
written). Teardown is best-effort and never raises. It owns the network of a launch that has
one, as a plain labelled bridge, so no planting touches the host's routing table.

The pure half (`planting_spec`), the vocabulary and the Docker port live in the sibling
modules. This module re-exports their public names so a consumer reads one name.
"""

import subprocess
from collections.abc import Generator
from contextlib import ExitStack, contextmanager

from evals.cve_planting_base import (
    RANDOM_NONCES as RANDOM_NONCES,
)
from evals.cve_planting_base import (
    SENTINEL_IMAGE as SENTINEL_IMAGE,
)
from evals.cve_planting_base import (
    SENTINEL_SERVICE as SENTINEL_SERVICE,
)
from evals.cve_planting_base import (
    AccountIntent,
    PlantedArgs,
    PlantingDocker,
    PlantingFailed,
    PlantingSpec,
    SentinelIntent,
    SymbolicUser,
    confinement_args,
    host_user_args,
    no_network_args,
    quiet,
    unprivileged_user_args,
)
from evals.cve_planting_base import (
    ImageAccounts as ImageAccounts,
)
from evals.cve_planting_base import (
    NonceSource as NonceSource,
)
from evals.cve_planting_base import (
    PlantingHost as PlantingHost,
)
from evals.cve_planting_docker import (
    DockerPlanting as DockerPlanting,
)
from evals.cve_planting_spec import planting_spec as planting_spec

# re-exported for a one-name import by the audit, calibration, survey and replay callers.
# The user and network helpers (host_user_args, no_network_args, unprivileged_user_args) are
# imported above for `planted`'s own use only, so they stay off this public surface.
__all__ = [
    "RANDOM_NONCES",
    "SENTINEL_IMAGE",
    "SENTINEL_SERVICE",
    "DockerPlanting",
    "ImageAccounts",
    "NonceSource",
    "PlantedArgs",
    "PlantingDocker",
    "PlantingFailed",
    "PlantingHost",
    "PlantingSpec",
    "SymbolicUser",
    "confinement_args",
    "planted",
    "planting_spec",
]

_HOLDER_SLEEP = "2147483647"


@contextmanager
def planted(spec: PlantingSpec, image_tag: str, docker: PlantingDocker) -> Generator[PlantedArgs]:
    stack = ExitStack()
    try:
        args = _set_up(spec, image_tag, docker, stack)
    except PlantingFailed:
        stack.close()
        raise
    except (subprocess.CalledProcessError, OSError, UnicodeError) as error:
        stack.close()
        raise PlantingFailed(str(error)) from error
    except BaseException:
        stack.close()
        raise
    try:
        yield args
    finally:
        stack.close()


def _set_up(
    spec: PlantingSpec, image_tag: str, docker: PlantingDocker, stack: ExitStack
) -> PlantedArgs:
    user, mounts = _user_and_mounts(spec, image_tag, docker, stack)
    network = None
    if spec.needs_network:
        network = docker.create_network()
        stack.callback(quiet, docker.remove_network, network)
    holder = _hold_endpoints(spec, network, docker, stack)
    hostname = ("--hostname", spec.hostname) if spec.hostname is not None and holder is None else ()
    return PlantedArgs(
        user=user,
        working_directory=("-w", spec.host.working_directory),
        env=_env_args(spec),
        mounts=mounts,
        hostname=hostname,
        network=_network_args(network, holder),
    )


def _user_and_mounts(
    spec: PlantingSpec, image_tag: str, docker: PlantingDocker, stack: ExitStack
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    mounts: list[str] = []
    if spec.account is not None:
        user, account_mounts = _account_user(spec.account, image_tag, docker, stack)
        mounts += account_mounts
    else:
        user = _symbolic_user_args(spec.host.user)
    for intent in spec.files:
        path = _write(docker, stack, intent.content)
        mounts += ["-v", f"{path}:{intent.container_path}:ro"]
    return user, tuple(mounts)


def _account_user(
    account: AccountIntent, image_tag: str, docker: PlantingDocker, stack: ExitStack
) -> tuple[tuple[str, ...], list[str]]:
    accounts = docker.image_accounts(image_tag)
    passwd = _write(docker, stack, _append_line(accounts.passwd, _passwd_line(account)))
    group = _write(docker, stack, _append_line(accounts.group, _group_line(account)))
    user = ("--user", f"{account.uid}:{account.gid}", "-e", f"HOME={account.home}")
    return user, ["-v", f"{passwd}:/etc/passwd:ro", "-v", f"{group}:/etc/group:ro"]


def _hold_endpoints(
    spec: PlantingSpec, network: str | None, docker: PlantingDocker, stack: ExitStack
) -> str | None:
    holder = None
    if spec.needs_holder:
        holder = docker.start_holder(_holder_args(spec, network))
        stack.callback(quiet, docker.remove_holder, holder)
    for address in spec.address_setups:
        docker.run_address_setup(_address_setup_args(holder, address))
    held: list[tuple[SentinelIntent, str]] = []
    for sentinel in spec.sentinels:
        name = docker.start_sentinel(_sentinel_args(sentinel, network, holder))
        stack.callback(quiet, docker.remove_sentinel, name)
        held.append((sentinel, name))
    # A positive probe by the endpoint's name, from the sentinel, which resolves it as the
    # target does: a running sentinel can still serve a 404, or answer under another name.
    for sentinel, name in held:
        if docker.sentinel_body(name, sentinel.host, sentinel.request_target) != sentinel.content:
            raise PlantingFailed(f"sentinel for {sentinel.host} is not serving")
    return holder


def _holder_args(spec: PlantingSpec, network: str | None) -> list[str]:
    identity: list[str] = []
    if spec.hostname is not None:
        identity += ["--hostname", spec.hostname]
    for host, address in spec.host_entries:
        identity += ["--add-host", f"{host}:{address}"]
    network_args = ["--network", network if network is not None else "none"]
    tail = ["--entrypoint", "sleep", SENTINEL_IMAGE, _HOLDER_SLEEP]
    return [*confinement_args(), *network_args, *identity, *tail]


def _address_setup_args(holder: str | None, address: str) -> list[str]:
    options = [*confinement_args(), "--cap-add", "NET_ADMIN", "--network", f"container:{holder}"]
    return [
        *options,
        "--entrypoint",
        "ip",
        SENTINEL_IMAGE,
        "addr",
        "add",
        f"{address}/32",
        "dev",
        "lo",
    ]


def _sentinel_args(sentinel: SentinelIntent, network: str | None, holder: str | None) -> list[str]:
    served = [
        *confinement_args(),
        "--cap-add",
        "NET_BIND_SERVICE",
        "-e",
        f"FLAG={sentinel.content}",
    ]
    served += ["-e", f"SERVE_FILE={sentinel.served_file}"]
    if sentinel.bind_address is None:
        assert network is not None  # a bridge alias exists only on a launch with a network
        return [*served, "--network", network, "--network-alias", sentinel.host, SENTINEL_IMAGE]
    served += ["--network", f"container:{holder}", "-e", f"BIND_ADDR={sentinel.bind_address}"]
    return [*served, SENTINEL_IMAGE]


def _env_args(spec: PlantingSpec) -> tuple[str, ...]:
    args: list[str] = []
    for intent in spec.env:
        args += ["-e", f"{intent.name}={intent.content}"]
    return tuple(args)


def _network_args(network: str | None, holder: str | None) -> tuple[str, ...]:
    if holder is not None:
        return ("--network", f"container:{holder}")
    if network is not None:
        return ("--network", network)
    return tuple(no_network_args())


def _write(docker: PlantingDocker, stack: ExitStack, content: str) -> str:
    path = docker.write_host_file(content, 0o644)
    stack.callback(quiet, docker.remove_host_file, path)
    return path


def _symbolic_user_args(user: SymbolicUser) -> tuple[str, ...]:
    return tuple(host_user_args() if user is SymbolicUser.HOST else unprivileged_user_args())


def _passwd_line(account: AccountIntent) -> str:
    return f"{account.name}:x:{account.uid}:{account.gid}::{account.home}:/usr/sbin/nologin"


def _group_line(account: AccountIntent) -> str:
    return f"{account.name}:x:{account.gid}:"


def _append_line(content: str, line: str) -> str:
    if content and not content.endswith("\n"):
        content += "\n"
    return f"{content}{line}\n"
