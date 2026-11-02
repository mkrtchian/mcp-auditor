import contextlib
import secrets
import socket
import subprocess
import threading
import time
from collections.abc import Generator

from evals.closed_network import create_closed_network
from evals.cve_planting import DockerPlanting, PlantedArgs, confinement_args, planted
from evals.cve_planting_base import LABEL, SENTINEL_IMAGE
from tests.integration.support.test_cve_planting_given import (
    IP_LITERAL as IP_LITERAL,
)
from tests.integration.support.test_cve_planting_given import (
    missing_prerequisite as missing_prerequisite,
)
from tests.integration.support.test_cve_planting_given import spec_of

PINNED_NAME = "pinned.test"
UNPINNED_NAME = "example.com"
_SERVING_BUDGET = 10.0


@contextlib.contextmanager
def a_host_listener() -> Generator[int]:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 0))
    server.listen()
    thread = threading.Thread(target=_accept_until_closed, args=(server,), daemon=True)
    thread.start()
    try:
        yield server.getsockname()[1]
    finally:
        server.close()


def _accept_until_closed(server: socket.socket) -> None:
    while True:
        try:
            connection, _ = server.accept()
        except OSError:
            return
        connection.close()


def host_ipv4_addresses() -> list[str]:
    output = subprocess.run(
        ["ip", "-4", "-o", "addr", "show"], check=True, capture_output=True, text=True
    ).stdout
    addresses = [line.split()[3].split("/")[0] for line in output.splitlines()]
    return [address for address in addresses if not address.startswith("127.")]


def a_network_name() -> str:
    return f"{LABEL}-closed-test-{secrets.token_hex(6)}"


@contextlib.contextmanager
def a_closed_network() -> Generator[str]:
    name = a_network_name()
    create_closed_network(name)
    with _removed_at_exit(name):
        yield name


@contextlib.contextmanager
def an_open_network() -> Generator[str]:
    name = a_network_name()
    _docker("network", "create", "--label", LABEL, name)
    with _removed_at_exit(name):
        yield name


@contextlib.contextmanager
def _removed_at_exit(network: str) -> Generator[None]:
    try:
        yield
    finally:
        subprocess.run(["docker", "network", "rm", network], check=False, capture_output=True)


@contextlib.contextmanager
def a_container_on(network: str) -> Generator[str]:
    """A sentinel serving on its own port 80, the pinned name resolving to its loopback."""
    name = start_container_on(network)
    try:
        _wait_serving(name)
        yield name
    finally:
        subprocess.run(["docker", "rm", "-f", name], check=False, capture_output=True)


@contextlib.contextmanager
def a_planted_launch_with_a_network() -> Generator[PlantedArgs]:
    """An IP-literal sentinel, so the launch joins a holder on the planting's own network."""
    spec = spec_of(IP_LITERAL, "/fict/secret", has_network=True)
    with planted(spec, SENTINEL_IMAGE, DockerPlanting()) as args:
        yield args


@contextlib.contextmanager
def a_container_with(args: PlantedArgs) -> Generator[str]:
    name = f"{LABEL}-closed-test-{secrets.token_hex(6)}"
    _docker(
        "run", "-d", "--rm", "--label", LABEL, "--name", name, *confinement_args(),
        *args.run_args(), "--entrypoint", "sleep", SENTINEL_IMAGE, "300",
    )  # fmt: skip
    try:
        yield name
    finally:
        subprocess.run(["docker", "rm", "-f", name], check=False, capture_output=True)


def start_container_on(network: str) -> str:
    name = f"{LABEL}-closed-test-{secrets.token_hex(6)}"
    _docker(
        "run", "-d", "--rm", "--label", LABEL, "--name", name, "--network", network,
        "--add-host", f"{PINNED_NAME}:127.0.0.1", "-e", "FLAG=closed-network-test",
        SENTINEL_IMAGE,
    )  # fmt: skip
    return name


def _wait_serving(container: str) -> None:
    deadline = time.monotonic() + _SERVING_BUDGET
    while not reaches(container, "127.0.0.1", 80) and time.monotonic() < deadline:
        time.sleep(0.2)


def reaches(container: str, host: str, port: int) -> bool:
    return _exec(container, "nc", "-z", "-w", "5", host, str(port)).returncode == 0


def timed_reach(container: str, host: str, port: int) -> tuple[bool, float]:
    start = time.monotonic()
    reached = reaches(container, host, port)
    return reached, time.monotonic() - start


def routes(container: str) -> str:
    return _exec(container, "ip", "route").stdout


def gateway(container: str) -> str:
    default = next(line for line in routes(container).splitlines() if line.startswith("default"))
    return default.split()[2]


def _exec(container: str, *command: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "exec", container, *command],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _docker(*arguments: str) -> None:
    subprocess.run(["docker", *arguments], check=True, capture_output=True)
