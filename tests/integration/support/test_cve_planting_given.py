import json
import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path

from evals.cve_places import Coordinates, Place, PlantKind
from evals.cve_planting import (
    RANDOM_NONCES,
    DockerPlanting,
    PlantedArgs,
    PlantingHost,
    PlantingSpec,
    SymbolicUser,
    confinement_args,
    planting_spec,
)
from evals.cve_planting_base import LABEL, SENTINEL_IMAGE, STAND_IN_IMAGE, PublicNames
from evals.cve_planting_spec import request_target
from mcp_auditor.adapters.docker import DockerRuntime

IP_LITERAL = "198.51.100.5"  # RFC 5737 documentation range: routes nowhere
STAND_IN_HOST = "public.fict"
STAND_IN_ADDRESS = "93.184.215.14"  # a global unicast address, as the capture loader requires
PLAIN_BODY = "the plain stand-in body"
SECURE_BODY = "the secure stand-in body"
PROBED_TARGET = "/0123456789abcdef"
MISSING_BODY = "the secure stand-in's answer to an unknown path"
_GENERATE_TLS = Path(__file__).parents[3] / "evals" / "stand_ins" / "tls" / "generate.sh"
# The stand-in image's Python as the target: urllib verifies TLS against the default paths,
# which `SSL_CERT_FILE` points at the fixture authority. A 4xx prints its status.
_FETCH = (
    "import sys,urllib.error,urllib.request\n"
    "try:print(urllib.request.urlopen(sys.argv[1],timeout=5).read().decode(),end='')\n"
    "except urllib.error.HTTPError as error:print(error.code,end='')"
)
# wget's own 5 s bound plus the start-up of the fresh container each read runs in.
_READ_TIMEOUT = 10.0


def missing_prerequisite() -> str | None:
    if not DockerRuntime().available():
        return "CVE planting needs Docker"
    return None


def missing_openssl() -> str | None:
    return None if shutil.which("openssl") else "the planted stand-in needs openssl"


def spec_of(
    host: str, path: str, *, has_network: bool = False, file_at: str | None = None
) -> PlantingSpec:
    places: list[Place] = []
    if file_at is not None:
        places.append(_place("file-1", Coordinates(PlantKind.FILE, path=file_at)))
    places.append(_place("endpoint-1", Coordinates(PlantKind.HTTP_ENDPOINT, host=host, path=path)))
    planting_host = PlantingHost(SymbolicUser.UNPRIVILEGED, "/srv/fictional", has_network)
    return planting_spec(places, planting_host, RANDOM_NONCES)


def a_stand_in_spec() -> PlantingSpec:
    names = PublicNames(stand_ins=(STAND_IN_HOST,), trust=("SSL_CERT_FILE",))
    planting_host = PlantingHost(SymbolicUser.UNPRIVILEGED, "/srv/fictional", True, names)
    return planting_spec([], planting_host, RANDOM_NONCES)


def a_launch_of_shape(shape: str) -> PlantingSpec:
    if shape == "no_network":
        planting_host = PlantingHost(SymbolicUser.UNPRIVILEGED, "/srv/fictional", False)
        return planting_spec([], planting_host, RANDOM_NONCES)
    if shape == "holder":
        return spec_of(IP_LITERAL, "/fict/secret", has_network=True)
    return spec_of("meta.fict", "/fict/secret", has_network=True)


def a_stand_ins_directory(directory: Path) -> Path:
    capture = {
        "host": STAND_IN_HOST,
        "address": STAND_IN_ADDRESS,
        "captured_at": "2026-11-02T10:00:00Z",
        "command": "uv run python -m evals.capture_stand_in --out x.json http://public.fict/",
        "request_headers": [],
        "routes": [_route("http", PLAIN_BODY), _route("https", SECURE_BODY)],
        "defaults": [_redirect_to_https(), _not_found()],
    }
    (directory / f"{STAND_IN_HOST}.json").write_text(json.dumps(capture))
    subprocess.run(
        [str(_GENERATE_TLS), "--out", str(directory / "tls"), STAND_IN_HOST],
        check=True,
        capture_output=True,
    )
    return directory


def _route(scheme: str, body: str) -> dict[str, object]:
    return {
        "scheme": scheme,
        "method": "GET",
        "target": "/",
        "status": 200,
        "headers": [["Content-Type", "text/plain"]],
        "body": body,
    }


def _redirect_to_https() -> dict[str, object]:
    return {
        "scheme": "http",
        "probed_target": PROBED_TARGET,
        "status": 301,
        "headers": [["Location", f"https://{STAND_IN_HOST}{PROBED_TARGET}"]],
        "body": "",
        "path_form": None,
    }


def _not_found() -> dict[str, object]:
    return {
        "scheme": "https",
        "probed_target": PROBED_TARGET,
        "status": 404,
        "headers": [["Content-Type", "text/plain"]],
        "body": MISSING_BODY,
        "path_form": None,
    }


def fetch_as_target(args: PlantedArgs, url: str) -> str:
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--label",
            LABEL,
            *confinement_args(),
            *args.run_args(),
            "--entrypoint",
            "python",
            STAND_IN_IMAGE,
            "-c",
            _FETCH,
            url,
        ],
        capture_output=True,
        text=True,
        timeout=_READ_TIMEOUT,
    )
    return result.stdout


def _place(entry_id: str, coordinates: Coordinates) -> Place:
    return Place(
        id=entry_id,
        family="fictional-family",
        reachable_by=frozenset({"arbitrary_read"}),
        kind=coordinates.kind,
        coordinates=coordinates,
    )


def read_as_target(args: PlantedArgs, host: str, path: str) -> str:
    try:
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--label",
                LABEL,
                *confinement_args(),
                *args.run_args(),
                "--entrypoint",
                "/bin/wget",
                SENTINEL_IMAGE,
                "-Y",
                "off",
                "-qO-",
                "-T",
                "5",
                f"http://{host}:80{request_target(path)}",
            ],
            capture_output=True,
            text=True,
            timeout=_READ_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return ""
    return result.stdout


def identity_as_target(args: PlantedArgs) -> dict[str, str]:
    """What the target reads of its own identity, each file under its name, from one container
    started with the target's own options."""
    script = "; ".join(
        f"echo '{_SECTION}{name}'; {command}" for name, command in _IDENTITY_READS.items()
    )
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--label",
            LABEL,
            *confinement_args(),
            *args.run_args(),
            "--entrypoint",
            "/bin/sh",
            SENTINEL_IMAGE,
            "-c",
            script,
        ],
        capture_output=True,
        text=True,
        timeout=_READ_TIMEOUT,
        check=True,
    )
    sections = result.stdout.split(_SECTION)[1:]
    return dict(section.split("\n", 1) for section in sections)


_SECTION = "=== "
_IDENTITY_READS = {
    "hostname": "hostname",
    "/etc/hosts": "cat /etc/hosts",
    "/etc/resolv.conf": "cat /etc/resolv.conf",
    "env": "env",
}


class RecordingPlanting(DockerPlanting):
    def __init__(self) -> None:
        self.networks: list[str] = []
        self.containers: list[str] = []
        self.stand_ins: list[str] = []

    def create_network(self) -> str:
        name = super().create_network()
        self.networks.append(name)
        return name

    def start_holder(self, run_args: Sequence[str]) -> str:
        name = super().start_holder(run_args)
        self.containers.append(name)
        return name

    def start_sentinel(self, run_args: Sequence[str]) -> str:
        name = super().start_sentinel(run_args)
        self.containers.append(name)
        return name

    def start_stand_in(self, run_args: Sequence[str]) -> str:
        name = super().start_stand_in(run_args)
        self.containers.append(name)
        self.stand_ins.append(name)
        return name
