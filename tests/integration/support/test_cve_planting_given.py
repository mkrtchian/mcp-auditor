import json
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
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
PROBED_TARGET = "/0123456789abcdef"
PLAIN_BODY = "the plain stand-in body"
# A captured route is replayed verbatim, so the probed target in it stays as captured.
SECURE_BODY = f"the secure stand-in body, {PROBED_TARGET} as captured"
MISSING_BODY = "the secure stand-in's answer to an unknown path"
# A request target a client sends percent-encoded, every character the escapings rewrite in it.
QUOTED_REQUEST = "/a%3Cb%3E%22%27"
CAPTURED_DATE = "Wed, 04 Nov 2026 07:36:50 GMT"
# The secure route's headers as a host sends them: duplicates, a lowercase name, and the
# connection and framing headers of the capture's own connection, with a length that is wrong
# for the replayed body.
SECURE_HEADERS = (
    ("Date", CAPTURED_DATE),
    ("Content-Type", "text/plain"),
    ("Transfer-Encoding", "chunked"),
    ("Connection", "keep-alive"),
    ("Server", "cloudflare"),
    ("Set-Cookie", "first=1; Path=/"),
    ("Set-Cookie", "second=2; Path=/"),
    ("strict-transport-security", "max-age=31536000"),
    ("Content-Length", "999"),
)
SECURE_REPLAYED = (
    ("Date", CAPTURED_DATE),
    ("Content-Type", "text/plain"),
    ("Server", "cloudflare"),
    ("Set-Cookie", "first=1; Path=/"),
    ("Set-Cookie", "second=2; Path=/"),
    ("strict-transport-security", "max-age=31536000"),
)
HEAD_ONLY_TARGET = "/checked"
# A HEAD route's captured length is the host's length for the body it did not send, kept as is.
HEAD_ONLY_HEADERS = (
    ("Content-Type", "text/html"),
    ("Content-Length", "1256"),
    ("keep-alive", "timeout=5"),
    ("Date", CAPTURED_DATE),
)
HEAD_ONLY_REPLAYED = (
    ("Content-Type", "text/html"),
    ("Content-Length", "1256"),
    ("Date", CAPTURED_DATE),
)
REDIRECT_SERVER = ("Server", "cloudflare")
_GENERATE_TLS = Path(__file__).parents[3] / "evals" / "stand_ins" / "tls" / "generate.sh"
# The stand-in image's Python as the target: http.client sends the target as given and follows
# no redirect, and the default context verifies TLS against the default paths, which
# `SSL_CERT_FILE` points at the fixture authority.
_FETCH = (
    "import http.client,json,ssl,sys,urllib.parse\n"
    "method,url=sys.argv[1],sys.argv[2]\n"
    "parts=urllib.parse.urlsplit(url)\n"
    "connection=(http.client.HTTPSConnection(parts.hostname,timeout=5,"
    "context=ssl.create_default_context()) if parts.scheme=='https'"
    " else http.client.HTTPConnection(parts.hostname,timeout=5))\n"
    "connection.request(method,parts.path)\n"
    "response=connection.getresponse()\n"
    "header_list=response.getheaders()\n"
    "headers={name.lower():value for name,value in header_list}\n"
    "body=response.read().decode()\n"
    "print(json.dumps({'status':response.status,'headers':headers,'header_list':header_list,"
    "'body':body}),end='')"
)
# wget's own 5 s bound plus the start-up of the fresh container each read runs in.
_READ_TIMEOUT = 10.0


DANGLING_LINK = "leak/report"


def a_tree_holding_a_dangling_absolute_link(root: Path) -> None:
    (root / "leak").mkdir(parents=True)
    (root / DANGLING_LINK).symlink_to("/nowhere/in/the/helper")


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


@dataclass(frozen=True)
class QuotingCase:
    content_type: str
    path_form: str
    body: str
    quoted_request: str

    def answer(self, target: str) -> str:
        return self.body.replace(PROBED_TARGET, target)


QUOTING_CASES = {
    "decoded_html": QuotingCase(
        "text/html; charset=utf-8",
        "decoded",
        f'<option value="/fr{PROBED_TARGET}">fr</option><p>No page at {PROBED_TARGET}.</p>',
        "/a&lt;b&gt;&#34;&#39;",
    ),
    "decoded_json": QuotingCase(
        "application/json",
        "decoded",
        f'{{"path": "{PROBED_TARGET}", "error": "no route for {PROBED_TARGET}"}}',
        "/a<b>\\\"'",
    ),
    "raw_html": QuotingCase(
        "text/html",
        "raw",
        f'<option value="/fr{PROBED_TARGET}">fr</option><p>No page at {PROBED_TARGET}.</p>',
        QUOTED_REQUEST,
    ),
}


def a_stand_ins_directory(directory: Path, quoting: QuotingCase | None = None) -> Path:
    secure_default = _not_found() if quoting is None else _quoting_not_found(quoting)
    capture = {
        "host": STAND_IN_HOST,
        "address": STAND_IN_ADDRESS,
        "captured_at": "2026-11-02T10:00:00Z",
        "command": "uv run python -m evals.capture_stand_in --out x.json http://public.fict/",
        "request_headers": [],
        "routes": [
            _route("http", PLAIN_BODY, [["Content-Type", "text/plain"]]),
            _route("https", SECURE_BODY, [list(header) for header in SECURE_HEADERS]),
            _head_only_route(),
        ],
        "defaults": [_redirect_to_https(), secure_default],
    }
    (directory / f"{STAND_IN_HOST}.json").write_text(json.dumps(capture))
    subprocess.run(
        [str(_GENERATE_TLS), "--out", str(directory / "tls"), STAND_IN_HOST],
        check=True,
        capture_output=True,
    )
    return directory


def _route(scheme: str, body: str, headers: list[list[str]]) -> dict[str, object]:
    return {
        "scheme": scheme,
        "method": "GET",
        "target": "/",
        "status": 200,
        "headers": headers,
        "body": body,
    }


def _head_only_route() -> dict[str, object]:
    return {
        "scheme": "https",
        "method": "HEAD",
        "target": HEAD_ONLY_TARGET,
        "status": 200,
        "headers": [list(header) for header in HEAD_ONLY_HEADERS],
        "body": "",
    }


def _redirect_to_https() -> dict[str, object]:
    return {
        "scheme": "http",
        "probed_target": PROBED_TARGET,
        "status": 301,
        "headers": [
            ["Location", f"https://{STAND_IN_HOST}{PROBED_TARGET}"],
            list(REDIRECT_SERVER),
        ],
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


def _quoting_not_found(case: QuotingCase) -> dict[str, object]:
    return {
        "scheme": "https",
        "probed_target": PROBED_TARGET,
        "status": 404,
        "headers": [["Content-Type", case.content_type]],
        "body": case.body,
        "path_form": case.path_form,
    }


@dataclass(frozen=True)
class Fetched:
    status: int
    headers: dict[str, str]
    header_list: list[tuple[str, str]]
    body: str


def fetch_as_target(args: PlantedArgs, url: str, method: str = "GET") -> Fetched:
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
            method,
            url,
        ],
        capture_output=True,
        text=True,
        timeout=_READ_TIMEOUT,
        check=True,
    )
    fetched = json.loads(result.stdout)
    header_list = [(name, value) for name, value in fetched.pop("header_list")]
    return Fetched(**fetched, header_list=header_list)


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
