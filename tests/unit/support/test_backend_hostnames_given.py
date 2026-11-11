import base64
import re
import shlex
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from evals.cve_images import dockerfile_instructions
from evals.docker_paths import DOCKER_DIRECTORY, image_dockerfile
from evals.gravitino_backend import GRAVITINO_PARTS, GRAVITINO_SEED, GravitinoPart
from evals.nuisance_admission import AdmittedServer
from tests.unit.support.test_nuisance_committed_admission_given import the_committed_admission


def admitted_servers() -> list[AdmittedServer]:
    return list(the_committed_admission().servers)


def the_admitted_server(service: str) -> AdmittedServer:
    return next(server for server in admitted_servers() if server.service == service)


def the_benign_argument(service: str, name: str) -> Any:
    server = the_admitted_server(service)
    calls = [call for flaw in server.flaws for call in flaw.benign_calls]
    return next(call.arguments[name] for call in calls if name in call.arguments)


def run_dockerfile_env(server: AdmittedServer) -> dict[str, str]:
    return _env_values(image_dockerfile(server.service, DOCKER_DIRECTORY))


def part_dockerfile_env(part: GravitinoPart) -> dict[str, str]:
    return _env_values(image_dockerfile(part.service))


def kafka_advertised_listeners() -> str:
    kafka = next(part for part in GRAVITINO_PARTS if part.alias == "kafka")
    return part_dockerfile_env(kafka)["KAFKA_ADVERTISED_LISTENERS"]


def gravitino_catalog_properties() -> dict[str, dict[str, str]]:
    return {
        request.body["name"]: request.body["properties"]
        for request in GRAVITINO_SEED
        if request.path.endswith("/catalogs")
    }


def gravitino_seeded_values() -> list[str]:
    return [
        value for request in GRAVITINO_SEED for value in [request.path, *_strings(request.body)]
    ]


def mcp_ssh_config() -> dict[str, str]:
    written = re.search(r"printf '(Host [^']*)' > /tmp/\.ssh/config", _text("mcp-ssh"))
    assert written is not None
    lines = (line.strip() for line in written.group(1).split("\\n"))
    return dict(line.split(" ", 1) for line in lines if line)


def sshd_authorized_key_fields() -> list[str]:
    written = re.search(
        r"'(ssh-ed25519 [^']*)' > /home/tester/\.ssh/authorized_keys", _text("mcp-ssh-sshd")
    )
    assert written is not None
    return written.group(1).split()


@dataclass(frozen=True)
class BakedPrivateKey:
    public_blob: bytes
    comment: str


def mcp_ssh_private_key() -> BakedPrivateKey:
    baked = re.search(r"'([A-Za-z0-9+/=]+)' \| base64 -d > /tmp/\.ssh/id_ed25519", _text("mcp-ssh"))
    assert baked is not None
    armored = base64.b64decode(baked.group(1)).decode().splitlines()
    body = base64.b64decode("".join(line for line in armored if not line.startswith("-----")))
    # PROTOCOL.key: magic, cipher, kdf, kdf options, key count, public blob, private section
    wire = _Wire(body.removeprefix(b"openssh-key-v1\0"))
    for _ in range(3):
        wire.string()
    wire.uint32()
    public_blob = wire.string()
    private = _Wire(wire.string())
    for _ in range(2):  # the two check integers
        private.uint32()
    for _ in range(3):  # key type, public key, private key
        private.string()
    return BakedPrivateKey(public_blob, private.string().decode())


class _Wire:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._at = 0

    def uint32(self) -> int:
        (value,) = struct.unpack_from(">I", self._data, self._at)
        self._at += 4
        return value

    def string(self) -> bytes:
        length = self.uint32()
        value = self._data[self._at : self._at + length]
        self._at += length
        return value


def _text(service: str) -> str:
    return image_dockerfile(service).read_text()


def benign_argument_values(server: AdmittedServer) -> list[str]:
    calls = [
        call
        for flaw in server.flaws
        for benign in flaw.benign_calls
        for call in [*(benign.before or []), benign]
    ]
    return [value for call in calls for value in _strings(call.arguments)]


def _env_values(dockerfile: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for instruction in _joined_continuations(dockerfile_instructions(dockerfile)):
        keyword, _, rest = instruction.partition(" ")
        # case-sensitive: a heredoc body line such as `env = ...` is not an instruction
        if keyword != "ENV":
            continue
        words = shlex.split(rest)
        if "=" not in words[0]:
            values[words[0]] = " ".join(words[1:])
            continue
        values |= dict(word.split("=", 1) for word in words)
    return values


def _joined_continuations(instructions: list[str]) -> Iterator[str]:
    pending = ""
    for line in instructions:
        if line.endswith("\\"):
            pending += line[:-1].strip() + " "
            continue
        yield pending + line
        pending = ""


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in cast(dict[str, Any], value).values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in cast(list[Any], value):
            yield from _strings(item)
    else:
        yield str(value)
