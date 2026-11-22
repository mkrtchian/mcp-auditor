import base64
import re
import struct
from dataclasses import dataclass
from typing import Any

from evals.cve.docker_paths import image_dockerfile
from tests.unit.support.committed_nuisance_admission import the_committed_admission


def mcp_ssh_config() -> dict[str, str]:
    written = re.search(r"printf '(Host [^']*)' > /tmp/\.ssh/config", _text("mcp-ssh"))
    assert written is not None
    lines = (line.strip() for line in written.group(1).split("\\n"))
    return dict(line.split(" ", 1) for line in lines if line)


def benign_host_aliases() -> list[Any]:
    server = next(
        server for server in the_committed_admission().servers if server.service == "mcp-ssh"
    )
    calls = [call for flaw in server.flaws for call in flaw.benign_calls]
    return [call.arguments["hostAlias"] for call in calls if "hostAlias" in call.arguments]


def sshd_authorized_key_fields() -> list[str]:
    written = re.search(
        r"'(ssh-ed25519 [^']*)' > /home/deploy/\.ssh/authorized_keys", _text("mcp-ssh-sshd")
    )
    assert written is not None
    return written.group(1).split()


def sshd_account() -> str:
    users = re.findall(r"^USER (\S+)$", _text("mcp-ssh-sshd"), re.MULTILINE)
    return users[-1]


@dataclass(frozen=True)
class BakedPrivateKey:
    public_blob: bytes
    comment: str


def mcp_ssh_private_key() -> BakedPrivateKey:
    baked = re.search(
        r"'([A-Za-z0-9+/=]+)' \| base64 -d > /tmp/\.ssh/id_production", _text("mcp-ssh")
    )
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
