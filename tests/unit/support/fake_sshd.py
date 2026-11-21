from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from evals.cve.backends.mcp_ssh_holdout import SshdDocker
from evals.cve.backends.mcp_ssh_sshd import StoodSshd

SCANNED = (
    "127.0.0.1 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ\n"
    "127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOk\n"
)


class FakeSshd:
    """Stands an sshd on a named network with a known_hosts file, and records the owner each
    stand-up asks for."""

    def __init__(self, known_hosts: Path) -> None:
        self.known_hosts = known_hosts
        self.owners: list[str] = []

    @contextmanager
    def stand(self, name: str, owner: str) -> Generator[StoodSshd]:
        self.owners.append(owner)
        yield StoodSshd(f"sshd-net-{len(self.owners)}", self.known_hosts)

    def connect(self, network: str, container: str) -> None:
        pass

    def docker(self) -> SshdDocker:
        return SshdDocker(self.stand, self.connect)


def an_sshd(tmp_path: Path) -> FakeSshd:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(SCANNED)
    return FakeSshd(known_hosts)
