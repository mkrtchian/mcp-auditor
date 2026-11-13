import subprocess
from collections.abc import Generator, Sequence
from contextlib import contextmanager
from pathlib import Path

import pytest

from evals.cve.backends.mcp_ssh_holdout import SshdDocker
from evals.cve.backends.mcp_ssh_sshd import StoodSshd
from tests.fakes.planting_docker import FakePlantingDocker

SCANNED = (
    "127.0.0.1 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ\n"
    "127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOk\n"
)


class FakeSshd:
    """Stands an sshd on a named network with a known_hosts file, and records the owner each
    stand-up asks for and the containers connected to its network."""

    def __init__(self, known_hosts: Path, planting: FakePlantingDocker | None = None) -> None:
        self.known_hosts = known_hosts
        self.planting = planting
        self.owners: list[str] = []
        self.connected: list[tuple[str, str]] = []
        self.holders_at_removal: list[list[str]] = []

    @contextmanager
    def stand(self, name: str, owner: str) -> Generator[StoodSshd]:
        self.owners.append(owner)
        yield StoodSshd(f"sshd-net-{len(self.owners)}", self.known_hosts)
        if self.planting is not None:
            self.holders_at_removal.append(list(self.planting.holders))

    def connect(self, network: str, container: str) -> None:
        self.connected.append((network, container))

    def docker(self) -> SshdDocker:
        return SshdDocker(self.stand, self.connect)


def an_sshd(tmp_path: Path) -> FakeSshd:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(SCANNED)
    return FakeSshd(known_hosts)


def an_sshd_watching_holders(tmp_path: Path, planting: FakePlantingDocker) -> FakeSshd:
    sshd = an_sshd(tmp_path)
    sshd.planting = planting
    return sshd


class FakeDocker:
    """Answers every Docker command with success and records it."""

    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def run(self, args: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        self.commands.append(list(args))
        return subprocess.CompletedProcess(list(args), 0, "", "")


def a_docker(monkeypatch: pytest.MonkeyPatch) -> FakeDocker:
    docker = FakeDocker()
    monkeypatch.setattr(subprocess, "run", docker.run)
    return docker
