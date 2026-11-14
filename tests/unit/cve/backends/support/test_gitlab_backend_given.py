import json
import subprocess
from collections.abc import Sequence
from typing import cast

import pytest

from evals.cve.planting_base import LABEL, PlantingHost, SymbolicUser

RECONFIGURED = "gitlab Reconfigured!\n"
RECONFIGURE_FAILED = "There was an error running gitlab-ctl reconfigure\n"


def a_host() -> PlantingHost:
    return PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=True)


class FakeGitLabDocker:
    """Answers every Docker command with success: a network it was asked to create inspects as
    closed, a backend runs, and its logs carry the given text."""

    def __init__(self, logs: str) -> None:
        self.logs = logs
        self.commands: list[list[str]] = []
        self.inputs: list[str | None] = []

    def run(self, args: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        command = list(args)
        self.commands.append(command)
        self.inputs.append(cast(str | None, kwargs.get("input")))
        return subprocess.CompletedProcess(command, 0, self._stdout(command), "")

    def _stdout(self, command: list[str]) -> str:
        match command[1:3]:
            case ["network", "inspect"]:
                return _a_closed_network()
            case ["logs", _]:
                return self.logs
            case ["inspect", _]:
                return "running\n"
            case _:
                return ""

    def started(self) -> list[list[str]]:
        return [command for command in self.commands if command[1:3] == ["run", "-d"]]

    def created_networks(self) -> list[str]:
        return [command[-1] for command in self.commands if command[1:3] == ["network", "create"]]

    def removed(self) -> list[str]:
        removals = (["rm", "-f", "-v"], ["network", "rm"])
        return [
            command[-1]
            for command in self.commands
            if any(command[1 : 1 + len(removal)] == removal for removal in removals)
        ]

    def seed_commands(self) -> list[tuple[list[str], str | None]]:
        return [
            (command, given_input)
            for command, given_input in zip(self.commands, self.inputs, strict=True)
            if command[1:3] == ["exec", "-i"]
        ]


def _a_closed_network() -> str:
    return json.dumps(
        {
            "Internal": True,
            "EnableIPv6": False,
            "Labels": {LABEL: ""},
            "Options": {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"},
            "Containers": {},
        }
    )


def a_docker_whose_gitlab_comes_up(monkeypatch: pytest.MonkeyPatch) -> FakeGitLabDocker:
    return _a_docker(monkeypatch, RECONFIGURED)


def a_docker_whose_gitlab_fails_to_reconfigure(
    monkeypatch: pytest.MonkeyPatch,
) -> FakeGitLabDocker:
    return _a_docker(monkeypatch, RECONFIGURE_FAILED)


def _a_docker(monkeypatch: pytest.MonkeyPatch, logs: str) -> FakeGitLabDocker:
    docker = FakeGitLabDocker(logs)
    monkeypatch.setattr(subprocess, "run", docker.run)
    return docker
