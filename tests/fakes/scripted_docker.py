"""`ScriptedDocker` answers every Docker command with success, its stdout the answer of the
longest scripted prefix of the arguments after `docker`, or empty. It records each command
with its input, and reads back the containers it started and what it removed."""

import json
import subprocess
from collections.abc import Mapping, Sequence

import pytest

from evals.cve.planting_base import LABEL

CLOSED_NETWORK_INSPECT = json.dumps(
    {
        "Internal": True,
        "EnableIPv6": False,
        "Labels": {LABEL: ""},
        "Options": {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"},
        "Containers": {},
    }
)

_REMOVALS = (("rm", "-f", "-v"), ("network", "rm"))


class ScriptedDocker:
    def __init__(self, answers: Mapping[tuple[str, ...], str]) -> None:
        self._answers = sorted(answers.items(), key=lambda answer: -len(answer[0]))
        self.commands: list[list[str]] = []
        self.inputs: list[str | None] = []

    def installed(self, monkeypatch: pytest.MonkeyPatch) -> "ScriptedDocker":
        def run(
            args: Sequence[str], *, input: str | None = None, **_options: object
        ) -> subprocess.CompletedProcess[str]:
            return self.run(args, input=input)

        monkeypatch.setattr(subprocess, "run", run)
        return self

    def run(
        self, args: Sequence[str], *, input: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        command = list(args)
        self.commands.append(command)
        self.inputs.append(input)
        return subprocess.CompletedProcess(command, 0, self._stdout(tuple(command[1:])), "")

    def _stdout(self, arguments: tuple[str, ...]) -> str:
        for prefix, answer in self._answers:
            if arguments[: len(prefix)] == prefix:
                return answer
        return ""

    def started(self) -> list[list[str]]:
        return [command for command in self.commands if command[1:3] == ["run", "-d"]]

    def created_networks(self) -> list[str]:
        return [command[-1] for command in self.commands if command[1:3] == ["network", "create"]]

    def removed(self) -> list[str]:
        return [
            command[-1]
            for command in self.commands
            if any(tuple(command[1 : 1 + len(removal)]) == removal for removal in _REMOVALS)
        ]
