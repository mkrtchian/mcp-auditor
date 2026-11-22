"""`ScriptedDockerExecutable` puts a `docker` executable first on `PATH`, so the code under test
reaches it through its own `subprocess.run(["docker", ...])`. The executable answers every
command with success, its stdout the answer of the longest scripted prefix of the arguments after
`docker`, or empty. It logs each command with what it read on its input, which it reads only under
`-i`, as Docker does, and the fake reads back the containers it started and what it removed.
Configured with a socket path, a `docker run -d` opens a unix socket of mode 0666 at that path in
the host directory mounted at its parent, as the node sandbox engine's entrypoint does."""

import json
import os
import stat
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import TypedDict

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
_SCRIPT_FILE = "script.json"
_LOG_FILE = "log.jsonl"

# Standard library only: `-IS` keeps the project's environment and site-packages out.
_EXECUTABLE = """\
import json
import os
import socket
import sys

directory = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(directory, "script.json")) as script_file:
    script = json.load(script_file)
arguments = sys.argv[1:]
stdin = sys.stdin.read() if "-i" in arguments else None
with open(os.path.join(directory, "log.jsonl"), "a") as log:
    log.write(json.dumps({"argv": ["docker", *arguments], "stdin": stdin}) + "\\n")

socket_path = script["opens_socket_at"]
if socket_path and arguments[:2] == ["run", "-d"]:
    for option, value in zip(arguments, arguments[1:]):
        if option == "-v" and value.split(":")[1] == os.path.dirname(socket_path):
            # A socket path is bounded to about 100 bytes, so it is bound relative to its directory.
            os.chdir(value.split(":")[0])
            name = os.path.basename(socket_path)
            with socket.socket(socket.AF_UNIX) as engine_socket:
                engine_socket.bind(name)
            os.chmod(name, 0o666)

for prefix, answer in sorted(script["answers"], key=lambda pair: -len(pair[0])):
    if arguments[: len(prefix)] == prefix:
        sys.stdout.write(answer)
        break
"""


class _LoggedCommand(TypedDict):
    argv: list[str]
    stdin: str | None


class ScriptedDockerExecutable:
    def __init__(
        self, answers: Mapping[tuple[str, ...], str], opens_socket_at: str | None = None
    ) -> None:
        self._answers = answers
        self._opens_socket_at = opens_socket_at
        self._directory: Path | None = None

    def installed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> "ScriptedDockerExecutable":
        directory = tmp_path / "scripted_docker"
        directory.mkdir()
        script = {
            "answers": [[list(prefix), answer] for prefix, answer in self._answers.items()],
            "opens_socket_at": self._opens_socket_at,
        }
        (directory / _SCRIPT_FILE).write_text(json.dumps(script))
        executable = directory / "docker"
        executable.write_text(f"#!{sys.executable} -IS\n{_EXECUTABLE}")
        executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
        monkeypatch.setenv("PATH", f"{directory}{os.pathsep}{os.environ['PATH']}")
        self._directory = directory
        return self

    @property
    def commands(self) -> list[list[str]]:
        return [logged["argv"] for logged in self._logged()]

    @property
    def inputs(self) -> list[str | None]:
        return [logged["stdin"] for logged in self._logged()]

    def _logged(self) -> list[_LoggedCommand]:
        assert self._directory is not None, "the fake docker is not installed"
        log = self._directory / _LOG_FILE
        if not log.exists():
            return []
        return [json.loads(line) for line in log.read_text().splitlines()]

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
