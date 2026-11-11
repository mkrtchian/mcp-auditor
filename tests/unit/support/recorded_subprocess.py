"""The commands a module hands `subprocess.run`, each answered as a success with no output."""

import subprocess
from collections.abc import Sequence

import pytest


def recorded_commands(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    commands: list[list[str]] = []

    def run(args: Sequence[str], **_: object) -> subprocess.CompletedProcess[str]:
        commands.append(list(args))
        return subprocess.CompletedProcess(list(args), 0, "", "")

    monkeypatch.setattr(subprocess, "run", run)
    return commands
