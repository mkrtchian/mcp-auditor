import json
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass

import pytest

from evals.cve.backends import doris
from evals.cve.nuisance.confinement import launch_digest
from evals.cve.planting_base import LABEL


@dataclass
class FakeClock:
    """Time that passes only while the module under test sleeps."""

    now: float = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


@dataclass
class FakeDorisDocker:
    """A Doris cluster already running with the committed launch, healthy, on its closed
    networks. Its sample table holds `rows` rows, or its back end answers no statement while
    `rows` is None."""

    rows: int | None
    seedings: int = 0

    def run(self, args: Sequence[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        command = list(args)
        code, stdout = self._answer(command)
        return subprocess.CompletedProcess(command, code, stdout, "")

    def _answer(self, command: list[str]) -> tuple[int, str]:
        match command[1:3]:
            case ["network", "inspect"]:
                return 0, _a_closed_network()
            case ["inspect", "-f"]:
                return 0, self._inspected(command[3])
            case ["run", "--rm"]:
                return self._statement(command[-1])
            case _:
                return 0, ""

    def _inspected(self, template: str) -> str:
        if "Health" in template:
            return "healthy\n"
        return f"true {launch_digest(doris.doris_cluster_run_args())}\n"

    def _statement(self, sql: str) -> tuple[int, str]:
        if self.rows is None:
            return 1, ""
        if sql.startswith("SELECT COUNT(*)"):
            return 0, f"COUNT(*)\n{self.rows}\n"
        if sql.startswith("insert into"):
            self.seedings += 1
            self.rows += 4
        return 0, ""


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


def a_cluster_whose_sample_table_holds(
    monkeypatch: pytest.MonkeyPatch, rows: int | None
) -> FakeDorisDocker:
    docker = FakeDorisDocker(rows)
    monkeypatch.setattr(subprocess, "run", docker.run)
    monkeypatch.setattr(doris, "time", FakeClock())
    return docker
