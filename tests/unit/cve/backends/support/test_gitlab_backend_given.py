import pytest

from evals.cve.backends import gitlab_responder
from evals.cve.backends.responder import Responder
from evals.cve.planting_base import PlantingHost, SymbolicUser
from tests.fakes import CLOSED_NETWORK_INSPECT, ScriptedDocker

RECONFIGURED = "gitlab Reconfigured!\n"
RECONFIGURE_FAILED = "There was an error running gitlab-ctl reconfigure\n"


def a_host() -> PlantingHost:
    return PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=True)


def the_gitlab_responder() -> Responder:
    return next(value for value in vars(gitlab_responder).values() if isinstance(value, Responder))


def a_docker_whose_gitlab_comes_up(monkeypatch: pytest.MonkeyPatch) -> ScriptedDocker:
    return _a_docker(monkeypatch, RECONFIGURED)


def a_docker_whose_gitlab_fails_to_reconfigure(
    monkeypatch: pytest.MonkeyPatch,
) -> ScriptedDocker:
    return _a_docker(monkeypatch, RECONFIGURE_FAILED)


def _a_docker(monkeypatch: pytest.MonkeyPatch, logs: str) -> ScriptedDocker:
    answers = {
        ("network", "inspect"): CLOSED_NETWORK_INSPECT,
        ("logs",): logs,
        ("inspect",): "running\n",
    }
    return ScriptedDocker(answers).installed(monkeypatch)
