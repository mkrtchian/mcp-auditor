import importlib
import re
import threading
from collections.abc import Sequence
from dataclasses import replace

import pytest

import tests.unit.support.test_nuisance_admission_given as admission_given
from evals import nuisance_provisioners
from evals.backend_lifecycle import BackendLifecycle
from evals.cve_planting_base import PlantingHost, SymbolicUser
from evals.holdout_kit.kit_backend_launch import lifecycle_of
from evals.nuisance_admission import AdmittedServer, BackendFixture
from evals.nuisance_backends import BACKENDS
from evals.responder_backend import Responder


def a_host() -> PlantingHost:
    return PlantingHost(SymbolicUser.UNPRIVILEGED, "/srv", has_network=False)


def every_responder() -> list[Responder]:
    modules = (importlib.import_module(f"evals.{key}_backend") for key in BACKENDS)
    return [
        value
        for module in modules
        for value in vars(module).values()
        if isinstance(value, Responder)
    ]


def a_server_with_backend(key: str) -> AdmittedServer:
    registered = BACKENDS[key]
    backend = BackendFixture(provisioner=key, image=registered.image, network=registered.network)
    return admission_given.with_a_backend(admission_given.an_admission().servers[0], backend)


def a_lifecycle_without_side_effects(key: str, monkeypatch: pytest.MonkeyPatch) -> BackendLifecycle:
    """The key's lifecycle with no-op ensure and remove, the provisioner's own ensure and remove
    replaced by the same no-ops, so both launches build their argv and touch no Docker."""
    lifecycle = lifecycle_of(key)
    monkeypatch.setattr(nuisance_provisioners, lifecycle.ensure.__name__, _noop_ensure)
    monkeypatch.setattr(nuisance_provisioners, lifecycle.remove.__name__, _noop_remove)
    return replace(lifecycle, ensure=_noop_ensure, remove=_noop_remove)


def _noop_ensure() -> None:
    pass


def _noop_remove(name: str) -> None:
    pass


def with_the_name_masked(args: Sequence[str]) -> list[str]:
    masked = list(args)
    position = masked.index("--name") + 1
    masked[position] = re.sub(r"[0-9a-f]{32}$", "<uuid>", masked[position])
    return masked


def name_of(args: Sequence[str]) -> str:
    return args[list(args).index("--name") + 1]


class RecordingLifecycle:
    def __init__(self) -> None:
        self.events: list[str] = []
        self.lifecycle = BackendLifecycle(
            "fake", threading.Lock(), self._ensure, _named_server_args, self._remove
        )

    def _ensure(self) -> None:
        self.events.append("ensure")

    def _remove(self, name: str) -> None:
        self.events.append(f"remove {name}")


def _named_server_args(
    name: str, image: str, host: PlantingHost, server_launch: Sequence[str]
) -> list[str]:
    return ["run", "--name", name, image, *server_launch]
