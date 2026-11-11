import importlib
import re
import threading
from collections.abc import Callable, Sequence
from contextlib import AbstractContextManager
from dataclasses import replace

import tests.unit.support.test_nuisance_admission_given as admission_given
from evals import cve_environments
from evals.backend_lifecycle import BackendLifecycle
from evals.cve.kit import launch as kit_launch
from evals.cve.kit.backend_launch import backend_launch, lifecycle_of
from evals.cve_planting_base import PlantingHost, SymbolicUser
from evals.nuisance_backends import BACKENDS
from evals.nuisance_provisioners import provisioner_of
from evals.responder_backend import Responder

type Launch = cve_environments.Launch | kit_launch.Launch
type Launcher = Callable[[BackendLifecycle], AbstractContextManager[Launch]]


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


def a_lifecycle_without_side_effects(key: str) -> BackendLifecycle:
    return replace(lifecycle_of(key), ensure=_noop_ensure, remove=_noop_remove)


def _noop_ensure() -> None:
    pass


def _noop_remove(name: str) -> None:
    pass


def through_the_provisioner(lifecycle: BackendLifecycle) -> AbstractContextManager[Launch]:
    return provisioner_of(lifecycle)(admission_given.an_admitted_server())


def through_the_kit(lifecycle: BackendLifecycle) -> AbstractContextManager[Launch]:
    return backend_launch(lifecycle, "image", a_host(), ["serve"])


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
