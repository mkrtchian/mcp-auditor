import importlib
import re
import threading
from collections.abc import Callable, Generator, Sequence
from contextlib import AbstractContextManager, contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import tests.unit.support.test_nuisance_admission_given as admission_given
from evals.cve import environments
from evals.cve.backends import gitlab, gitlab_responder, kubernetes, node_sandbox_engine
from evals.cve.backends.lifecycle import BackendLifecycle, PerLaunchBackend
from evals.cve.backends.responder import Responder
from evals.cve.kit import launch as kit_launch
from evals.cve.kit.backend_launch import backend_launch, lifecycle_of
from evals.cve.nuisance.backend_registry import BACKENDS
from evals.cve.nuisance.provisioners import provisioner_of
from evals.cve.planting_base import PlantingHost, SymbolicUser

type Launch = environments.Launch | kit_launch.Launch
type Launcher = Callable[[BackendLifecycle | PerLaunchBackend], AbstractContextManager[Launch]]


def a_host() -> PlantingHost:
    return PlantingHost(SymbolicUser.UNPRIVILEGED, "/srv", has_network=False)


def every_responder() -> list[Responder]:
    # The GitLab responder serves a fix check, not a registered backend.
    names = [*(f"evals.cve.backends.{key}" for key in BACKENDS), gitlab_responder.__name__]
    modules = (importlib.import_module(name) for name in names)
    return [
        value
        for module in modules
        for value in vars(module).values()
        if isinstance(value, Responder)
    ]


def shared_keys() -> list[str]:
    return sorted(
        key for key, entry in BACKENDS.items() if isinstance(entry.lifecycle, BackendLifecycle)
    )


def shared_lifecycle_of(key: str) -> BackendLifecycle:
    lifecycle = lifecycle_of(key)
    assert isinstance(lifecycle, BackendLifecycle), f"{key} is a per-launch backend"
    return lifecycle


def a_lifecycle_without_side_effects(key: str) -> BackendLifecycle | PerLaunchBackend:
    match lifecycle_of(key):
        case BackendLifecycle() as shared:
            return replace(shared, ensure=_noop_ensure, remove=_noop_remove)
        case PerLaunchBackend():
            return _a_quiet_per_launch_backend(key)


@contextmanager
def _a_socket_with_no_engine(name: str) -> Generator[Path]:
    yield Path("/tmp/engine-socket-directory/docker.sock")


@contextmanager
def _a_gitlab_with_no_container(name: str) -> Generator[gitlab.StoodGitLab]:
    yield gitlab.StoodGitLab(f"{gitlab.GITLAB_NETWORK}-quiet", "token-of-the-stand-up")


@contextmanager
def _a_control_plane_with_no_container(
    name: str, memory_bound: Sequence[str]
) -> Generator[kubernetes.StoodControlPlane]:
    yield kubernetes.StoodControlPlane(
        f"{kubernetes.CONTROL_PLANE_NETWORK}-quiet", Path("/tmp/kubeconfig-directory/config")
    )


def _a_quiet_per_launch_backend(key: str) -> PerLaunchBackend:
    # Each per-launch backend's own launch, with a stand-up that starts no container.
    match key:
        case "node_sandbox_engine":
            launch = node_sandbox_engine.engine_launch(_a_socket_with_no_engine, _noop_remove)
        case "gitlab":
            launch = gitlab.gitlab_launch(_a_gitlab_with_no_container, _noop_remove)
        case "kubernetes":
            launch = kubernetes.control_plane_launch(
                _a_control_plane_with_no_container, _noop_remove
            )
        case _:
            raise AssertionError(f"give the per-launch backend {key} a quiet stand-up here")
    return PerLaunchBackend(key, launch)


def a_module_whose_lifecycle_is_neither_kind(name: str) -> SimpleNamespace:
    return SimpleNamespace(LIFECYCLE=object())


def _noop_ensure() -> None:
    pass


def _noop_remove(name: str) -> None:
    pass


def through_the_provisioner(
    lifecycle: BackendLifecycle | PerLaunchBackend,
) -> AbstractContextManager[Launch]:
    return provisioner_of(lifecycle)(admission_given.an_admitted_server())


def through_the_kit(
    lifecycle: BackendLifecycle | PerLaunchBackend,
) -> AbstractContextManager[Launch]:
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


class RecordingPerLaunchBackend:
    """Stands one backend per launch, numbered in order, and yields server arguments carrying
    that number, as a stand-up yields a value only it knows."""

    def __init__(self) -> None:
        self.events: list[str] = []
        self.backend = PerLaunchBackend("fake_per_launch", self._launch)

    @contextmanager
    def _launch(
        self, name: str, image: str, host: PlantingHost, server_launch: Sequence[str]
    ) -> Generator[list[str]]:
        stood = sum(event.startswith("stand") for event in self.events)
        self.events.append(f"stand {name}")
        try:
            yield ["run", "--name", name, "-e", f"TOKEN=token-{stood}", image, *server_launch]
        finally:
            self.events.append(f"remove {name}")
