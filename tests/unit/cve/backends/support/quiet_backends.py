"""Every registered backend's lifecycle with a stand-up that starts no container."""

from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

from evals.cve.backends import gitlab, kubernetes, node_sandbox_engine
from evals.cve.backends.lifecycle import BackendLifecycle, PerLaunchBackend
from evals.cve.kit.backend_launch import lifecycle_of


def a_lifecycle_without_side_effects(key: str) -> BackendLifecycle | PerLaunchBackend:
    match lifecycle_of(key):
        case BackendLifecycle() as shared:
            return replace(shared, ensure=_noop_ensure, remove=_noop_remove)
        case PerLaunchBackend():
            return _a_quiet_per_launch_backend(key)


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


@contextmanager
def _a_socket_with_no_engine(name: str) -> Generator[Path]:
    yield Path("/tmp/engine-socket-directory/docker.sock")


@contextmanager
def _a_gitlab_with_no_container(name: str) -> Generator[gitlab.StoodGitLab]:
    yield gitlab.StoodGitLab(f"{gitlab.GITLAB_NETWORK}-quiet", "token-of-the-stand-up")


@contextmanager
def _a_control_plane_with_no_container(name: str) -> Generator[kubernetes.StoodControlPlane]:
    yield kubernetes.StoodControlPlane(
        f"{kubernetes.CONTROL_PLANE_NETWORK}-quiet", Path("/tmp/kubeconfig-directory/config")
    )


def _noop_ensure() -> None:
    pass


def _noop_remove(name: str) -> None:
    pass
