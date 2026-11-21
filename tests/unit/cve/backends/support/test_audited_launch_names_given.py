from collections.abc import Callable, Sequence
from pathlib import Path

from evals.cve.backends import gitlab, node_sandbox_engine
from evals.cve.backends import kubernetes as kubernetes_backend
from evals.cve.backends.facebook_ads import FACEBOOK_ADS_RESPONDER
from evals.cve.backends.gitlab import StoodGitLab
from evals.cve.backends.kubernetes import StoodControlPlane
from evals.cve.backends.lifecycle import BackendLifecycle
from evals.cve.nuisance.backend_registry import BACKENDS
from evals.cve.planting_base import PlantingHost, SymbolicUser

SERVER = "server-name"
_IMAGE = "img"
_HOST = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=True)
_LAUNCH = ("serve",)

type ServerArgs = Callable[[str, str, PlantingHost, Sequence[str]], list[str]]


def named_server_args() -> dict[str, ServerArgs]:
    """Every function that returns, for a server it names, the run argv of a nuisance server
    beside its backend: each shared backend's `server_args`, the responders' method, and each
    per-launch backend's `server_run_args` with its backend stood."""
    shared = {
        key: entry.lifecycle.server_args
        for key, entry in BACKENDS.items()
        if isinstance(entry.lifecycle, BackendLifecycle)
    }
    return {
        **shared,
        "Responder.server_args": FACEBOOK_ADS_RESPONDER.server_args,
        "kubernetes server_run_args": _with_a_control_plane,
        "gitlab server_run_args": _with_a_gitlab,
        "node_sandbox_engine server_run_args": _with_an_engine,
    }


def run_args_of(server_args: ServerArgs) -> list[str]:
    return server_args(SERVER, _IMAGE, _HOST, _LAUNCH)


def _with_a_control_plane(
    name: str, image: str, host: PlantingHost, launch: Sequence[str]
) -> list[str]:
    stood = StoodControlPlane("kube-net", Path("/tmp/admin.conf"))
    return kubernetes_backend.server_run_args(name, image, host, launch, stood)


def _with_a_gitlab(name: str, image: str, host: PlantingHost, launch: Sequence[str]) -> list[str]:
    return gitlab.server_run_args(name, image, host, launch, StoodGitLab("gitlab-net", "token"))


def _with_an_engine(name: str, image: str, host: PlantingHost, launch: Sequence[str]) -> list[str]:
    return node_sandbox_engine.server_run_args(name, image, host, launch, Path("/tmp/engine.sock"))
