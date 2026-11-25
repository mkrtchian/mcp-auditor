import threading
from collections.abc import Callable, Generator, Sequence
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from types import ModuleType

import tests.unit.support.nuisance_admissions as admissions
from evals.cve import environments
from evals.cve.backends import (
    ckan,
    doris,
    gitlab,
    gravitino,
    httpbin,
    jenkins,
    kubernetes,
    mcp_ssh_sshd,
    n8n,
    node_sandbox_engine,
    searxng,
)
from evals.cve.backends.lifecycle import BackendLifecycle, PerLaunchBackend
from evals.cve.kit import launch as kit_launch
from evals.cve.kit.backend_launch import backend_launch, lifecycle_of
from evals.cve.nuisance.admission.admission import AdmittedServer
from evals.cve.nuisance.backend_registry import BACKENDS
from evals.cve.nuisance.provisioners import provisioned_launch
from evals.cve.planting_base import PlantingHost, SymbolicUser

type Launch = environments.Launch | kit_launch.Launch
type Launcher = Callable[[BackendLifecycle | PerLaunchBackend], AbstractContextManager[Launch]]


@dataclass(frozen=True)
class BackendContainer:
    argv: list[str]
    confined: bool = True  # carries confinement_args() and adds no capability
    resolver_options: int = 1
    reason: str = ""  # why the container departs from the rule, when it does


def every_backend_container_argv() -> dict[str, BackendContainer]:
    parts = (*ckan.CKAN_PARTS, *gravitino.GRAVITINO_PARTS, *httpbin.HTTPBIN_PARTS)
    return {
        "doris cluster": BackendContainer(
            doris.doris_cluster_run_args(),
            confined=False,
            reason="no hardened options were measured for the all-in-one cluster's start",
        ),
        **{part.container: BackendContainer(part.run_args()) for part in parts},
        "mcp-ssh sshd": BackendContainer(mcp_ssh_sshd.singleton_run_args()),
        "mcp-ssh per-launch sshd": BackendContainer(mcp_ssh_sshd.sshd_args("sshd", "network")),
        "jenkins controller": BackendContainer(jenkins.singleton_run_args()),
        "n8n instance": BackendContainer(n8n.singleton_run_args()),
        "gitlab": BackendContainer(
            gitlab.gitlab_run_args("gitlab", "network"),
            confined=False,
            reason="GitLab CE carries its own hardening, with the capabilities and the process "
            "bound its Omnibus start needs",
        ),
        "kubernetes control plane": BackendContainer(
            kubernetes.control_plane_run_args("control-plane", "network")
        ),
        "node sandbox engine": BackendContainer(
            node_sandbox_engine.engine_run_args("engine", Path("/tmp/engine-socket-directory"))
        ),
        # Production always passes the holder join: the searxng target declares a stand-in.
        "searxng": BackendContainer(
            searxng.searxng_args("searxng", ["--network", "container:holder"]),
            confined=False,
            resolver_options=0,
            reason="SearXNG carries its own hardening and process bound, and joins the holder's "
            "network namespace, whose resolv.conf it reads",
        ),
    }


def shared_keys() -> list[str]:
    return sorted(
        key for key, entry in BACKENDS.items() if isinstance(entry.lifecycle, BackendLifecycle)
    )


def shared_lifecycle_of(key: str) -> BackendLifecycle:
    lifecycle = lifecycle_of(key)
    assert isinstance(lifecycle, BackendLifecycle), f"{key} is a per-launch backend"
    return lifecycle


def a_module_whose_lifecycle_is_neither_kind(name: str) -> ModuleType:
    module = ModuleType(name)
    module.__dict__["LIFECYCLE"] = object()
    return module


def through_the_provisioner(
    lifecycle: BackendLifecycle | PerLaunchBackend,
) -> AbstractContextManager[Launch]:
    return provisioned_launch(lifecycle, admissions.an_admitted_server())


def an_admitted_server_with_a_distinctive_host() -> AdmittedServer:
    admitted = admissions.an_admitted_server()
    return admitted.model_copy(
        update={"host": replace(admitted.host, working_directory="/srv/app", has_network=True)}
    )


def through_the_kit(
    lifecycle: BackendLifecycle | PerLaunchBackend,
) -> AbstractContextManager[Launch]:
    return backend_launch(lifecycle, "image", a_host(), ["serve"])


def a_host() -> PlantingHost:
    return PlantingHost(SymbolicUser.UNPRIVILEGED, "/srv", has_network=False)


def name_of(args: Sequence[str]) -> str:
    return args[list(args).index("--name") + 1]


class RecordingLifecycle:
    def __init__(self) -> None:
        self.events: list[str] = []
        self.launched_servers: list[tuple[str, PlantingHost, list[str]]] = []
        self.lifecycle = BackendLifecycle(
            "fake", threading.Lock(), self._ensure, self._server_args, self._remove
        )

    def _server_args(
        self, name: str, image: str, host: PlantingHost, server_launch: Sequence[str]
    ) -> list[str]:
        self.launched_servers.append((image, host, list(server_launch)))
        return ["run", "--name", name, image, *server_launch]

    def _ensure(self) -> None:
        self.events.append("ensure")

    def _remove(self, name: str) -> None:
        self.events.append(f"remove {name}")


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
