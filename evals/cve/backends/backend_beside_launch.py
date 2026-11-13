"""The launch of a detection builder whose backend runs in its own network namespace, never in the
namespace holder, whose loopback carries the target's sentinels: the server launch of
`command_injection_env`, with the backend stood for the launch.

It lives apart from the backend modules because it plants through `evals.cve.environments`, which
imports `mcp_auditor`, while the dossiers copy the import closure of those modules.

The backend is stood before the planting, so the planting's holder is removed before the backend's
network, which Docker refuses to remove while a container is attached to it. When the launch has a
namespace holder, the holder joins the backend's network and the server reaches the backend through
the holder's namespace. When it has none, the backend's network is the server's second network.
"""

from collections.abc import Callable, Generator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from typing import Protocol

from evals.cve.environments import Launch, LaunchShape, materialise
from evals.cve.layout import layout_mount_args, owned_layout
from evals.cve.planting import PlantingDocker, PlantingSpec, confinement_args, planted

_HOLDER_PREFIX = "container:"


class StoodBackend(Protocol):
    @property
    def network(self) -> str: ...

    def mount_args(self) -> list[str]: ...


@dataclass(frozen=True)
class BackendStand:
    stand: Callable[[], AbstractContextManager[StoodBackend]]
    connect: Callable[[str, str], None]  # (network, container)


@contextmanager
def launch_beside_backend(
    image: str,
    spec: PlantingSpec,
    shape: LaunchShape,
    *,
    docker: PlantingDocker,
    backend: BackendStand,
) -> Generator[Launch]:
    with (
        owned_layout(docker, lambda root: materialise(root, spec, shape)) as root,
        backend.stand() as stood,
        planted(spec, image, docker) as args,
    ):
        holder = _holder(args.network)
        if holder is not None:
            backend.connect(stood.network, holder)
        second_network = () if holder is not None else ("--network", stood.network)
        yield Launch(
            command="docker",
            args=[
                "run",
                "-i",
                "--rm",
                *confinement_args(),
                *args.run_args(),
                *second_network,
                *stood.mount_args(),
                *layout_mount_args(root, spec.host.layout_mount),
                image,
            ],
        )


def _holder(network: tuple[str, ...]) -> str | None:
    if len(network) >= 2 and network[0] == "--network" and network[1].startswith(_HOLDER_PREFIX):
        return network[1].removeprefix(_HOLDER_PREFIX)
    return None
