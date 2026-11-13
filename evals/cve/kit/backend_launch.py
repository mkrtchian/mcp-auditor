"""The server launch of a nuisance server with a backend, from that backend's lifecycle record.

Parity note: it mirrors evals/cve/nuisance/provisioners.py, whose provisioners build the same argv
from the same backend functions. A test pins every registered backend's launch here equal to its
provisioner's. A shared backend's containers, which `ensure` brings up, serve every launch and
stay running once the launch ends, only the server container is removed. A per-launch backend is
stood for this launch alone and removed with its server.
"""

import importlib
from collections.abc import Generator, Sequence
from contextlib import contextmanager
from uuid import uuid4

from evals.cve.backends.lifecycle import BackendLifecycle, PerLaunchBackend, launched_server_args
from evals.cve.kit.launch import Launch
from evals.cve.planting_base import LABEL, PlantingHost


def lifecycle_of(key: str) -> BackendLifecycle | PerLaunchBackend:
    try:
        lifecycle = importlib.import_module(f"evals.cve.backends.{key}").LIFECYCLE
    except (ModuleNotFoundError, AttributeError) as error:
        raise ValueError(f"no backend lifecycle for the key {key!r}") from error
    match lifecycle:
        case BackendLifecycle() | PerLaunchBackend():
            return lifecycle
        case _:
            raise ValueError(f"the LIFECYCLE of the key {key!r} is no backend lifecycle")


@contextmanager
def backend_launch(
    lifecycle: BackendLifecycle | PerLaunchBackend,
    image: str,
    host: PlantingHost,
    server_launch: Sequence[str],
) -> Generator[Launch]:
    name = f"{LABEL}-{lifecycle.key}-server-{uuid4().hex}"
    with launched_server_args(lifecycle)(name, image, host, server_launch) as args:
        yield Launch(command="docker", args=args)
