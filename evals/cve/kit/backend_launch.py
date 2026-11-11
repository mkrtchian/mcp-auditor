"""The server launch of a nuisance server with a backend, from that backend's lifecycle record.

Parity note: it mirrors evals/cve/nuisance/provisioners.py, whose provisioners build the same argv
from the same backend functions. A test pins every registered backend's launch here equal to its
provisioner's. The backend containers `ensure` brings up are shared and persistent: they serve every
launch and stay running once the launch ends, only the server container is removed.
"""

import importlib
from collections.abc import Generator, Sequence
from contextlib import contextmanager
from uuid import uuid4

from evals.backend_lifecycle import BackendLifecycle
from evals.cve.kit.launch import Launch
from evals.cve_planting_base import LABEL, PlantingHost


def lifecycle_of(key: str) -> BackendLifecycle:
    try:
        return importlib.import_module(f"evals.{key}_backend").LIFECYCLE
    except (ModuleNotFoundError, AttributeError) as error:
        raise ValueError(f"no backend lifecycle for the key {key!r}") from error


@contextmanager
def backend_launch(
    lifecycle: BackendLifecycle, image: str, host: PlantingHost, server_launch: Sequence[str]
) -> Generator[Launch]:
    # The lock serialises only the backend stand-up, not the yield, as the provisioners do.
    with lifecycle.lock:
        lifecycle.ensure()
    name = f"{LABEL}-{lifecycle.key}-server-{uuid4().hex}"
    try:
        yield Launch(command="docker", args=lifecycle.server_args(name, image, host, server_launch))
    finally:
        lifecycle.remove(name)
