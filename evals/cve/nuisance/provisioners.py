"""The provisioner of a registered nuisance backend, built from its lifecycle.

It ensures the backend is up and query-ready, yields the server `Launch` wired to it, and reaps
the server when the launch ends. `backend_registry` registers the lifecycles under their fixture
keys.
"""

from __future__ import annotations

from collections.abc import Callable, Generator
from contextlib import AbstractContextManager, contextmanager
from typing import TYPE_CHECKING
from uuid import uuid4

from evals.cve.environments import Launch
from evals.cve.nuisance.images import image_tag
from evals.cve.planting_base import LABEL

if TYPE_CHECKING:
    from evals.cve.backends.lifecycle import BackendLifecycle
    from evals.cve.nuisance.admission import AdmittedServer

type BackendProvisioner = Callable[[AdmittedServer], AbstractContextManager[Launch]]


def provisioner_of(lifecycle: BackendLifecycle) -> BackendProvisioner:
    @contextmanager
    def provisioner(server: AdmittedServer) -> Generator[Launch]:
        # The nuisance run plants nothing, so the lock serialises only the backend stand-up, not
        # the yield: a server's concurrent runs share the one backend that serves them all.
        with lifecycle.lock:
            lifecycle.ensure()
        name = f"{LABEL}-{lifecycle.key}-server-{uuid4().hex}"
        image = image_tag(server.service)
        try:
            yield Launch(
                command="docker",
                args=lifecycle.server_args(name, image, server.host, server.launch),
            )
        finally:
            lifecycle.remove(name)

    return provisioner
