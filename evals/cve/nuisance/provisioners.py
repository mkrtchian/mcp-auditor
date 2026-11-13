"""The provisioner of a registered nuisance backend, built from its lifecycle.

It brings the backend up (a shared backend ensured once, a per-launch backend stood for this
launch alone), yields the server `Launch` wired to it, and reaps the server, and a per-launch
backend with it, when the launch ends. `backend_registry` registers the lifecycles under their
fixture keys.
"""

from __future__ import annotations

from collections.abc import Callable, Generator
from contextlib import AbstractContextManager, contextmanager
from typing import TYPE_CHECKING
from uuid import uuid4

from evals.cve.backends.lifecycle import launched_server_args
from evals.cve.environments import Launch
from evals.cve.nuisance.images import image_tag
from evals.cve.planting_base import LABEL

if TYPE_CHECKING:
    from evals.cve.backends.lifecycle import BackendLifecycle, PerLaunchBackend
    from evals.cve.nuisance.admission import AdmittedServer

type BackendProvisioner = Callable[[AdmittedServer], AbstractContextManager[Launch]]


def provisioner_of(lifecycle: BackendLifecycle | PerLaunchBackend) -> BackendProvisioner:
    launched = launched_server_args(lifecycle)

    @contextmanager
    def provisioner(server: AdmittedServer) -> Generator[Launch]:
        name = f"{LABEL}-{lifecycle.key}-server-{uuid4().hex}"
        image = image_tag(server.service)
        with launched(name, image, server.host, server.launch) as args:
            yield Launch(command="docker", args=args)

    return provisioner
