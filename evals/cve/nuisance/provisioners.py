"""The provisioner of a registered nuisance backend, run from its lifecycle.

It brings the backend up (a shared backend ensured once, a per-launch backend stood for this
launch alone), yields the server `Launch` wired to it, and reaps the server, and a per-launch
backend with it, when the launch ends. `backend_registry` registers the lifecycles under their
fixture keys.
"""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from typing import TYPE_CHECKING

from evals.cve.environments import Launch
from evals.cve.kit.backend_launch import backend_launch
from evals.cve.nuisance.images import image_tag

if TYPE_CHECKING:
    from evals.cve.backends.lifecycle import BackendLifecycle, PerLaunchBackend
    from evals.cve.nuisance.admission.admission import AdmittedServer


@contextmanager
def provisioned_launch(
    lifecycle: BackendLifecycle | PerLaunchBackend, server: AdmittedServer
) -> Generator[Launch]:
    with backend_launch(lifecycle, image_tag(server.service), server.host, server.launch) as kit:
        yield Launch(command=kit.command, args=kit.args)
