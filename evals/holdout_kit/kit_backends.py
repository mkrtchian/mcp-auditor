"""Kit builders for a backend a fix check brings up.

Copied into a dossier only for a server admitted with that backend, so a blind agent that does not
admit the backend never receives its lifecycle. Each builder ensures the persistent cluster is
query-ready, stands the fix check's own sentinels, and yields the server launch wired to the
backend's network, exactly as the acceptance environment does, but wrapping the kit-local
`Launch`.
"""

import time
from collections.abc import Generator
from contextlib import contextmanager
from uuid import uuid4

from evals.cve_planting_base import LABEL, PlantingSpec
from evals.doris_backend import (
    DORIS_LAUNCH_LOCK,
    DORIS_SERVER_LAUNCH,
    doris_rm,
    doris_server_args,
    ensure_doris,
    start_doris_sentinel,
)
from evals.holdout_kit.kit_launch import Launch, LaunchShape


@contextmanager
def doris_backend_env(
    image: str, spec: PlantingSpec, shape: LaunchShape = LaunchShape.NORMAL
) -> Generator[Launch]:
    # The lock is held across the yield: the fix check's sentinels sit at fixed link-local IPs,
    # so concurrent exercises that share them must not reap each other's. No /srv layout, as the
    # holdout env: every kept place is reached from the backend, not the server container.
    with DORIS_LAUNCH_LOCK:
        ensure_doris()
        server = f"{LABEL}-doris-server-{uuid4().hex}"
        sentinels: list[str] = []
        try:
            for sentinel in spec.sentinels:
                sentinels.append(start_doris_sentinel(sentinel))
            time.sleep(2)  # let each sentinel's httpd bind before the server can drive a fetch
            yield Launch(
                command="docker",
                args=doris_server_args(server, image, spec.host, DORIS_SERVER_LAUNCH),
            )
        finally:
            doris_rm(server)
            for name in sentinels:
                doris_rm(name)
