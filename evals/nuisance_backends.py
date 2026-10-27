"""The registry of the backends a nuisance fixture can provision, each a named lifecycle the
holdout already drives.

A server records a `BackendFixture` naming one of these keys; the provisioner ensures the
backend is up and query-ready and yields the server `Launch` wired to it, as `doris_db_env`
does for the holdout. `backend_problems` is the load check that a recorded fixture matches the
backend its key defines.
"""

from __future__ import annotations

from collections.abc import Callable, Generator, Mapping
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING
from uuid import uuid4

from evals.ckan_backend import (
    CKAN_BRIDGE,
    CKAN_LAUNCH_LOCK,
    CKAN_RESPONDER_IMAGE,
    ckan_rm,
    ckan_server_args,
    ensure_ckan_responder,
)
from evals.contextforge_backend import (
    CONTEXTFORGE_BRIDGE,
    CONTEXTFORGE_LAUNCH_LOCK,
    CONTEXTFORGE_RESPONDER_IMAGE,
    contextforge_rm,
    contextforge_server_args,
    ensure_contextforge_responder,
)
from evals.cve_environments import Launch
from evals.cve_planting_base import LABEL
from evals.doris_backend import (
    DORIS_BRIDGE,
    DORIS_IMAGE,
    DORIS_LAUNCH_LOCK,
    doris_rm,
    doris_server_args,
    ensure_doris,
)
from evals.nuisance_images import image_tag

if TYPE_CHECKING:
    from evals.nuisance_admission import AdmittedServer

type BackendProvisioner = Callable[[AdmittedServer], AbstractContextManager[Launch]]


@dataclass(frozen=True)
class RegisteredBackend:
    provisioner: BackendProvisioner
    network: str
    image: str


@contextmanager
def doris_provisioner(server: AdmittedServer) -> Generator[Launch]:
    # The nuisance run stands no sentinel, so the lock is not held across the yield: a server's
    # concurrent runs share the one cluster that serves them all.
    with DORIS_LAUNCH_LOCK:
        ensure_doris()
    name = f"{LABEL}-doris-server-{uuid4().hex}"
    try:
        yield Launch(
            command="docker",
            args=doris_server_args(name, image_tag(server.service), server.host, server.launch),
        )
    finally:
        doris_rm(name)


@contextmanager
def ckan_provisioner(server: AdmittedServer) -> Generator[Launch]:
    # The nuisance run stands no sentinel, so the lock serialises only the responder stand-up,
    # not the yield: a server's concurrent runs share the one responder that serves them all.
    with CKAN_LAUNCH_LOCK:
        ensure_ckan_responder()
    name = f"{LABEL}-ckan-server-{uuid4().hex}"
    try:
        yield Launch(
            command="docker",
            args=ckan_server_args(name, image_tag(server.service), server.host, server.launch),
        )
    finally:
        ckan_rm(name)


@contextmanager
def contextforge_provisioner(server: AdmittedServer) -> Generator[Launch]:
    # The nuisance run stands no sentinel, so the lock serialises only the responder stand-up,
    # not the yield: a server's concurrent runs share the one responder that serves them all.
    with CONTEXTFORGE_LAUNCH_LOCK:
        ensure_contextforge_responder()
    name = f"{LABEL}-contextforge-server-{uuid4().hex}"
    try:
        yield Launch(
            command="docker",
            args=contextforge_server_args(
                name, image_tag(server.service), server.host, server.launch
            ),
        )
    finally:
        contextforge_rm(name)


BACKENDS: dict[str, RegisteredBackend] = {
    "doris": RegisteredBackend(doris_provisioner, DORIS_BRIDGE, DORIS_IMAGE),
    "ckan": RegisteredBackend(ckan_provisioner, CKAN_BRIDGE, CKAN_RESPONDER_IMAGE),
    "contextforge": RegisteredBackend(
        contextforge_provisioner, CONTEXTFORGE_BRIDGE, CONTEXTFORGE_RESPONDER_IMAGE
    ),
}


def backend_problems(
    server: AdmittedServer, backends: Mapping[str, RegisteredBackend]
) -> list[str]:
    if server.backend is None:
        return []
    key = server.backend.provisioner
    entry = backends.get(key)
    if entry is None:
        return [f"{server.server_package}: backend provisioner {key!r} is not registered"]
    expected = {"provisioner": key, "image": entry.image, "network": entry.network}
    if server.backend.model_dump() != expected:
        return [
            f"{server.server_package}: backend fixture {server.backend.model_dump()} "
            f"is not the registered {expected}"
        ]
    return []
