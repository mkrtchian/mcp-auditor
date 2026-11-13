"""The detection builder of CVE-2026-33060: the server reaches the CKAN 2.12.1 stack of
`evals.cve.backends.ckan`, persistent and shared with the nuisance suite, under demo.ckan.org,
served by the stack's front with the fixture authority's leaf, as a deployment reaching that
portal would.

The target's kept places are link-local endpoints the server itself fetches, so the sentinels
stand on the static-IP link-local network of `evals.cve.backends.doris`, the server joins it as
its second network, and `planted()` is never called: its holder would carry the sentinels and the
public names together, and a backend host without a stand-in cannot be named through it. The two
holdout targets with link-local sentinels share that network and its addresses, so the sentinels
stand under `DORIS_LAUNCH_LOCK`, held across the yield. No part of the CKAN stack runs on that
network or in a namespace a sentinel shares: the stack sits on its own bridge, so nothing seeded
or served leads to a kept place.
"""

import time
from collections.abc import Callable, Generator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from uuid import uuid4

from evals.cve.backends.ckan import (
    CKAN_BRIDGE,
    CKAN_FRONT_IP,
    CKAN_LAUNCH_LOCK,
    ensure_ckan_backend,
    trust_args,
)
from evals.cve.backends.doris import (
    DORIS_LAUNCH_LOCK,
    LINK_LOCAL_NETWORK,
    doris_rm,
    ensure_link_local_network,
    start_doris_sentinel,
)
from evals.cve.environments import Launch, LaunchShape, materialise
from evals.cve.layout import layout_mount_args, owned_layout
from evals.cve.planting import PlantingDocker, PlantingSpec, confinement_args
from evals.cve.planting_base import (
    LABEL,
    SentinelIntent,
    own_network_args,
    unprivileged_user_args,
)
from evals.cve.planting_docker import DOCKER_PLANTING

PORTAL_NAME = "demo.ckan.org"


def _ensure_stack() -> None:
    # The stack is a singleton the nuisance suite stands under the same lock.
    with CKAN_LAUNCH_LOCK:
        ensure_ckan_backend()


@dataclass(frozen=True)
class CkanHoldoutDocker:
    ensure_stack: Callable[[], None]
    ensure_link_local_network: Callable[[], None]
    start_sentinel: Callable[[SentinelIntent], str]
    remove: Callable[[str], None]
    wait: Callable[[float], None] = field(default=time.sleep)


DOCKER_CKAN = CkanHoldoutDocker(
    _ensure_stack, ensure_link_local_network, start_doris_sentinel, doris_rm
)


@contextmanager
def ckan_ssrf_env(
    image: str,
    spec: PlantingSpec,
    shape: LaunchShape = LaunchShape.NORMAL,
    *,
    docker: PlantingDocker = DOCKER_PLANTING,
    ckan: CkanHoldoutDocker = DOCKER_CKAN,
) -> Generator[Launch]:
    ckan.ensure_stack()
    with (
        owned_layout(docker, lambda root: materialise(root, spec, shape)) as root,
        DORIS_LAUNCH_LOCK,
    ):
        ckan.ensure_link_local_network()
        server = f"{LABEL}-ckan-server-{uuid4().hex}"
        sentinels: list[str] = []
        try:
            for sentinel in spec.sentinels:
                sentinels.append(ckan.start_sentinel(sentinel))
            ckan.wait(2)  # let each sentinel's httpd bind before the server can drive a fetch
            yield Launch(command="docker", args=_server_args(server, image, spec, root))
        finally:
            ckan.remove(server)
            for name in sentinels:
                ckan.remove(name)


def _server_args(name: str, image: str, spec: PlantingSpec, root: Path) -> list[str]:
    return [
        "run", "-i", "--rm",
        *confinement_args(),
        "--name", name,
        "--label", LABEL,
        *own_network_args(CKAN_BRIDGE),
        "--network", LINK_LOCAL_NETWORK,
        "--add-host", f"{PORTAL_NAME}:{CKAN_FRONT_IP}",
        *trust_args(),
        *unprivileged_user_args(),
        "-w", spec.host.working_directory,
        *layout_mount_args(root, spec.host.layout_mount),
        image,
    ]  # fmt: skip
