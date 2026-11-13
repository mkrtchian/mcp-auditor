"""The detection builder of CVE-2025-9654: the launch of `launch_beside_backend`, with an sshd of
`evals.cve.backends.mcp_ssh_sshd` as its backend at the README's `prod.example.com`, so the
server's ssh and scp reach a real OpenSSH server as its documentation sets one up.

It lives apart from `mcp_ssh_sshd.py` because it plants through `evals.cve.environments`, which
imports `mcp_auditor`, while the re-admission dossier copies the import closure of
`mcp_ssh_sshd.py`.

The sshd stays out of the namespace holder since a remote shell there would read the target's
sentinels. The known_hosts is root-owned, since the launch runs the server under an account named
after a nonce and the layout check's reference arm under 65534.
"""

import secrets
from collections.abc import Callable, Generator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass

from evals.cve.backends.backend_beside_launch import BackendStand, launch_beside_backend
from evals.cve.backends.mcp_ssh_sshd import ROOT, StoodSshd, connect_to_network, stood_sshd
from evals.cve.environments import Launch, LaunchShape
from evals.cve.planting import PlantingDocker, PlantingSpec
from evals.cve.planting_base import LABEL
from evals.cve.planting_docker import DOCKER_PLANTING


@dataclass(frozen=True)
class SshdDocker:
    stand: Callable[[str, str], AbstractContextManager[StoodSshd]]  # (name, known_hosts owner)
    connect: Callable[[str, str], None]  # (network, container)


DOCKER_SSHD = SshdDocker(stood_sshd, connect_to_network)


@contextmanager
def mcp_ssh_injection_env(
    image: str,
    spec: PlantingSpec,
    shape: LaunchShape = LaunchShape.NORMAL,
    *,
    docker: PlantingDocker = DOCKER_PLANTING,
    sshd: SshdDocker = DOCKER_SSHD,
) -> Generator[Launch]:
    if not spec.host.has_network:
        # Docker connects no network to a container on `none`, the holder's or the server's.
        raise ValueError("the mcp-ssh target's planting host needs has_network=True")
    name = f"{LABEL}-mcp-ssh-sshd-{secrets.token_hex(6)}"
    backend = BackendStand(lambda: sshd.stand(name, ROOT), sshd.connect)
    with launch_beside_backend(image, spec, shape, docker=docker, backend=backend) as launch:
        yield launch
