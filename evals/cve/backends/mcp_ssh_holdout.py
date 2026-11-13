"""The detection builder of CVE-2025-9654: the server launch of `command_injection_env`, with an
sshd of `evals.cve.backends.mcp_ssh_sshd` stood for the launch at the README's
`prod.example.com`, so the server's ssh and scp reach a real OpenSSH server as its documentation
sets one up.

It lives apart from `mcp_ssh_sshd.py` because it plants through `evals.cve.environments`, which
imports `mcp_auditor`, while the re-admission dossier copies the import closure of
`mcp_ssh_sshd.py`.

The sshd runs in its own network namespace, never in the namespace holder, whose loopback carries
the target's sentinels: a remote shell there would read them. It is stood before the planting, so
the holder is removed before the sshd's network, which Docker refuses to remove while a container
is attached to it. When the launch has a holder, the holder joins the sshd's network and the
server reaches the sshd through the holder's namespace. When it has none, the sshd's network is
the server's second network. The known_hosts is root-owned, since the launch runs the server under
an account named after a nonce and the layout check's reference arm under 65534.
"""

import secrets
from collections.abc import Callable, Generator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass

from evals.cve.backends.mcp_ssh_sshd import ROOT, StoodSshd, connect_to_network, stood_sshd
from evals.cve.environments import Launch, LaunchShape, materialise
from evals.cve.layout import layout_mount_args, owned_layout
from evals.cve.planting import PlantingDocker, PlantingSpec, confinement_args, planted
from evals.cve.planting_base import LABEL
from evals.cve.planting_docker import DOCKER_PLANTING

_HOLDER_PREFIX = "container:"


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
    with (
        owned_layout(docker, lambda root: materialise(root, spec, shape)) as root,
        sshd.stand(name, ROOT) as stood,
        planted(spec, image, docker) as args,
    ):
        holder = _holder(args.network)
        if holder is not None:
            sshd.connect(stood.network, holder)
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
