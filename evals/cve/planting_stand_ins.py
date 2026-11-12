"""The stand-ins of a planted launch: a public name served under its real name inside the holder.

`with_stand_ins` loads the captures the planting host declares and pins each name to its
captured address on the holder, as a bound sentinel's literal is pinned. `serve_stand_ins`
starts one stand-in per name inside the holder, bound to that address, `trust_args` mounts the
fixture authority into the target for the declared trust settings, and `probe_stand_ins`
checks each stand-in listens by its name from a container started with the target's own
arguments. A host that declares no stand-in reads no file.
"""

from collections.abc import Sequence
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path

from evals.cve.planting_base import (
    STAND_IN_IMAGE,
    PlantingDocker,
    PlantingFailed,
    PlantingSpec,
    confinement_args,
    quiet,
)
from evals.cve.public_stand_ins import stand_in

_AUTHORITY_PATH = "/etc/ssl/extra-ca.pem"
_SERVED_PORTS = (80, 443)


def with_stand_ins(spec: PlantingSpec, directory: Path) -> PlantingSpec:
    loaded = tuple(stand_in(host, directory) for host in spec.host.public_names.stand_ins)
    if not loaded:
        return spec
    address_setups = list(spec.address_setups)
    for loaded_stand_in in loaded:
        if loaded_stand_in.address in address_setups:
            raise ValueError(f"{loaded_stand_in.host}: a stand-in address already set up")
        address_setups.append(loaded_stand_in.address)
    host_entries = [(each.host, each.address) for each in loaded]
    return replace(
        spec,
        stand_ins=loaded,
        address_setups=tuple(address_setups),
        host_entries=(*spec.host_entries, *host_entries),
    )


def serve_stand_ins(
    spec: PlantingSpec, holder: str | None, docker: PlantingDocker, stack: ExitStack
) -> None:
    for served in spec.stand_ins:
        assert holder is not None  # `planting_spec` forces a holder for a declared stand-in
        capture = _write(docker, stack, served.capture)
        certificate = _write(docker, stack, served.certificate)
        key = _write(docker, stack, served.key)
        name = docker.start_stand_in(
            [
                *confinement_args(),
                "--cap-add",
                "NET_BIND_SERVICE",
                "--network",
                f"container:{holder}",
                "-e",
                f"BIND_ADDR={served.address}",
                "-v",
                f"{capture}:/stand-in/capture.json:ro",
                "-v",
                f"{certificate}:/stand-in/cert.pem:ro",
                "-v",
                f"{key}:/stand-in/key.pem:ro",
                STAND_IN_IMAGE,
            ]
        )
        stack.callback(quiet, docker.remove_stand_in, name, served.host)


def trust_args(
    spec: PlantingSpec, docker: PlantingDocker, stack: ExitStack
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    trust = spec.host.public_names.trust
    if not trust:
        return (), ()
    # Every stand-in's leaf comes from the one fixture authority, so any loaded copy serves.
    authority = _write(docker, stack, spec.stand_ins[0].authority)
    env = tuple(arg for name in trust for arg in ("-e", f"{name}={_AUTHORITY_PATH}"))
    return env, ("-v", f"{authority}:{_AUTHORITY_PATH}:ro")


def probe_stand_ins(spec: PlantingSpec, probe_args: Sequence[str], docker: PlantingDocker) -> None:
    for served in spec.stand_ins:
        if not all(docker.probe_listener(probe_args, served.host, port) for port in _SERVED_PORTS):
            raise PlantingFailed(f"stand-in for {served.host} is not serving")


def _write(docker: PlantingDocker, stack: ExitStack, content: str) -> str:
    # 0644 because the stand-in runs with no capability, so its root cannot read a 0600 file
    # the host user owns.
    path = docker.write_host_file(content, 0o644)
    stack.callback(quiet, docker.remove_host_file, path)
    return path
