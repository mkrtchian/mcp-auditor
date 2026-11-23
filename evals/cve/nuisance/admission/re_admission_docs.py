"""The rendered documents of a re-admission: the run's confinement for one admitted server,
rendered from the run's own launch builders and never retyped, and the README section on the
re-admission tools."""

import shlex
from collections.abc import Mapping, Sequence

from evals.cve.backends.lifecycle import BackendLifecycle, PerLaunchBackend
from evals.cve.nuisance.admission.admission import AdmittedServer
from evals.cve.nuisance.admission.admission_docs import IMAGE_PLACEHOLDER, confinement_options
from evals.cve.nuisance.backend_registry import BACKENDS, RegisteredBackend
from evals.cve.nuisance.confinement import single_container_run_args
from evals.cve.planting_base import memory_bound_args

_NAME = "<name>"


def confinement_text(
    server: AdmittedServer, backends: Mapping[str, RegisteredBackend] = BACKENDS
) -> str:
    backend = backends[server.backend.provisioner] if server.backend is not None else None
    return _CONFINEMENT.format(
        launch=_launch_text(server, backend),
        options=confinement_options(),
        backend=_backend_paragraph(backend),
    )


def _launch_text(server: AdmittedServer, backend: RegisteredBackend | None) -> str:
    if backend is None:
        args = single_container_run_args(IMAGE_PLACEHOLDER, server.host, server.launch)
        return _ARGV.format(command=_docker(args))
    match backend.lifecycle:
        case BackendLifecycle() as lifecycle:
            args = lifecycle.server_args(_NAME, IMAGE_PLACEHOLDER, server.host, server.launch)
            return _ARGV.format(command=_docker(args))
        case PerLaunchBackend() as lifecycle:
            return _PER_LAUNCH_ARGV.format(key=lifecycle.key)


def _docker(args: list[str]) -> str:
    return f"docker {shlex.join(args)}"


def _backend_paragraph(backend: RegisteredBackend | None) -> str:
    if backend is None:
        return _NO_BACKEND
    bound = " ".join(memory_bound_args())
    match backend.lifecycle:
        case BackendLifecycle() as lifecycle:
            return _BACKEND.format(key=lifecycle.key, network=backend.network, bound=bound)
        case PerLaunchBackend() as lifecycle:
            return _PER_LAUNCH_BACKEND.format(
                key=lifecycle.key, network=backend.network, bound=bound
            )


def re_admission_readme(server: AdmittedServer, fix_check_modules: Sequence[str]) -> str:
    backend = server.backend.provisioner if server.backend is not None else None
    backend_line = (
        f"`evals/cve/backends/{backend}.py` is the lifecycle of its `{backend}` backend."
        if backend is not None
        else "The server has no backend."
    )
    fix_checks = ", ".join(f"`{module}`" for module in fix_check_modules) or "none"
    return _README.format(service=server.service, backend_line=backend_line, fix_checks=fix_checks)


_CONFINEMENT = """\
# The run's confinement

{launch}
The confinement options, every server alike:

{options}

{backend}"""

_ARGV = """\
The run launches the server with this argv, `<image>` standing for the image tag
(`mcp-auditor-nuisance-<service>:local` in the repository, the prefixed kit tag here) and
`<name>` for the container name:

```
{command}
```
"""

_PER_LAUNCH_ARGV = """\
The run launches the server with the argv its `{key}` backend yields once it has stood the
backend for that launch (`LIFECYCLE.launch` in `evals/cve/backends/{key}.py`). The argv carries
values only that stand-up knows, so it is not rendered here: read it in that module.
"""

_NO_BACKEND = """\
The server has no backend: it runs with no network. When its host declares public names, the
launch joins a namespace holder that serves each one under its real name from its capture in
`evals/stand_ins/`, with the trust setting, and the argv above takes the holder's network in
place of `--network none`.
"""

_BACKEND = """\
The server joins the closed network `{network}` of its `{key}` backend, which reaches the
backend's containers and nothing else (no route to the host or the Internet). The backend's
containers run under the same memory bound, `{bound}`.
"""

_PER_LAUNCH_BACKEND = """\
The `{key}` backend is stood for each launch of the server and removed with it, so no other
launch reaches it. Each closed network it creates for a launch is named after the prefix
`{network}` and reaches that launch's server and backend containers and nothing else (no route to
the host or the Internet), or, when the prefix is `none`, it creates none and both run with no
network. The backend's containers run under the same memory bound, `{bound}`.
"""

_README = """
## Re-admission

This dossier also carries what a re-admission of this server needs, beside the first-admission
kit above.

- `admission_record.json`: the server's committed `AdmittedServer` record.
- `confinement.md`: here, the argv the run launches this server with and its confinement
  options.
- `evals/docker/`: the Dockerfiles of the run's image (`Dockerfile.{service}`), of the committed
  fix checks, of the holdout target and of the backend, as the repository holds them.
- `evals/cve/nuisance/fix_checks/`: the server's committed fix-check modules.

{backend_line}

### Build the run image under a prefixed tag

Pick a prefix of your own, so two agents on one machine never share an image. Copy
`evals/docker/Dockerfile.{service}` to `docker/Dockerfile.<prefix>-{service}`, then:

```
python - <<'EOF'
from pathlib import Path
from evals.cve.kit import launch
launch.build_images(Path("docker"), ["<prefix>-{service}"])
EOF
```

The image is tagged `mcp-auditor-kit-<prefix>-{service}:local`. A real-software probe image is
built the same way from a Dockerfile of your own.

### Probe the benign calls

```
python -m evals.cve.kit.benign_probe --record admission_record.json \\
  --image mcp-auditor-kit-<prefix>-{service}:local [--calls calls.json]
```

It launches the image with the run's argv (`confinement.md`), lists the tools and makes each
benign call of the record (or of `calls.json`, in the `BenignCall` JSON shape), each `before`
call first. The first line is `tools/list: <n> tools`. Each call prints one line,
`<tool> [listed|NOT LISTED] -> ok|error[, expect found|, expect MISSING] <content>`, preceded by
one `  before <tool> ...` line per prerequisite call. The exit code is 0 when every call and
before call is listed and answers without error and every set `expect` is found, else 1.

### Run a committed fix check under prefixed services

This server's fix-check modules: {fix_checks}.

Copy each Dockerfile the fix check names (`vulnerable_service`, `patched_service`,
`server_patched_service`) from `evals/docker/` to `docker/Dockerfile.<prefix>-<service>`, build
them with `launch.build_images`, then:

```
python - <<'EOF'
import asyncio, dataclasses
from evals.cve.kit.fix_check import check_fix
from evals.cve.nuisance.fix_checks.<module> import FIXTURES
fixture = dataclasses.replace(
    FIXTURES[0],
    vulnerable_service="<prefix>-<vulnerable>",
    patched_service="<prefix>-<patched>",
    server_patched_service="<prefix>-<server-patched>",  # None when the fixture sets none
)
print(asyncio.run(check_fix(fixture)))
EOF
```

### Shared and per-launch backends

The shared backend containers and networks (`mcp-auditor-cve-*`) are persistent: they serve
every agent on the machine, and are never removed or stopped by the agent. The probe and the fix
check bring them up when they are down and remove only the server containers they start.
A per-launch backend is stood by the probe or the fix check for its own launch and removed with
it.
"""
