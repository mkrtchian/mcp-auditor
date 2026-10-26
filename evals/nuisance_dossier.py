"""Assemble, outside the repository, the self-contained admission dossier for one server.

The twin of `calibration_dossier.write_kit` for the nuisance admission: the two blind agents
develop a fix-check fixture from the advisories, the fixture format and the grammar, with no
access to the auditor's code, so the exported tree imports nothing from `mcp_auditor`. Where the
holdout kit ships the frozen list and the deployment layout, the admission dossier ships the
fix-check driver (`evals/holdout_kit/fix_check.py`) and no `holdout_places.json`: the fix check
plants the flaw's own witness at its own coordinate, free of any catalogue place.

The dossier is rebuilt from the committed census (`CensusFlaw` fields alone), one advisory per
census flaw of the server, never from the raw hand-downloaded exports.
"""

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from evals import calibration_dossier, nuisance_walk
from evals.calibration_dossier import EVALS, KIT_MODULES, acceptance_services, copy_clean_sources
from evals.eval_session import Refused
from evals.holdout_census import HoldoutCensus
from evals.nuisance_admission import AdmittedServer, FlawRecord
from evals.run_census import GRAMMAR_CLASSES


@dataclass(frozen=True)
class BackendSources:
    evals_modules: tuple[str, ...]
    kit_modules: tuple[str, ...]


# The lifecycle a dossier copies for a server admitted with a backend. Kept here, not read from
# the nuisance_backends registry, so the dossier stays free of the auditor-coupled registry.
_BACKEND_SOURCES: dict[str, BackendSources] = {
    "doris": BackendSources(evals_modules=("doris_backend",), kit_modules=("kit_backends",))
}


def write_dossier(
    census: HoldoutCensus, server_package: str, out: Path, backend: str | None = None
) -> None:
    identifiers = nuisance_walk.census_flaws_of(
        nuisance_walk.normalized_package(server_package), census
    )
    if not identifiers:
        raise Refused(
            f"Refused: no census flaw names the server {server_package}.",
            ["The --server argument must be a server package the holdout census records."],
        )
    sources = _backend_sources(backend)
    out.mkdir(parents=True, exist_ok=True)
    _write_advisories(census, identifiers, out)
    copy_clean_sources(out, (*KIT_MODULES, "fix_check", *sources.kit_modules))
    for module in sources.evals_modules:
        shutil.copyfile(EVALS / f"{module}.py", out / "evals" / f"{module}.py")
    _write_docs(out, backend)


def _backend_sources(backend: str | None) -> BackendSources:
    if backend is None:
        return BackendSources((), ())
    if backend not in _BACKEND_SOURCES:
        raise Refused(
            f"Refused: no backend named {backend!r}.",
            [f"--backend takes one of: {', '.join(sorted(_BACKEND_SOURCES))}"],
        )
    return _BACKEND_SOURCES[backend]


def _write_advisories(census: HoldoutCensus, identifiers: list[str], out: Path) -> None:
    by_identifier = {flaw.identifier: flaw for flaw in census.flaws}
    advisories = out / "advisories"
    advisories.mkdir(parents=True, exist_ok=True)
    for identifier in identifiers:
        dossier = calibration_dossier.advisory_dossier(by_identifier[identifier])
        (advisories / f"{identifier}.json").write_text(dossier.model_dump_json(indent=2))


def _write_docs(out: Path, backend: str | None) -> None:
    (out / "grammar_classes.md").write_text(GRAMMAR_CLASSES)
    (out / "fixture_format.md").write_text(_fixture_format(backend))
    (out / "README.md").write_text(_readme())


def _fixture_format(backend: str | None) -> str:
    flaw = json.dumps(FlawRecord.model_json_schema(), indent=2)
    server = json.dumps(AdmittedServer.model_json_schema(), indent=2)
    paragraph = _DORIS_BUILDER_PARAGRAPH if backend == "doris" else ""
    return _FIXTURE_FORMAT.format(
        flaw_record=flaw, admitted_server=server, backend_paragraph=paragraph
    )


def _readme() -> str:
    names = ", ".join(f"`{name}`" for name in sorted(acceptance_services()))
    return _README.format(acceptance_services=names)


_FIXTURE_FORMAT = """\
# The fixture format

Author a `FixCheckTarget` (`evals/holdout_kit/fix_check.py`) and run it through `check_fix`. The
fixture never leaves the kit: unlike a holdout `KitTarget`, it is not transplanted into the
repository, so the vulnerable Dockerfile and the exploits are committed beside the admission as
`FixCheckTarget` fixtures and the auditor never sees them.

## FixCheckTarget fields

- `flaw`: the census identifier the fixture reproduces.
- `mechanism`: the grammar `MechanismClass`, or `None`.
- `aim`: a compiled `re.Pattern` the exploit's call arguments must match, so a witness that
  surfaces by accident (an exploit not aimed at it) does not count.
- `witness`: the `Place` the exploit surfaces (an id of its own, a `PlantKind` and
  `Coordinates`). The fix check plants it at the flaw's own coordinate, with no catalogue list.
- `planting_host`: the `PlantingHost` the witness plants into.
- `builder`: a context manager yielding a `kit_launch.Launch`.
- `exploits`: `async (Places, KitClient) -> None`, both agents' exploits. The witness counts
  when either surfaces it.
- `benign_calls`: `async (Places, KitClient) -> None`, one per tool, read from the tool
  description, not aimed at the flaw. The patched version must answer them without error.
- `vulnerable_service`, `patched_service`: service names, built and launched as
  `mcp-auditor-kit-<service>:local`. Each must differ from every acceptance service (the README
  lists them).
- `server_patched_service`: the server's own patched version when it differs from the flaw's,
  else `None`.

## FixCheckResult (the driver prints it)

`check_fix` returns a `FixCheckResult` the agent pastes into the flaw's `fix_check` record:
`source`, `witness`, `exploit_calls`, `vulnerable_surfaces`, `patched_surfaces`,
`server_patched_surfaces` and `patched_benign_errored`. The flaw counts when the witness
surfaces on the vulnerable version and on neither patched one, and no benign call errors on a
patched version.

## AdmittedServer fields the run reads

- `launch`: the container command appended after the image tag (the image's `ENTRYPOINT`, when
  it has one, applies to it).
- `backend`: the backend fixture the run provisions, or `null` when the server needs none or
  bakes it into its image. When set, it names the provisioner key, the pinned image tag the
  provisioner pulls, and the network the server joins.
- `host`: the `PlantingHost` the agents fill.
  - `user`: `host` or `unprivileged`, `unprivileged` unless the patched image breaks under uid
    65534 and `HOME=/tmp`, the fix-check driver establishing it.
  - `working_directory`: `/` unless the image needs another.
  - `has_network`: true only when a benign call reaches a host outside the container, which
    gives the plain bridge, false otherwise, which runs the server with no network. A server
    with a `backend` has the egress of its provisioner's network whatever `has_network` says, so
    `has_network` does not control a backend server's reach.

## FlawRecord backend_need

- `backend_need`: `"none"` when no tool of the flaw needs a backend; `"fixture"` when a tool
  needs one the fixture provides (an `AdmittedServer.backend`, or one baked into the server
  image); `"external"` when a tool needs one the fixture cannot provide (a remote third-party
  service, a credential or an account the maintainer does not have, a proprietary binary), which
  drops the tool from the count.

## FlawRecord JSON schema

```json
{flaw_record}
```

## AdmittedServer JSON schema

```json
{admitted_server}
```
{backend_paragraph}
The grammar effect classes are in `grammar_classes.md`.
"""

_DORIS_BUILDER_PARAGRAPH = """
## The Doris backend builder

This server records the `doris` backend. Its `FixCheckTarget.builder` is
`kit_backends.doris_backend_env`, which ensures the persistent Doris cluster and yields the server
launch wired to the backend's network. A fetch-class witness host must be a literal IP in
`169.254.0.0/16`: the sentinel is stood with `--ip` on the link-local network, so a DNS name or an
out-of-range IP fails `docker run` opaquely. `DORIS_SERVER_LAUNCH` is the holdout fixture's launch
the agents may start from, not a value to copy.
"""

_README = """\
# Isolated admission dossier

A self-contained workshop for admitting one nuisance server, free of any `mcp_auditor` import.
Run it from this directory with this directory on the Python path (its `evals/` package resolves
the copied clean modules). It needs Docker but no LLM and no repository checkout.

## Procedure

1. Build the sentinel image first (the planting layer's sidecar for network places and a
   namespace holder):

   ```
   docker build -t mcp-auditor-cve-sentinel:local -f docker/Dockerfile.sentinel docker
   ```

2. Read `advisories/<id>.json` (one per census flaw of the server), `fixture_format.md` and
   `grammar_classes.md`.

3. For each flaw, write its two Dockerfiles into `docker/`: `Dockerfile.<service>` (the
   vulnerable version) and `Dockerfile.<service>-patched` (the fixed version).
   `kit_launch.build_images` builds each as `mcp-auditor-kit-<service>:local`. The service name
   must differ from every acceptance service: {acceptance_services}.

   For a server that needs a backend to answer its benign calls: a pulled backend is recorded in
   the `backend` field (the provisioner key, the pinned image tag, the network), not written as a
   Dockerfile. A built backend is out of scope, so the maintainer wires its provisioner at
   settlement. A brand-new backend server that is not a holdout twin needs a provisioner the
   maintainer writes: the agents record the backend and flag it, and the maintainer wires it.

4. Write the `FixCheckTarget` fixture (see `fixture_format.md`) and run it through `check_fix`,
   making as many attempts as you need, until the witness surfaces on the vulnerable version and
   on neither patched version, and the benign call does not error on a patched version.

5. Paste the printed `FixCheckResult` into the flaw's `fix_check` record of the admission, and
   fill the rest of the `FlawRecord` and `AdmittedServer` fields (`fixture_format.md` carries
   their schemas).
"""
