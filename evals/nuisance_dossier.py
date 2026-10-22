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
from pathlib import Path

from evals import calibration_dossier, nuisance_walk
from evals.calibration_dossier import KIT_MODULES, acceptance_services, copy_clean_sources
from evals.eval_session import Refused
from evals.holdout_census import HoldoutCensus
from evals.nuisance_admission import AdmittedServer, FlawRecord
from evals.run_census import GRAMMAR_CLASSES


def write_dossier(census: HoldoutCensus, server_package: str, out: Path) -> None:
    identifiers = nuisance_walk.census_flaws_of(
        nuisance_walk.normalized_package(server_package), census
    )
    if not identifiers:
        raise Refused(
            f"Refused: no census flaw names the server {server_package}.",
            ["The --server argument must be a server package the holdout census records."],
        )
    out.mkdir(parents=True, exist_ok=True)
    _write_advisories(census, identifiers, out)
    copy_clean_sources(out, (*KIT_MODULES, "fix_check"))
    _write_docs(out)


def _write_advisories(census: HoldoutCensus, identifiers: list[str], out: Path) -> None:
    by_identifier = {flaw.identifier: flaw for flaw in census.flaws}
    advisories = out / "advisories"
    advisories.mkdir(parents=True, exist_ok=True)
    for identifier in identifiers:
        dossier = calibration_dossier.advisory_dossier(by_identifier[identifier])
        (advisories / f"{identifier}.json").write_text(dossier.model_dump_json(indent=2))


def _write_docs(out: Path) -> None:
    (out / "grammar_classes.md").write_text(GRAMMAR_CLASSES)
    (out / "fixture_format.md").write_text(_fixture_format())
    (out / "README.md").write_text(_readme())


def _fixture_format() -> str:
    flaw = json.dumps(FlawRecord.model_json_schema(), indent=2)
    server = json.dumps(AdmittedServer.model_json_schema(), indent=2)
    return _FIXTURE_FORMAT.format(flaw_record=flaw, admitted_server=server)


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
- `host`: the `PlantingHost` the agents fill.
  - `user`: `host` or `unprivileged`, `unprivileged` unless the patched image breaks under uid
    65534 and `HOME=/tmp`, the fix-check driver establishing it.
  - `working_directory`: `/` unless the image needs another.
  - `has_network`: true only when a benign call reaches a host outside the container, which
    gives the plain bridge, false otherwise, which runs the server with no network.

## FlawRecord JSON schema

```json
{flaw_record}
```

## AdmittedServer JSON schema

```json
{admitted_server}
```

The grammar effect classes are in `grammar_classes.md`.
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

4. Write the `FixCheckTarget` fixture (see `fixture_format.md`) and run it through `check_fix`,
   making as many attempts as you need, until the witness surfaces on the vulnerable version and
   on neither patched version, and the benign call does not error on a patched version.

5. Paste the printed `FixCheckResult` into the flaw's `fix_check` record of the admission, and
   fill the rest of the `FlawRecord` and `AdmittedServer` fields (`fixture_format.md` carries
   their schemas).
"""
