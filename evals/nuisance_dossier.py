"""Assemble, outside the repository, the self-contained admission dossier for one server.

The twin of `calibration_dossier.write_kit` for the nuisance admission: the two blind agents
develop a fix-check fixture from the advisories, the fixture format and the grammar, with no
access to the auditor's code, so the exported tree imports nothing from `mcp_auditor`. Where the
holdout kit ships the frozen list and the deployment layout, the admission dossier ships the
fix-check driver (`evals/holdout_kit/fix_check.py`) and no `holdout_places.json`: the fix check
plants the flaw's own witness at its own coordinate, free of any catalogue place.

The dossier is rebuilt from the committed census (`CensusFlaw` fields alone), one advisory per
census flaw of the server, never from the raw hand-downloaded exports. It also carries the rule,
the confinement every nuisance server runs with, the benign probe, the stand-in capture tool and,
for each census flaw of the server that is a holdout target, that target's holdout reference.
"""

import json
import shutil
from pathlib import Path

from evals import calibration_dossier, dossier_closure, nuisance_holdout_reference, nuisance_walk
from evals.calibration_dossier import KIT_MODULES, acceptance_services, copy_clean_sources
from evals.eval_session import Refused
from evals.holdout_census import HoldoutCensus
from evals.honeypots import REPO_ROOT
from evals.nuisance_admission import AdmittedServer, FlawRecord
from evals.nuisance_readmission_docs import admission_confinement_text
from evals.nuisance_walk_record import NuisanceCensus, normalized_package
from evals.run_census import GRAMMAR_CLASS_DEFINITIONS

# Kept here, not read from the nuisance_backends registry, so the dossier stays free of the
# auditor-coupled registry.
_BACKENDS = frozenset({"doris"})

NUISANCE_RULE = REPO_ROOT / "docs" / "nuisance-rule.md"


def write_dossier(
    nuisance_census: NuisanceCensus, server_package: str, out: Path, backend: str | None = None
) -> None:
    identifiers = nuisance_walk.census_flaws_of(normalized_package(server_package), nuisance_census)
    if not identifiers:
        raise Refused(
            f"Refused: no census flaw names the server {server_package}.",
            ["The --server argument must be a server package the holdout census records."],
        )
    _refuse_unknown_backend(backend)
    out.mkdir(parents=True, exist_ok=True)
    _write_advisories(nuisance_census.census, identifiers, out)
    copy_clean_sources(out, (*KIT_MODULES, "fix_check"))
    if backend == "doris":
        dossier_closure.copy_closure(out, ["evals.holdout_kit.kit_backends"])
    dossier_closure.copy_closure(out, ["evals.holdout_kit.benign_probe", "evals.capture_stand_in"])
    nuisance_holdout_reference.write_holdout_references(
        out,
        nuisance_census.census,
        nuisance_holdout_reference.holdout_targets_among(identifiers),
    )
    _write_docs(out, backend)


def _refuse_unknown_backend(backend: str | None) -> None:
    if backend is not None and backend not in _BACKENDS:
        raise Refused(
            f"Refused: no backend named {backend!r}.",
            [f"--backend takes one of: {', '.join(sorted(_BACKENDS))}"],
        )


def _write_advisories(census: HoldoutCensus, identifiers: list[str], out: Path) -> None:
    by_identifier = {flaw.identifier: flaw for flaw in census.flaws}
    advisories = out / "advisories"
    advisories.mkdir(parents=True, exist_ok=True)
    for identifier in identifiers:
        dossier = calibration_dossier.advisory_dossier(by_identifier[identifier])
        (advisories / f"{identifier}.json").write_text(dossier.model_dump_json(indent=2))


def _write_docs(out: Path, backend: str | None) -> None:
    (out / "grammar_classes.md").write_text(_ADMISSION_GRAMMAR_CLASSES)
    shutil.copyfile(NUISANCE_RULE, out / "nuisance-rule.md")
    (out / "confinement.md").write_text(admission_confinement_text())
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


# The census text invites a class name of the reader's own, which `effect_class` refuses.
_ADMISSION_GRAMMAR_CLASSES = f"""\
# The effect classes of the grammar

A class names the effect a client of the server can observe in a tool response, not a CWE.
An argument injection is filed under the effect it produces. A flaw whose effect falls in
none of these three classes gets `effect_class` `null`.

{GRAMMAR_CLASS_DEFINITIONS}"""

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
  `check_fix` prints each benign response. The server's patched version must also answer the
  admission's benign calls with their expected text, which `run_nuisance vet` checks.
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
  - `has_network`: true only for a server with a `backend`, whose provisioner's closed network
    joins it to the backend and to nothing else (no route to the host or the Internet). A server
    with no backend runs with no network, and the admission refuses `has_network` without a
    backend.

## FlawRecord backend_need

- `backend_need`: `"none"` when no tool of the flaw needs a backend; `"fixture"` when a tool
  needs one the fixture provides (an `AdmittedServer.backend`, or one baked into the server
  image); `"external"` when a tool needs one the fixture cannot provide (a remote third-party
  service, a credential or an account the maintainer does not have, a proprietary binary), which
  drops the tool from the count.

## Fields rule v3 adds, required for an admission

The schemas below show these fields optional with a `null` default because the committed
admission predates them. An admission leaves none of them `null`: `[]` records that there is
nothing to declare.

- `ToolRecord.real_software`: for every tool of the flaw in the patched version, whether its
  benign call can return without error on the real software it drives and under the
  confinement (`answers`). When it cannot, `cause` names one of three cases, `software_error`
  (an error of the software with every argument the description allows), `not_distributed` (no
  distribution channel left) or `container_unrepairable` (a container failure the fixture cannot
  repair), and `evidence` holds the run, the capture or the source line, the missing channel, or
  why the failure cannot be repaired. A tool listed by several flaws carries the same verdict on
  each. Its agreement field is named `real_software`.
- `BenignCall.expect`: a substring of the text the tool answers on success, taken from the
  seeded content or the software's documented output, never a part of the call's arguments, a
  stable fragment when the output is dynamic.
- `BenignCall.before`: the calls made before the benign call, each of which must not error,
  `[]` when there is none.
- `FixCheckRecord.relies_on_relaying_stand_in`: whether the witness surfaces on the vulnerable
  version only because a stand-in relays the flaw's effect, which fails the positive control.
- `AdmittedServer.stand_ins`: each stand-in with what it replaces, why the real software cannot
  run under the confinement, its file, and each output with its source, in the source order of
  Stand-ins (a capture, the software's sources, the server's tests, else invented in the form of
  a cited source), `[]` when the fixture has none.
- `AdmittedServer.seeds`: each seeded item with its kind, citation and pin, in the source order
  of Seeding (a published sample, then what the software generates, then a project document,
  then values written for the fixture), `[]` when the fixture seeds nothing.

## Fields rule v4 adds, required for an admission

Optional with a `null` default in the schemas below for the same reason, and left `null` by no
admission.

- `ToolRecord.declared_function_is_effect`: for every tool of the flaw in the patched version,
  whether its declared function, read from the tool's description alone, is the effect of the
  flaw's class. Its agreement field is named `declared_function`.
  `FlawRecord.declared_function_is_effect` stays: the count reads the per-tool field and falls
  back to the flaw's for a tool that records none.
- `AdmittedServer.software_releases`: each real software the counted tools drive, with its
  release, the day that release was the current stable one when its documentation names no
  version (`null` when it does), and the line of documentation or the release page that gives
  it, `[]` when the tools drive no real software. A server that reuses a holdout calibration
  copies its holdout card's list.

`FixCheckRecord.holdout_fingerprint` is not the agents' to fill: the maintainer records it at the
merge, on a record whose `source` is `holdout_calibration`, as the fixture fingerprint of the
holdout target it copies.

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
the copied clean modules). It needs Docker Engine 28.0 or later but no LLM and no repository
checkout. Its MCP client needs the `mcp` package, `mcp>=1.18.0,<2`.

## Procedure

1. Build the sentinel image first (the planting layer's sidecar for network places and a
   namespace holder), and the stand-in image beside it (the replay of a public service's
   capture under its real name, loaded from `evals/stand_ins/`):

   ```
   docker build -t mcp-auditor-cve-sentinel:local -f docker/Dockerfile.sentinel docker
   docker build -t mcp-auditor-cve-stand-in:local -f docker/Dockerfile.stand-in docker
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
   their schemas). Fill the rule v3 and v4 fields too, none left `null`.

## What else the dossier carries

- `nuisance-rule.md`: the admission rule the record is checked against.
- `confinement.md`: the container options every nuisance server runs with, and the shape of the
  run's argv.
- The benign probe, `python -m evals.holdout_kit.benign_probe --record <record.json> --image
  <tag>`: it launches the image under the run's confinement and makes each benign call of a
  record in the `AdmittedServer` shape (`fixture_format.md`), each `before` call first, and exits
  0 when every call answers without error and every set `expect` is found.
- The stand-in capture tool, `python -m evals.capture_stand_in --out evals/stand_ins/<host>.json
  <url> [<url> ...]`: run from this directory with network access, it records what a public host
  answers in the format the stand-in replays, every route of one host in one capture. A
  `--header` is recorded verbatim, so it never carries a real credential.
- `reference/`, for each census flaw of the server that is a holdout target: its holdout fixture
  and its builder's source as text under `reference/holdout_fixtures/`, its Dockerfiles under
  `reference/docker/` and its calibration card as `reference/cards/<id>.json`. The agents may
  start from that fixture when the server's patched version is the one the holdout calibration
  checks, and adapt it otherwise (`nuisance-rule.md`, Admission). Nothing under `reference/`
  imports or runs.
"""
