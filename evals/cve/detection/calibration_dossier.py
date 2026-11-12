"""Assemble, outside the repository, the self-contained calibration kit for one candidate.

The kit the detection suite rule's `Calibration` demands: the agent develops a fixture from the
advisories, the fixture format, the grammar, the list of places and the deployment layout, with
no access to the auditor's code. So the exported tree imports nothing from `mcp_auditor`: the kit
modules and every repository module they import, copied under `evals/` at their repository
paths, run in the external directory with no repository on the path. The dossier is rebuilt from
the committed census (`CensusFlaw` fields alone), never from the raw hand-downloaded exports
`run_census._dossier` needs.
"""

import json
import shutil
from collections.abc import Mapping, Sequence
from pathlib import Path

from pydantic import BaseModel

from evals.cve import dossier_closure, places
from evals.cve.census.census import CLASSIFIERS, Census, CensusFlaw
from evals.cve.census.classification import Classification
from evals.cve.census.sources import SourceName, SourceRecord
from evals.cve.detection.draw_record import CalibrationCard
from evals.cve.detection.targets import ACCEPTANCE_TARGETS
from evals.cve.planting_base import SENTINEL_SERVICE
from evals.eval_session import Refused
from evals.honeypots import REPO_ROOT
from evals.run_census import GRAMMAR_CLASSES

EVALS = REPO_ROOT / "evals"
DOCKER = EVALS / "docker"

KIT_ROOTS = (
    "evals.cve.kit.client",
    "evals.cve.kit.launch",
    "evals.cve.kit.target",
    "evals.cve.kit.driver",
)

_ADVISORY_PAGES = {
    SourceName.GHSA: "https://github.com/advisories/{}",
    SourceName.NVD: "https://nvd.nist.gov/vuln/detail/{}",
    SourceName.OSV: "https://osv.dev/vulnerability/{}",
}


class Dossier(BaseModel):
    identifier: str
    ids: list[str]
    advisory_urls: list[str]
    records: list[SourceRecord]


class CandidateDossier(Dossier):
    server_package: str
    neighbours: list[Dossier]


def write_kit(census: Census, flaw_id: str, out: Path) -> None:
    flaw = _member(census, flaw_id)
    out.mkdir(parents=True, exist_ok=True)
    _write_advisories(census, flaw, out)
    _copy_sources(out)
    _write_docs(out)


def _member(census: Census, flaw_id: str) -> CensusFlaw:
    for flaw in census.flaws:
        if flaw.identifier == flaw_id:
            return flaw
    raise Refused(
        f"Refused: {flaw_id} is not a census member.",
        ["The --flaw argument must be the flaw ID of a census flaw."],
    )


def _write_advisories(census: Census, flaw: CensusFlaw, out: Path) -> None:
    packages = server_packages(census.classifications)
    package = packages.get(flaw.identifier, "")
    neighbours = [
        advisory_dossier(other)
        for other in census.flaws
        if other.identifier != flaw.identifier and packages.get(other.identifier) == package
    ]
    candidate = CandidateDossier(
        **advisory_dossier(flaw).model_dump(), server_package=package, neighbours=neighbours
    )
    advisories = out / "advisories"
    advisories.mkdir(parents=True, exist_ok=True)
    (advisories / f"{flaw.identifier}.json").write_text(candidate.model_dump_json(indent=2))


def server_packages(classifications: Mapping[str, list[Classification]]) -> dict[str, str]:
    return {each.flaw: each.server_package for each in classifications[CLASSIFIERS[0]]}


def advisory_dossier(flaw: CensusFlaw) -> Dossier:
    return Dossier(
        identifier=flaw.identifier,
        ids=flaw.ids,
        advisory_urls=[_ADVISORY_PAGES[record.source].format(record.id) for record in flaw.records],
        records=flaw.records,
    )


def copy_kit_sources(out: Path, kit_roots: Sequence[str]) -> None:
    """Copy the given kit modules with their import closure (every `__init__.py` on the way),
    the stand-in captures (evals/stand_ins/), the sentinel Dockerfile and the stand-in Dockerfile
    into the exported tree. The calibration kit adds its own places file."""
    dossier_closure.copy_closure(out, kit_roots)
    shutil.copytree(EVALS / "stand_ins", out / "evals" / "stand_ins", dirs_exist_ok=True)
    docker_out = out / "docker"
    docker_out.mkdir(parents=True, exist_ok=True)
    for dockerfile in ("Dockerfile.sentinel", "Dockerfile.stand-in"):
        shutil.copyfile(DOCKER / dockerfile, docker_out / dockerfile)


def _copy_sources(out: Path) -> None:
    copy_kit_sources(out, KIT_ROOTS)
    shutil.copyfile(places.DETECTION_PLACES, out / "evals" / "detection_places.json")


def _write_docs(out: Path) -> None:
    (out / "grammar_classes.md").write_text(GRAMMAR_CLASSES)
    (out / "layout.md").write_text(_LAYOUT)
    (out / "fixture_format.md").write_text(_fixture_format())
    (out / "README.md").write_text(_readme())


def acceptance_services() -> set[str]:
    services = {
        name for target in ACCEPTANCE_TARGETS for name in (*target.images, target.patched_image)
    }
    return services | {SENTINEL_SERVICE}


def _readme() -> str:
    names = ", ".join(f"`{name}`" for name in sorted(acceptance_services()))
    return _README.format(acceptance_services=names)


def _fixture_format() -> str:
    classification = json.dumps(Classification.model_json_schema(), indent=2)
    card = json.dumps(CalibrationCard.model_json_schema(), indent=2)
    return _FIXTURE_FORMAT.format(classification=classification, card=card)


_LAYOUT = """\
# The deployment layout

Every launch builds the frozen `/srv` deployment layout (ADR 031) under a temp root mounted at
`/srv`, byte-for-byte universal apart from which nodes carry a live nonce. Plant a kept layout
place into its node; every other node carries neutral content of the same shape.

The tree is owned by the unprivileged account, `65534:65534`, on every target and both versions:
`owned_layout` (`evals/cve/layout.py`) builds it on the host, hands it over with a short-lived
container of the pinned busybox running `chown -hR 65534:65534`, and removes it with another after
the launch. A layout builder enters `owned_layout` before `planted`.

The mount mode is the target's, declared on its `PlantingHost` (`layout_mount`) and the same on
both versions: read-only by default, read-write (`LayoutMount.READ_WRITE`) only on a target whose
exploits, written from the published mechanism, write to the layout. A builder mounts the tree
with `layout.layout_mount_args(root, spec.host.layout_mount)` and never chooses the mode.

The target runs as the unprivileged account, `65534:65534`, unless a kept `account` place has it
run as the account named after a nonce: the planting code emits that `--user`. The kit driver
(`evals/cve/kit/driver.py`) reports, on each version, a launch whose last `--user` before the
image is any other account, or that sets none, as an out-of-calibration reason, so a builder must
not pass a `--user` of its own.

A target that cannot write to the checkout, while a tool its flaw is reached through writes to
the working directory before the flaw's code runs, takes `/work` as its working directory
(`PlantingHost.working_directory`, `layout.WORK`): an empty tmpfs outside the layout, owned
by `65534:65534` and sticky, that the planting code mounts at each launch. The checkout stays its
scope, and `/work` holds no place: a file place resolving under it is refused.

Nodes (the `anchor` of a layout place in `detection_places.json`):

- `workspace` -> `/srv`: the workspace directory. `/srv/.env` sits here, a dotenv at the
  workspace level.
- `project` -> `/srv/app`: a shallow checkout cloned from the bare repository, its
  `.git/config` naming the bare as origin, genuinely lacking the history `.env`.
- `project_bare` -> `/srv/app.git`: a bare repository. Its `config` holds a remote URL, and its
  history carries an add-then-remove `.env` (the file lives in the history but not at HEAD).

A layout place cites `anchor` and a `relpath` relative to that node. A catalogue place sits at
an absolute host path instead. The route check (run in the repository on the transplanted
fixture) decides which layout places a given server actually reaches.
"""

_FIXTURE_FORMAT = """\
# The fixture format

Author a `KitTarget` (`evals/cve/kit/target.py`) and run it through the kit driver
(`evals/cve/kit/driver.py`). The maintainer transplants it into
`evals/cve/detection/holdout_targets.py` by swapping two import lines and nothing else:

- `from evals.cve.kit.client import KitClient` -> the auditor's `MCPClientPort` and
  `ToolResponse` (the exploits run unchanged: `KitResponse` mirrors `ToolResponse`).
- `from evals.cve.kit.launch import Launch` -> `evals.cve.environments.Launch`.

The authored `KitTarget` then wraps into a `Target` (the shared fields).

## KitTarget fields

- `flaw_id`: the drawn flaw ID.
- `classes`: the `frozenset` of grammar `FlawClass` values the target is filed under:
  one class, the union of its flaws' classes when they differ, or empty for no class.
- `aim`: a compiled `re.Pattern` the exploit's call arguments must match, so a place that
  surfaces by accident (an exploit not aimed at it) does not count.
- `reaches`: the `reachable_by` tokens the target claims (`arbitrary_read`,
  `command_execution`, `internal_fetch`).
- `kept_places`: the ids of the places only this target reaches.
- `images`, `server_image`, `patched_image`: service names, built and launched as
  `mcp-auditor-kit-<service>:local`. The service name must differ from every acceptance service
  (the README lists them).
- `planting_host`: the `PlantingHost` the places plant into: `user` (`SymbolicUser.UNPRIVILEGED`),
  `working_directory` (the checkout `/srv/app`, or `/work` for a target that cannot write to the
  checkout while a tool its flaw is reached through writes to its working directory first),
  `has_network`, `public_names` (optional), and `layout_mount` (`LayoutMount.READ_ONLY` by
  default, `LayoutMount.READ_WRITE` when the exploits, written from the published mechanism,
  write to the layout). `layout.md` gives the rules.
- `builder`: a context manager yielding a `launch.Launch` (`evals/cve/kit/launch.py`).
- `exploits`, `benign`: `async (Places, KitClient) -> None`.
- `launch_mode`, `fallback_scope`: optional, defaulting to normal launch and no fallback.

## Classification JSON schema

```json
{classification}
```

## CalibrationCard JSON schema

```json
{card}
```

The grammar effect classes are in `grammar_classes.md`; the places are in
`evals/detection_places.json`; the deployment layout is in `layout.md`.
"""

_README = """\
# Isolated calibration kit

A self-contained kit for calibrating one holdout candidate, free of any `mcp_auditor`
import. Run it from this directory with this directory on the Python path (its `evals/` package
resolves the copied modules). It needs rootful Docker Engine 28.0 or later on Linux but
no LLM and no repository checkout: the layout's hand-over chowns a bind mount, which fails under
rootless Docker, `userns-remap` or Docker Desktop, and every layout target is then skipped. Its
MCP client needs the `mcp` package, `mcp>=1.18.0,<2`.

## Procedure

1. Build the sentinel image first (the planting code's sidecar for network places and a
   namespace holder), and the stand-in image beside it (it serves a public service's
   capture under its real name):

   ```
   docker build -t mcp-auditor-cve-sentinel:local -f docker/Dockerfile.sentinel docker
   docker build -t mcp-auditor-cve-stand-in:local -f docker/Dockerfile.stand-in docker
   ```

   The first launch also pulls the busybox pinned by digest in
   `evals/cve/planting_docker.py` (`LAYOUT_HELPER_IMAGE`), which hands the layout over and
   removes it, so it needs network once.

2. Read `advisories/<id>.json` (the candidate and the advisories of its server's other census
   flaws), `fixture_format.md`, `grammar_classes.md`, `layout.md` and
   `evals/detection_places.json`. A target that declares a stand-in loads its capture from
   `evals/stand_ins/` (`public_stand_ins.stand_in(host)`).

3. Write the candidate's two Dockerfiles into `docker/`: `Dockerfile.<service>` (the vulnerable
   version) and `Dockerfile.<service>-patched` (the fixed version). `launch.build_images`
   (`evals/cve/kit/launch.py`) builds each as `mcp-auditor-kit-<service>:local`. The service
   name transplants unchanged into the repository, so it must differ from every acceptance
   service: {acceptance_services}.

4. Write the `KitTarget` fixture (see `fixture_format.md`) and run it through the kit driver,
   making as many attempts as you need, until the candidate reproduces on the vulnerable version
   (the exploits surface the nonce, the benign call is clean) and is clean on the patched version
   (no nonce surfaces, the benign call does not error).

5. Fill the calibration card (`fixture_format.md` carries its schema): the mechanism, the effect
   class, the siblings, the kept and unkept places, the launch options, the seeded layout files,
   each item seeded outside the layout (`seeded_outside_layout`) and each stand-in with the
   source of its outputs (`stand_ins`), both with the tools that return it or use it by default,
   the release of each real software the fixture runs (`software_releases`), with the day that
   release was the current stable one when the documentation names no version, the exploit and
   benign calls, the patched result and the number of attempts. `[]` records that there is
   nothing to declare.

## The layout and route checks are NOT in the kit

The layout-break check and the per-place route check are code the auditor pins with a committed
golden master, so a kit copy would be a silent rule change. They are run in the repository on the
transplanted fixture, not here: the maintainer runs them and hands back the layout check's result
and the per-place route results, and the agent settles which layout places the card keeps on
those results. The kit replaces only the MCP client, the Docker launch and the calibration
driver.
"""
