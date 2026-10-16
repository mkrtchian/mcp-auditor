"""Assemble, outside the repository, the self-contained calibration kit for one candidate.

The kit the holdout rule's `Calibration` demands: the agent develops a fixture from the
advisories, the fixture format, the grammar, the list of places and the deployment layout, with
no access to the auditor's code. So the exported tree imports nothing from `mcp_auditor`: the
copied clean modules and the kit source under `evals/` run in the external directory with no
repository on the path. The dossier is rebuilt from the committed census (`CensusFlaw` fields
alone), never from the raw hand-downloaded exports `run_census._dossier` needs.
"""

import json
import shutil
from collections.abc import Mapping
from pathlib import Path

from pydantic import BaseModel

from evals import cve_places
from evals.census_classification import Classification
from evals.census_draw import CalibrationCard
from evals.census_sources import SourceName, SourceRecord
from evals.eval_session import Refused
from evals.holdout_census import CLASSIFIERS, CensusFlaw, HoldoutCensus
from evals.honeypots import REPO_ROOT
from evals.run_census import GRAMMAR_CLASSES

EVALS = REPO_ROOT / "evals"
KIT_DIR = EVALS / "holdout_kit"
DOCKER = EVALS / "docker"

_CLEAN_MODULES = (
    "cve_grammar",
    "cve_proofs",
    "cve_units",
    "cve_places",
    "cve_layout",
    "cve_planting",
    "cve_planting_base",
    "cve_planting_spec",
    "cve_planting_docker",
    "cve_endpoint_address",
)
_KIT_MODULES = ("__init__", "kit_client", "kit_launch", "kit_target", "kit_driver")

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


def write_kit(census: HoldoutCensus, cve: str, out: Path) -> None:
    flaw = _member(census, cve)
    out.mkdir(parents=True, exist_ok=True)
    _write_advisories(census, flaw, out)
    _copy_sources(out)
    _write_docs(out)


def _member(census: HoldoutCensus, cve: str) -> CensusFlaw:
    for flaw in census.flaws:
        if flaw.identifier == cve:
            return flaw
    raise Refused(
        f"Refused: {cve} is not a census member.",
        ["The --cve argument must be the identifier of a flaw in the census."],
    )


def _write_advisories(census: HoldoutCensus, flaw: CensusFlaw, out: Path) -> None:
    packages = _server_packages(census.classifications)
    package = packages.get(flaw.identifier, "")
    neighbours = [
        _dossier(other)
        for other in census.flaws
        if other.identifier != flaw.identifier and packages.get(other.identifier) == package
    ]
    candidate = CandidateDossier(
        **_dossier(flaw).model_dump(), server_package=package, neighbours=neighbours
    )
    advisories = out / "advisories"
    advisories.mkdir(parents=True, exist_ok=True)
    (advisories / f"{flaw.identifier}.json").write_text(candidate.model_dump_json(indent=2))


def _server_packages(classifications: Mapping[str, list[Classification]]) -> dict[str, str]:
    return {each.flaw: each.server_package for each in classifications[CLASSIFIERS[0]]}


def _dossier(flaw: CensusFlaw) -> Dossier:
    return Dossier(
        identifier=flaw.identifier,
        ids=flaw.ids,
        advisory_urls=[_ADVISORY_PAGES[record.source].format(record.id) for record in flaw.records],
        records=flaw.records,
    )


def _copy_sources(out: Path) -> None:
    evals_out = out / "evals"
    (evals_out / "holdout_kit").mkdir(parents=True, exist_ok=True)
    (evals_out / "__init__.py").write_text((EVALS / "__init__.py").read_text())
    for module in _CLEAN_MODULES:
        shutil.copyfile(EVALS / f"{module}.py", evals_out / f"{module}.py")
    for module in _KIT_MODULES:
        shutil.copyfile(KIT_DIR / f"{module}.py", evals_out / "holdout_kit" / f"{module}.py")
    shutil.copyfile(cve_places.HOLDOUT_PLACES, evals_out / "holdout_places.json")
    docker_out = out / "docker"
    docker_out.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(DOCKER / "Dockerfile.sentinel", docker_out / "Dockerfile.sentinel")


def _write_docs(out: Path) -> None:
    (out / "grammar_classes.md").write_text(GRAMMAR_CLASSES)
    (out / "layout.md").write_text(_LAYOUT)
    (out / "fixture_format.md").write_text(_fixture_format())
    (out / "README.md").write_text(_README)


def _fixture_format() -> str:
    classification = json.dumps(Classification.model_json_schema(), indent=2)
    card = json.dumps(CalibrationCard.model_json_schema(), indent=2)
    return _FIXTURE_FORMAT.format(classification=classification, card=card)


_LAYOUT = """\
# The deployment layout

Every launch builds the frozen `/srv` deployment layout (ADR 031) under a temp root mounted at
`/srv`, byte-for-byte universal apart from which nodes carry a live nonce. Plant a kept layout
place into its node; every other node carries neutral content of the same shape.

Nodes (the `anchor` of a layout place in `holdout_places.json`):

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

Author a `KitTarget` (`evals/holdout_kit/kit_target.py`) and run it through `kit_driver`. The
maintainer transplants it into `evals/holdout_targets.py` by swapping two import lines and
nothing else:

- `from evals.holdout_kit.kit_client import KitClient` -> the auditor's `MCPClientPort` and
  `ToolResponse` (the exploits run unchanged: `KitResponse` mirrors `ToolResponse`).
- `from evals.holdout_kit.kit_launch import Launch` -> `evals.cve_environments.Launch`.

The authored `KitTarget` then wraps into a `CVETarget` (the shared fields) and into
`HoldoutTarget(target, side)`.

## KitTarget fields

- `cve_id`: the drawn identifier.
- `mechanism`: the grammar `MechanismClass`, or `None`.
- `aim`: a compiled `re.Pattern` the exploit output must match.
- `reaches`: the `reachable_by` tokens the target claims (`arbitrary_read`,
  `command_execution`, `internal_fetch`).
- `kept_places`: the ids of the places only this target reaches.
- `images`, `server_image`, `patched_image`: `mcp-auditor-cve-<service>:local` image tags.
- `planting_host`: the `PlantingHost` the places plant into.
- `builder`: a context manager yielding a `kit_launch.Launch`.
- `exploits`, `benign`: `async (Places, KitClient) -> None`.
- `side`: the draw side (`pre_cutoff` / `post_cutoff`).
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
`evals/holdout_places.json`; the deployment layout is in `layout.md`.
"""

_README = """\
# Isolated calibration kit

A self-contained workshop for calibrating one holdout candidate, free of any `mcp_auditor`
import. Run it from this directory with this directory on the Python path (its `evals/` package
resolves the copied clean modules). It needs Docker but no LLM and no repository checkout.

## Procedure

1. Build the sentinel image first (the planting layer's sidecar for network places and a
   namespace holder):

   ```
   docker build -t mcp-auditor-cve-sentinel:local -f docker/Dockerfile.sentinel docker
   ```

2. Read `advisories/<id>.json` (the candidate and the advisories of its server's other census
   flaws), `fixture_format.md`, `grammar_classes.md`, `layout.md` and
   `evals/holdout_places.json`.

3. Write the candidate's two Dockerfiles into `docker/`: `Dockerfile.<service>` (the vulnerable
   version) and `Dockerfile.<service>-patched` (the fixed version). `kit_launch.build_images`
   builds each as `mcp-auditor-cve-<service>:local`, so the image names transplant unchanged.

4. Write the `KitTarget` fixture (see `fixture_format.md`) and run it through `kit_driver`,
   making as many attempts as you need, until the candidate reproduces on the vulnerable version
   (the exploits surface the nonce, the benign call is clean) and is clean on the patched version
   (no nonce surfaces, the benign call does not error).

5. Fill the calibration card (`fixture_format.md` carries its schema): the mechanism, the effect
   class, the siblings, the kept and unkept places, the launch options, the seeded layout files,
   the exploit and benign calls, the patched result and the number of attempts.

## The layout and route checks are NOT in the kit

The layout-break check and the per-place route check are code the auditor pins with a committed
golden master, so a kit copy would be a silent rule change. They are run in the repository on the
transplanted fixture, not here: the maintainer runs them and hands back the layout-break verdict
and the per-place route results, and the agent settles which layout places the card keeps on
those results. The kit replaces only the MCP client, the Docker launch and the calibration
driver.
"""
