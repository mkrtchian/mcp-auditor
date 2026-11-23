"""The files every blind kit shares: the kit modules with their import closure, the stand-in
captures, the sentinel and stand-in Dockerfiles, and the advisory dossier of a census flaw."""

import shutil
from collections.abc import Sequence
from pathlib import Path

from pydantic import BaseModel

from evals.cve import dossier_closure
from evals.cve.census.census import CensusFlaw
from evals.cve.census.sources import SourceName, SourceRecord
from evals.repository import REPO_ROOT

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
