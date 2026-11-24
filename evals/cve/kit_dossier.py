"""The files every blind kit shares: the kit modules with their import closure, the stand-in
captures, the sentinel and stand-in Dockerfiles, and the advisory dossier of a census flaw."""

import shutil
from collections.abc import Sequence
from pathlib import Path

from pydantic import BaseModel

from evals.cve import dossier_closure
from evals.cve.census.census import CensusFlaw
from evals.cve.census.sources import SourceRecord, advisory_urls
from evals.cve.docker_paths import image_dockerfile
from evals.cve.public_stand_ins import STAND_INS_DIRECTORY

KIT_ROOTS = (
    "evals.cve.kit.client",
    "evals.cve.kit.launch",
    "evals.cve.kit.target",
    "evals.cve.kit.driver",
)


class Dossier(BaseModel):
    identifier: str
    ids: list[str]
    advisory_urls: list[str]
    records: list[SourceRecord]


def advisory_dossier(flaw: CensusFlaw) -> Dossier:
    return Dossier(
        identifier=flaw.identifier,
        ids=flaw.ids,
        advisory_urls=advisory_urls(flaw.records),
        records=flaw.records,
    )


def copy_kit_sources(out: Path, kit_roots: Sequence[str]) -> None:
    """Copy the given kit modules with their import closure (every `__init__.py` on the way),
    the stand-in captures (evals/stand_ins/), the sentinel Dockerfile and the stand-in Dockerfile
    into the exported tree. The calibration kit adds its own places file."""
    dossier_closure.copy_closure(out, kit_roots)
    shutil.copytree(STAND_INS_DIRECTORY, out / "evals" / "stand_ins", dirs_exist_ok=True)
    docker_out = out / "docker"
    docker_out.mkdir(parents=True, exist_ok=True)
    for name in ("sentinel", "stand-in"):
        dockerfile = image_dockerfile(name)
        shutil.copyfile(dockerfile, docker_out / dockerfile.name)
