"""Assemble, outside the repository, the self-contained admission dossier for one server.

The counterpart of `calibration_dossier.write_kit` for the nuisance admission: the two blind agents
develop a fix-check fixture from the advisories, the fixture format and the grammar, with no
access to the auditor's code, so the exported tree imports nothing from `mcp_auditor`. Where the
calibration kit ships the frozen list and the deployment layout, the admission dossier ships the
fix-check driver (`evals/cve/kit/fix_check.py`) and no `detection_places.json`: the fix check
plants the flaw's own witness at its own coordinate, free of any catalogue place.

The dossier is rebuilt from the committed census (`CensusFlaw` fields alone), one advisory per
census flaw of the server, never from the raw hand-downloaded exports. It also carries the rule,
the confinement every nuisance server runs with, the benign probe, the stand-in capture tool and,
for each census flaw of the server that is a holdout target, its holdout target reference.
"""

import shutil
from pathlib import Path

from evals.cve import dossier_closure
from evals.cve.census.census import Census
from evals.cve.kit_dossier import KIT_ROOTS, advisory_dossier, copy_kit_sources
from evals.cve.nuisance.admission import holdout_target_reference
from evals.cve.nuisance.admission import walk as nuisance_walk
from evals.cve.nuisance.admission.admission_docs import (
    ADMISSION_GRAMMAR_CLASSES,
    KIT_BACKEND_PARAGRAPHS,
    admission_confinement_text,
    admission_readme,
    fixture_format,
)
from evals.cve.nuisance.admission.walk_record import WalkInputs, normalized_package
from evals.eval_session import Refused
from evals.repository import REPO_ROOT

NUISANCE_SUITE_RULE = REPO_ROOT / "docs" / "nuisance-suite-rule.md"


def write_dossier(
    walk_inputs: WalkInputs, server_package: str, out: Path, backend: str | None = None
) -> None:
    identifiers = nuisance_walk.census_flaws_of(normalized_package(server_package), walk_inputs)
    if not identifiers:
        raise Refused(
            f"Refused: no census flaw names the server {server_package}.",
            ["The --server argument must be a server package the census records."],
        )
    _refuse_unknown_backend(backend)
    out.mkdir(parents=True, exist_ok=True)
    _write_advisories(walk_inputs.census, identifiers, out)
    copy_kit_sources(out, (*KIT_ROOTS, "evals.cve.kit.fix_check"))
    if backend is not None:
        dossier_closure.copy_closure(out, ["evals.cve.kit.backends"])
    dossier_closure.copy_closure(out, ["evals.cve.kit.benign_probe", "evals.capture_stand_in"])
    holdout_target_reference.write_holdout_target_references(
        out,
        walk_inputs.census,
        holdout_target_reference.holdout_targets_among(identifiers),
    )
    _write_docs(out, backend)


def _refuse_unknown_backend(backend: str | None) -> None:
    if backend is not None and backend not in KIT_BACKEND_PARAGRAPHS:
        raise Refused(
            f"Refused: no backend named {backend!r}.",
            [f"--backend takes one of: {', '.join(sorted(KIT_BACKEND_PARAGRAPHS))}"],
        )


def _write_advisories(census: Census, identifiers: list[str], out: Path) -> None:
    by_identifier = {flaw.identifier: flaw for flaw in census.flaws}
    advisories = out / "advisories"
    advisories.mkdir(parents=True, exist_ok=True)
    for identifier in identifiers:
        dossier = advisory_dossier(by_identifier[identifier])
        (advisories / f"{identifier}.json").write_text(dossier.model_dump_json(indent=2))


def _write_docs(out: Path, backend: str | None) -> None:
    (out / "grammar_classes.md").write_text(ADMISSION_GRAMMAR_CLASSES)
    shutil.copyfile(NUISANCE_SUITE_RULE, out / "nuisance-suite-rule.md")
    (out / "confinement.md").write_text(admission_confinement_text())
    (out / "fixture_format.md").write_text(fixture_format(backend))
    (out / "README.md").write_text(admission_readme())
