"""The pin that keeps the holdout kit free of mcp_auditor, the way the acceptance conformance
phase had to be re-pinned: the written kit's import closure, a static scan of the kit, a
negative control, and the KitTarget/CVETarget field transplant rule."""

from dataclasses import fields
from pathlib import Path

import tests.unit.support.holdout_kit_isolation as iso
import tests.unit.support.test_census_given as census_given
from evals.calibration_dossier import write_kit
from evals.cve_targets import CVETarget
from evals.holdout_kit.fix_check import FixCheckResult
from evals.holdout_kit.kit_target import KitTarget
from evals.nuisance_admission import FixCheckRecord

_KIT_DIR = iso.REPO_ROOT / "evals" / "holdout_kit"


def test_the_written_kit_imports_from_its_own_tree_with_no_mcp_auditor_module(tmp_path: Path):
    out = tmp_path / "kit"
    write_kit(census_given.a_census(), census_given.FLAW_WITH_A_CVE, out)

    assert iso.import_closure_offenders(iso.kit_modules(out), root=out) == []


def test_no_kit_file_imports_mcp_auditor():
    assert iso.scan_tree(_KIT_DIR) == {}


def test_scan_flags_a_planted_mcp_auditor_import(tmp_path: Path):
    planted = tmp_path / "kit_client.py"
    planted.write_text(
        (_KIT_DIR / "kit_client.py").read_text() + "\nimport mcp_auditor  # negative control\n"
    )
    assert iso.scan_tree(tmp_path) == {str(planted): ["mcp_auditor"]}


# A drawn target is a CVETarget the maintainer wraps a KitTarget into, so every KitTarget field
# must exist on CVETarget for the transplant.
def test_kit_target_fields_are_cve_target_fields():
    kit_names = {field.name for field in fields(KitTarget)}
    assert kit_names <= {field.name for field in fields(CVETarget)}


def test_fix_check_result_mirrors_the_admission_record_fields():
    # relies_on_relaying_stand_in is a judgment the admission records and holdout_fingerprint the
    # provenance of a copied calibration: the kit observes neither.
    recorded = set(FixCheckRecord.model_fields) - {
        "relies_on_relaying_stand_in",
        "holdout_fingerprint",
    }
    assert {field.name for field in fields(FixCheckResult)} == recorded
