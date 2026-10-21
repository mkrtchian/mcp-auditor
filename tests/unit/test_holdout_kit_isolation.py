"""The pin that keeps the holdout kit free of mcp_auditor, the way the acceptance conformance
phase had to be re-pinned: the written kit's import closure, a static scan of the kit, a
negative control, and the KitTarget/CVETarget field parity."""

from dataclasses import fields
from pathlib import Path

import tests.unit.support.holdout_kit_isolation as iso
import tests.unit.support.test_holdout_census_given as census_given
from evals.calibration_dossier import write_kit
from evals.cve_targets import CVETarget
from evals.holdout_kit.kit_target import KitTarget

_KIT_DIR = iso.REPO_ROOT / "evals" / "holdout_kit"

# A drawn target is a CVETarget, so the parity the transplant needs is between KitTarget's fields
# and CVETarget's: the maintainer wraps a KitTarget into a CVETarget (these fields).
_DRAWN_TARGET_FIELDS = frozenset(
    {
        "cve_id",
        "mechanism",
        "aim",
        "reaches",
        "kept_places",
        "images",
        "server_image",
        "patched_image",
        "planting_host",
        "builder",
        "exploits",
        "benign",
        "launch_mode",
        "fallback_scope",
    }
)


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


def test_kit_target_mirrors_the_drawn_cve_target_fields():
    kit_names = {field.name for field in fields(KitTarget)}
    cve_names = {field.name for field in fields(CVETarget)}
    assert kit_names == _DRAWN_TARGET_FIELDS
    assert cve_names >= _DRAWN_TARGET_FIELDS
