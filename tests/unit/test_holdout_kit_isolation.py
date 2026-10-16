"""The pin that keeps the holdout kit free of mcp_auditor, the way the acceptance conformance
phase had to be re-pinned: the kit's import closure, a static scan of the kit and the clean
modules the dossier copies, a negative control, and the KitTarget/CVETarget field parity."""

from dataclasses import fields
from pathlib import Path

import tests.unit.support.holdout_kit_isolation as iso
from evals.cve_targets import CVETarget
from evals.holdout_kit.kit_target import KitTarget

_KIT_DIR = iso.REPO_ROOT / "evals" / "holdout_kit"
_KIT_MODULES = [
    "evals.holdout_kit.kit_client",
    "evals.holdout_kit.kit_launch",
    "evals.holdout_kit.kit_target",
    "evals.holdout_kit.kit_driver",
]
_COPIED_CLEAN_MODULES = [
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
]

# HoldoutTarget is a composition HoldoutTarget(target: CVETarget, side: Side), so the parity the
# transplant needs is between KitTarget's fields and CVETarget's: the maintainer wraps a KitTarget
# into a CVETarget (these fields) then into HoldoutTarget(target, side). `side` is the one KitTarget
# field that maps to HoldoutTarget rather than to CVETarget.
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


def test_kit_import_closure_holds_no_mcp_auditor_module():
    assert iso.import_closure_offenders(_KIT_MODULES) == []


def test_no_kit_file_imports_mcp_auditor():
    assert iso.scan_tree(_KIT_DIR) == {}


def test_no_copied_clean_module_imports_mcp_auditor():
    offenders: dict[str, list[str]] = {}
    for name in _COPIED_CLEAN_MODULES:
        path = iso.REPO_ROOT / "evals" / f"{name}.py"
        found = iso.mcp_auditor_imports(path.read_text(), str(path))
        if found:
            offenders[str(path)] = found
    assert offenders == {}


def test_scan_flags_a_planted_mcp_auditor_import(tmp_path: Path):
    planted = tmp_path / "kit_client.py"
    planted.write_text(
        (_KIT_DIR / "kit_client.py").read_text() + "\nimport mcp_auditor  # negative control\n"
    )
    assert iso.scan_tree(tmp_path) == {str(planted): ["mcp_auditor"]}


def test_kit_target_mirrors_the_drawn_cve_target_fields():
    kit_names = {field.name for field in fields(KitTarget)}
    cve_names = {field.name for field in fields(CVETarget)}
    assert "side" in kit_names
    assert kit_names - {"side"} == _DRAWN_TARGET_FIELDS
    assert cve_names >= _DRAWN_TARGET_FIELDS
