import ast
import importlib.util
from pathlib import Path

# These modules are the paths a holdout target must never travel: the detection gate
# (session_model's _BENCHMARKED = ACCEPTANCE_TARGETS), the preflight, the judge fixture draw
# (seeded from ACCEPTANCE_TARGETS) and the probe corpus (iterated over ACCEPTANCE_TARGETS). A plain
# import of the holdout target module in any of them would let a holdout flaw reach the measured
# instruments, so the AST scan pins them clean.
_INSTRUMENTS = (
    "cve/detection/session_model.py",
    "detection_preflight.py",
    "draw_judge_cases.py",
    "capture_probe_corpus.py",
    "run_detection.py",
    "cve/detection/command_deps.py",
    "cve/detection/calibration_check_exit.py",
    "cve/launch_audit.py",
)

_EVALS = Path(__file__).resolve().parents[3] / "evals"
_HOLDOUT_TARGET_MODULE = "evals.cve.detection.holdout_targets"


def test_every_instrument_the_scan_reads_exists():
    assert [path for path in _INSTRUMENTS if not (_EVALS / path).is_file()] == []


def test_the_module_the_scan_looks_for_exists():
    assert importlib.util.find_spec(_HOLDOUT_TARGET_MODULE) is not None


def test_no_instrument_imports_the_holdout_target_module():
    for path in _INSTRUMENTS:
        assert not _imports_holdout_targets(_EVALS / path), (
            f"{path} imports {_HOLDOUT_TARGET_MODULE}, so a holdout target could reach it"
        )


def _imports_holdout_targets(path: Path) -> bool:
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == _HOLDOUT_TARGET_MODULE:
            return True
        if isinstance(node, ast.Import) and any(
            alias.name == _HOLDOUT_TARGET_MODULE for alias in node.names
        ):
            return True
    return False
