import ast
from pathlib import Path

import tests.unit.support.test_cve_planting_given as planting_given
from evals.census_draw import Side
from evals.cve_places import (
    HOLDOUT_PLACES,
    REACHABLE_BY,
    PlantKind,
    kept_records,
    load_places,
)
from evals.cve_planting import planting_spec
from evals.cve_targets import CVE_TARGETS, OUT_OF_SCOPE_CVES
from evals.holdout_targets import HOLDOUT_TARGETS, HoldoutTarget

# These modules are the paths a holdout target must never travel: the acceptance gate
# (cve_session_model's _BENCHMARKED = CVE_TARGETS), the preflight, the judge fixture draw
# (seeded from CVE_TARGETS) and the probe corpus (iterated over CVE_TARGETS). A plain
# `import evals.holdout_targets` in any of them would let a holdout flaw reach the measured
# instruments, so the AST scan pins them clean.
_INSTRUMENTS = (
    "cve_session_model",
    "cve_preflight",
    "draw_judge_cases",
    "capture_probe_corpus",
    "run_cve_benchmark",
)

_EVALS = Path(__file__).resolve().parents[2] / "evals"


def test_the_empty_holdout_target_tuple_loads():
    assert HOLDOUT_TARGETS == ()
    assert all(isinstance(entry, HoldoutTarget) for entry in HOLDOUT_TARGETS)


def test_identifier_reads_from_the_composed_target():
    for entry in HOLDOUT_TARGETS:
        assert entry.identifier == entry.target.cve_id
        assert isinstance(entry.side, Side)


def test_holdout_identifiers_are_disjoint_from_the_acceptance_layer():
    holdout_ids = {entry.target.cve_id for entry in HOLDOUT_TARGETS}
    acceptance_ids = {target.cve_id for target in CVE_TARGETS}
    acceptance_ids |= {out.cve_id for out in OUT_OF_SCOPE_CVES}

    assert holdout_ids.isdisjoint(acceptance_ids), (
        "a flaw cannot be both an acceptance and a holdout target"
    )


def test_no_holdout_target_carries_a_tools_filter_or_a_ci_skip():
    for entry in HOLDOUT_TARGETS:
        assert entry.target.tools_filter is None
        assert entry.target.ci_skip_reason is None


def test_no_instrument_imports_the_holdout_target_module():
    for module_name in _INSTRUMENTS:
        assert not _imports_holdout_targets(_EVALS / f"{module_name}.py"), (
            f"{module_name} imports evals.holdout_targets, so a holdout target could reach it"
        )


def _imports_holdout_targets(path: Path) -> bool:
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "evals.holdout_targets":
            return True
        if isinstance(node, ast.Import) and any(
            alias.name == "evals.holdout_targets" for alias in node.names
        ):
            return True
    return False


# The per-target structural guards below mirror test_cve_places.py over HOLDOUT_TARGETS: every
# kept id is in holdout_places.json within its target's reach, every reach token is in the closed
# vocabulary, no kept place is unplaceable, and the kept list plants together. They are trivially
# satisfied while the tuple is empty; they are the guard for the module once the draw fills it.


def test_every_holdout_target_reaches_only_the_closed_vocabulary():
    for entry in HOLDOUT_TARGETS:
        assert entry.target.reaches <= REACHABLE_BY, (
            f"{entry.identifier}: reaches holds a token outside the closed vocabulary"
        )


def test_every_holdout_kept_place_is_offered_within_its_reach():
    places = load_places(HOLDOUT_PLACES)
    for entry in HOLDOUT_TARGETS:
        for place_id in entry.target.kept_places:
            assert place_id in places, f"{entry.identifier}: keeps {place_id}, absent from the file"
            assert places[place_id].reachable_by & entry.target.reaches, (
                f"{entry.identifier}: keeps {place_id}, reachable by none of its reach"
            )


def test_no_holdout_target_keeps_an_unplaceable_place():
    places = load_places(HOLDOUT_PLACES)
    for entry in HOLDOUT_TARGETS:
        for record in kept_records(entry.target.kept_places, places):
            assert record.kind is not PlantKind.UNPLACEABLE, (
                f"{entry.identifier}: keeps {record.id}, an unplaceable place"
            )


def test_every_holdout_kept_list_plants_together():
    places = load_places(HOLDOUT_PLACES)
    for entry in HOLDOUT_TARGETS:
        planting_spec(
            kept_records(entry.target.kept_places, places),
            entry.target.planting_host,
            planting_given.FakeNonces(),
        )
