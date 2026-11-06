import ast
from collections.abc import Iterable
from pathlib import Path

import tests.unit.support.test_cve_planting_given as planting_given
import tests.unit.support.test_holdout_targets_given as given
from evals import doris_backend, n8n_instance_backend
from evals.cve_places import (
    HOLDOUT_PLACES,
    REACHABLE_BY,
    PlantKind,
    kept_records,
    load_places,
)
from evals.cve_planting import SymbolicUser, planting_spec
from evals.cve_planting_base import SENTINEL_SERVICE, STAND_IN_SERVICE
from evals.cve_targets import CVE_TARGETS, OUT_OF_SCOPE_CVES, CVETarget
from evals.holdout_targets import HOLDOUT_TARGETS

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
    "cve_benchmark_modes",
    "admission_calibration",
    "launch_audit",
)

_EVALS = Path(__file__).resolve().parents[2] / "evals"


def test_the_holdout_targets_are_the_census_drawn_flaws():
    # The run reads HOLDOUT_TARGETS and the census records draw.drawn: a flaw in one and not the
    # other would be skipped or refused silently. The orders differ (transplant against draw).
    assert {target.cve_id for target in HOLDOUT_TARGETS} == given.the_census_drawn_identifiers()


def test_holdout_identifiers_are_disjoint_from_the_acceptance_layer():
    holdout_ids = {target.cve_id for target in HOLDOUT_TARGETS}
    acceptance_ids = {target.cve_id for target in CVE_TARGETS}
    acceptance_ids |= {out.cve_id for out in OUT_OF_SCOPE_CVES}

    assert holdout_ids.isdisjoint(acceptance_ids), (
        "a flaw cannot be both an acceptance and a holdout target"
    )


def test_holdout_services_are_disjoint_from_the_acceptance_services():
    assert _services(HOLDOUT_TARGETS)
    assert _services(HOLDOUT_TARGETS).isdisjoint(_services(CVE_TARGETS))


# The sentinel and the stand-in are the fixture images targets share, so a holdout target may
# list them.
def _services(targets: Iterable[CVETarget]) -> set[str]:
    services = {name for target in targets for name in (*target.images, target.patched_image)}
    return services - {SENTINEL_SERVICE, STAND_IN_SERVICE}


# A baked `/work` is a nuisance fix check's: rule v11 gives a CVE target's `/work` the empty tmpfs.
def test_no_acceptance_or_holdout_target_bakes_its_work_directory():
    for target in (*CVE_TARGETS, *HOLDOUT_TARGETS):
        assert not target.planting_host.baked_work, target.cve_id


# Version 11 runs every target under the unprivileged account: the host uid is a
# benchmark-machine value that must not reach the launch.
def test_no_holdout_target_runs_as_the_host_user():
    for target in HOLDOUT_TARGETS:
        assert target.planting_host.user is not SymbolicUser.HOST, target.cve_id


def test_no_holdout_target_carries_a_tools_filter_or_a_ci_skip():
    for target in HOLDOUT_TARGETS:
        assert target.tools_filter is None
        assert target.ci_skip_reason is None


def test_the_doris_target_fingerprints_the_module_that_seeds_its_backend():
    doris = next(target for target in HOLDOUT_TARGETS if target.cve_id == "CVE-2025-66335")

    assert Path(doris_backend.__file__) in doris.backend_sources


def test_the_n8n_target_fingerprints_the_module_that_provisions_its_instance():
    n8n = next(target for target in HOLDOUT_TARGETS if target.cve_id == "GHSA-8g7g-hmwm-6rv2")

    assert Path(n8n_instance_backend.__file__) in n8n.backend_sources


def test_every_backend_image_is_pinned_by_digest():
    targets = [*HOLDOUT_TARGETS, *CVE_TARGETS]
    unpinned = [
        image for target in targets for image in target.backend_images if "@sha256:" not in image
    ]

    assert unpinned == []


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
    for target in HOLDOUT_TARGETS:
        assert target.reaches <= REACHABLE_BY, (
            f"{target.cve_id}: reaches holds a token outside the closed vocabulary"
        )


def test_every_holdout_kept_place_is_offered_within_its_reach():
    places = load_places(HOLDOUT_PLACES)
    for target in HOLDOUT_TARGETS:
        for place_id in target.kept_places:
            assert place_id in places, f"{target.cve_id}: keeps {place_id}, absent from the file"
            assert places[place_id].reachable_by & target.reaches, (
                f"{target.cve_id}: keeps {place_id}, reachable by none of its reach"
            )


def test_no_holdout_target_keeps_an_unplaceable_place():
    places = load_places(HOLDOUT_PLACES)
    for target in HOLDOUT_TARGETS:
        for record in kept_records(target.kept_places, places):
            assert record.kind is not PlantKind.UNPLACEABLE, (
                f"{target.cve_id}: keeps {record.id}, an unplaceable place"
            )


def test_every_holdout_kept_list_plants_together():
    places = load_places(HOLDOUT_PLACES)
    for target in HOLDOUT_TARGETS:
        planting_spec(
            kept_records(target.kept_places, places),
            target.planting_host,
            planting_given.FakeNonces(),
        )
