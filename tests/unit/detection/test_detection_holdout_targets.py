import ast
import importlib.util
from collections.abc import Iterable
from pathlib import Path

import pytest

import tests.unit.detection.support.test_detection_holdout_targets_given as given
import tests.unit.support.fictional_planting as planting
from evals.cve.backends.kubernetes import CONTROL_PLANE_SERVICE
from evals.cve.detection.holdout_targets import HOLDOUT_TARGETS
from evals.cve.detection.targets import ACCEPTANCE_TARGETS, OUT_OF_SCOPE_FLAWS, Target
from evals.cve.layout import PROJECT, WORK
from evals.cve.places import (
    DETECTION_PLACES,
    REACHES,
    PlaceKind,
    kept_records,
    load_places,
)
from evals.cve.planting import planting_spec
from evals.cve.planting_base import SENTINEL_SERVICE, STAND_IN_SERVICE
from tests.unit.support.audited_launch_builders import AUDITED_LAUNCH_BUILDERS

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
    "cve/detection/no_llm_modes.py",
    "cve/detection/calibration_check_exit.py",
    "cve/launch_audit.py",
)

_EVALS = Path(__file__).resolve().parents[3] / "evals"
_HOLDOUT_TARGET_MODULE = "evals.cve.detection.holdout_targets"


def test_the_holdout_targets_are_the_census_drawn_flaws():
    # The run reads HOLDOUT_TARGETS and the census records draw.drawn: a flaw in one and not the
    # other would be skipped or refused silently. The orders differ (transplant against draw).
    assert {target.flaw_id for target in HOLDOUT_TARGETS} == given.the_census_drawn_identifiers()


def test_holdout_identifiers_are_disjoint_from_the_acceptance_layer():
    holdout_ids = {target.flaw_id for target in HOLDOUT_TARGETS}
    acceptance_ids = {target.flaw_id for target in ACCEPTANCE_TARGETS}
    acceptance_ids |= {out.flaw_id for out in OUT_OF_SCOPE_FLAWS}

    assert holdout_ids.isdisjoint(acceptance_ids), (
        "a flaw cannot be both an acceptance and a holdout target"
    )


def test_holdout_services_are_disjoint_from_the_acceptance_services():
    assert _services(HOLDOUT_TARGETS)
    assert _services(HOLDOUT_TARGETS).isdisjoint(_services(ACCEPTANCE_TARGETS))


# The sentinel, the stand-in and the Kubernetes control plane are the fixture images targets share,
# so a holdout target may list them.
def _services(targets: Iterable[Target]) -> set[str]:
    services = {name for target in targets for name in (*target.images, target.patched_image)}
    return services - {SENTINEL_SERVICE, STAND_IN_SERVICE, CONTROL_PLANE_SERVICE}


# A baked `/work` is a nuisance fix check's: detection suite rule v11 gives a target's `/work` the
# empty tmpfs.
def test_no_acceptance_or_holdout_target_bakes_its_work_directory():
    for target in (*ACCEPTANCE_TARGETS, *HOLDOUT_TARGETS):
        assert not target.planting_host.baked_work, target.flaw_id


# The image's own `/work` would sit under the per-launch tmpfs the planting code mounts there, so a
# target that needs a writable project bakes it elsewhere.
def test_no_acceptance_or_holdout_image_names_a_path_under_work():
    services = {
        service
        for target in (*ACCEPTANCE_TARGETS, *HOLDOUT_TARGETS)
        for service in (*target.images, target.server_image, target.patched_image)
    }

    for service in sorted(services):
        assert given.the_instructions_naming_work_in(service) == [], service


# Rule v11 starts a target in the checkout, or in the empty `/work` when it cannot write there.
def test_every_holdout_target_starts_in_the_checkout_or_work():
    for target in HOLDOUT_TARGETS:
        assert target.planting_host.working_directory in {PROJECT, WORK}, target.flaw_id


def test_no_holdout_target_carries_a_tools_filter_or_a_ci_skip():
    for target in HOLDOUT_TARGETS:
        assert target.tools_filter is None
        assert target.ci_skip_reason is None


def test_only_the_desktop_commander_and_frogman_targets_settle_a_leak_at_calibration():
    settled = {t.flaw_id: t.settled_leaks for t in [*ACCEPTANCE_TARGETS, *HOLDOUT_TARGETS]}

    assert {flaw_id: leaks for flaw_id, leaks in settled.items() if leaks} == {
        "CVE-2025-11489": frozenset({"container-hostname"}),
        "CVE-2026-46514": frozenset({"container-hostname"}),
    }


def test_every_settled_leak_is_a_kept_place():
    for target in [*ACCEPTANCE_TARGETS, *HOLDOUT_TARGETS]:
        assert target.settled_leaks <= set(target.kept_places), target.flaw_id


@pytest.mark.parametrize(
    "target",
    [
        target
        for target in (*ACCEPTANCE_TARGETS, *HOLDOUT_TARGETS)
        if AUDITED_LAUNCH_BUILDERS[target.builder].backend_sources
        or AUDITED_LAUNCH_BUILDERS[target.builder].images
    ],
    ids=lambda target: target.flaw_id,
)
def test_a_target_fingerprints_the_backend_modules_and_builds_the_images_of_its_builder(
    target: Target,
):
    builder = AUDITED_LAUNCH_BUILDERS[target.builder]

    assert builder.backend_sources <= set(target.backend_sources)
    assert builder.images <= set(target.images)


# The a11y images inline a copy of the fixture authority into Chromium's NSS store: a regeneration
# of the authority leaves that copy stale until both Dockerfiles take the new one and are rebuilt.
def test_the_a11y_images_bake_the_committed_fixture_authority():
    a11y = next(target for target in HOLDOUT_TARGETS if target.flaw_id == "CVE-2026-5323")
    committed = (_EVALS / "stand_ins" / "tls" / "fixture-authority.pem").read_text()

    for service in (a11y.server_image, a11y.patched_image):
        dockerfile = _EVALS / "docker" / f"Dockerfile.{service}"
        assert given.the_authority_inlined_in(dockerfile) == committed, service


def test_every_backend_image_is_pinned_by_digest():
    targets = [*HOLDOUT_TARGETS, *ACCEPTANCE_TARGETS]
    unpinned = [
        image for target in targets for image in target.backend_images if "@sha256:" not in image
    ]

    assert unpinned == []


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


# The per-target structural guards below mirror test_cve_places.py over HOLDOUT_TARGETS: every
# kept id is in detection_places.json within its target's reach, every reach token is in the closed
# vocabulary, no kept place is unplaceable, and the kept list plants together.


def test_every_holdout_target_reaches_only_the_closed_vocabulary():
    for target in HOLDOUT_TARGETS:
        assert target.reaches <= REACHES, (
            f"{target.flaw_id}: reaches holds a token outside the closed vocabulary"
        )


def test_every_holdout_kept_place_is_offered_within_its_reach():
    places = load_places(DETECTION_PLACES)
    for target in HOLDOUT_TARGETS:
        for place_id in target.kept_places:
            assert place_id in places, f"{target.flaw_id}: keeps {place_id}, absent from the file"
            assert places[place_id].reaches & target.reaches, (
                f"{target.flaw_id}: keeps {place_id}, reachable by none of its reach"
            )


def test_no_holdout_target_keeps_an_unplaceable_place():
    places = load_places(DETECTION_PLACES)
    for target in HOLDOUT_TARGETS:
        for record in kept_records(target.kept_places, places):
            assert record.kind is not PlaceKind.UNPLACEABLE, (
                f"{target.flaw_id}: keeps {record.id}, an unplaceable place"
            )


def test_every_holdout_kept_list_plants_together():
    places = load_places(DETECTION_PLACES)
    for target in HOLDOUT_TARGETS:
        planting_spec(
            kept_records(target.kept_places, places),
            target.planting_host,
            planting.FakeNonces(),
        )
