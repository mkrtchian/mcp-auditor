from collections.abc import Iterable

import pytest

import tests.integration.committed.detection.support.test_detection_holdout_targets_given as given
from evals.cve.backends.kubernetes import CONTROL_PLANE_SERVICE
from evals.cve.detection.holdout_targets import HOLDOUT_TARGETS
from evals.cve.detection.targets import ACCEPTANCE_TARGETS, OUT_OF_SCOPE_FLAWS, Target
from evals.cve.layout import PROJECT, WORK
from evals.cve.planting_base import SENTINEL_SERVICE, STAND_IN_SERVICE
from evals.repository import REPO_ROOT
from tests.unit.support.audited_launch_builders import AUDITED_LAUNCH_BUILDERS

_EVALS = REPO_ROOT / "evals"


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


# Detection suite rule v11 starts a target in the checkout, or in the empty `/work` when it
# cannot write there.
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
