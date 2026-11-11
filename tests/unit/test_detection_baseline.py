import dataclasses
import re
from pathlib import Path

import pytest

import tests.unit.support.test_detection_baseline_given as given
from evals.cve.detection.baseline import (
    DetectionBaseline,
    baseline_integrity,
    fixture_fingerprint,
    load_baselines,
    planting_host_parts,
    write_baseline,
)
from evals.cve.detection.targets import ACCEPTANCE_TARGETS
from evals.cve_grammar import CVEStatus
from evals.cve_places import LayoutAnchor
from evals.cve_planting_base import STAND_IN_SERVICE, PlantingHost, SymbolicUser
from evals.holdout_targets import HOLDOUT_TARGETS

DETECTED = CVEStatus.DETECTED
MISSED = CVEStatus.MISSED


@pytest.mark.parametrize(
    "change", given.FINGERPRINTED_CHANGES.values(), ids=list(given.FINGERPRINTED_CHANGES)
)
def test_the_fixture_fingerprint_moves_with_what_builds_or_reaches_the_target(
    change: given.TargetChange, tmp_path: Path
):
    docker_directory = given.a_docker_directory(tmp_path)
    target, places = given.a_target_keeping_an_endpoint()
    before = fixture_fingerprint(target, places, docker_directory)

    changed_target, changed_places = change(target, places, docker_directory)

    assert fixture_fingerprint(changed_target, changed_places, docker_directory) != before


@pytest.mark.parametrize(
    "change", given.UNFINGERPRINTED_CHANGES.values(), ids=list(given.UNFINGERPRINTED_CHANGES)
)
def test_the_fixture_fingerprint_ignores_what_neither_builds_nor_reaches_the_target(
    change: given.TargetChange, tmp_path: Path
):
    docker_directory = given.a_docker_directory(tmp_path)
    target, places = given.a_target_keeping_a_file()
    before = fixture_fingerprint(target, places, docker_directory)

    changed_target, changed_places = change(target, places, docker_directory)

    assert fixture_fingerprint(changed_target, changed_places, docker_directory) == before


@pytest.mark.parametrize(
    "change", given.STAND_IN_CHANGES.values(), ids=list(given.STAND_IN_CHANGES)
)
def test_the_fixture_fingerprint_moves_with_what_a_declared_stand_in_serves(
    change: given.StandInChange, tmp_path: Path
):
    stand_ins = given.a_stand_ins_directory(tmp_path)
    target, places = given.a_target_declaring_a_stand_in()
    before = fixture_fingerprint(target, places, stand_ins_directory=stand_ins)

    changed_target = change(target, stand_ins)

    assert fixture_fingerprint(changed_target, places, stand_ins_directory=stand_ins) != before


def test_the_fixture_fingerprint_moves_when_a_backend_source_changes(tmp_path: Path):
    target, places = given.a_target_seeding_a_backend(tmp_path)
    before = fixture_fingerprint(target, places)

    given.rewriting_the_backend_source(target)

    assert fixture_fingerprint(target, places) != before


def test_a_read_only_host_is_its_user_working_directory_and_network_stance_alone():
    host = PlantingHost(SymbolicUser.UNPRIVILEGED, "/srv/app", has_network=True)

    assert planting_host_parts(host) == ["unprivileged", "/srv/app", True]


def test_a_target_without_public_names_reads_no_stand_in(tmp_path: Path):
    target, places = given.a_target_keeping_a_file()

    absent = fixture_fingerprint(target, places, stand_ins_directory=tmp_path / "absent")

    assert absent == fixture_fingerprint(target, places)


def test_a_target_declaring_a_stand_in_builds_the_stand_in_image():
    declaring = [
        target
        for target in (*ACCEPTANCE_TARGETS, *HOLDOUT_TARGETS)
        if target.planting_host.public_names.stand_ins
    ]

    assert not [target.flaw_id for target in declaring if STAND_IN_SERVICE not in target.images]


def test_two_targets_sharing_an_image_and_a_builder_but_not_an_aim_differ():
    base = dataclasses.replace(given.SYMLINK_TARGET, kept_places=())
    one = dataclasses.replace(base, aim=re.compile(r"(^|/)report$"))
    other = dataclasses.replace(base, aim=re.compile(r"^/srv/app[^/]"))

    assert fixture_fingerprint(one, {}) != fixture_fingerprint(other, {})


def test_the_fixture_fingerprint_moves_when_a_kept_layout_coordinate_moves():
    target, places = given.a_target_keeping_a_layout_place()
    before = fixture_fingerprint(target, places)

    moved_relpath = {given.KEPT_LAYOUT_ID: given.a_layout_record(relpath="other")}
    moved_anchor = {given.KEPT_LAYOUT_ID: given.a_layout_record(anchor=LayoutAnchor.WORKSPACE)}

    assert fixture_fingerprint(target, moved_relpath) != before
    assert fixture_fingerprint(target, moved_anchor) != before


@pytest.mark.parametrize(
    ("baseline", "detected_runs", "gated"),
    [
        (given.a_baseline([DETECTED, DETECTED, DETECTED]), [True, True, True], False),
        (
            given.a_confirmation([DETECTED] * 6),
            [True] * 6,
            True,
        ),
        (
            given.a_confirmation([DETECTED, DETECTED, DETECTED, DETECTED, MISSED, DETECTED]),
            [True, True, True, True, False, True],
            False,
        ),
    ],
    ids=["unconfirmed", "confirmed, every run detected", "confirmed, one miss"],
)
def test_only_a_confirmed_baseline_detected_in_every_run_is_gated(
    baseline: DetectionBaseline, detected_runs: list[bool], gated: bool
):
    assert baseline.detected_runs() == detected_runs
    assert baseline.gated() is gated


@pytest.mark.parametrize(
    "baseline",
    [given.a_baseline([DETECTED] * 3), given.a_confirmation([DETECTED] * 6)],
    ids=["runs", "twice runs with a confirmation"],
)
def test_integrity_accepts_the_runs_its_conditions_claim(baseline: DetectionBaseline):
    assert baseline_integrity(baseline) == []


@pytest.mark.parametrize(
    "baseline",
    [given.a_baseline([DETECTED] * 6), given.a_confirmation([DETECTED] * 3), given.a_baseline([])],
    ids=["twice runs without a confirmation", "runs with a confirmation", "no run"],
)
def test_integrity_names_a_run_count_its_conditions_do_not_claim(baseline: DetectionBaseline):
    assert len(baseline_integrity(baseline)) == 1


def test_a_written_baseline_loads_back_keyed_by_its_cve(tmp_path: Path):
    baseline = given.a_confirmation([DETECTED, DETECTED, MISSED] * 2)

    write_baseline(tmp_path / "detection", baseline)

    assert load_baselines(tmp_path / "detection") == {baseline.flaw_id: baseline}


def test_a_missing_directory_loads_as_no_baseline(tmp_path: Path):
    assert load_baselines(tmp_path / "absent") == {}


def test_a_file_named_after_another_cve_is_refused(tmp_path: Path):
    baseline = given.a_baseline([DETECTED] * 3)
    (tmp_path / "CVE-2025-65513.json").write_text(baseline.model_dump_json())

    with pytest.raises(ValueError, match="CVE-2025-65513"):
        load_baselines(tmp_path)
