import dataclasses
import re
from pathlib import Path

import pytest

import tests.unit.support.test_cve_baseline_given as given
from evals.cve_baseline import (
    CVETargetBaseline,
    baseline_integrity,
    fixture_fingerprint,
    load_baselines,
    write_baseline,
)
from evals.cve_grammar import CVEStatus
from evals.cve_places import LayoutAnchor

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


def test_two_targets_sharing_an_image_and_a_builder_but_not_an_aim_differ():
    one = dataclasses.replace(given.SYMLINK_TARGET, aim=re.compile(r"(^|/)report$"))
    other = dataclasses.replace(given.SYMLINK_TARGET, aim=re.compile(r"^/srv/app[^/]"))

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
    ids=["exploratory", "confirmed, every run detected", "confirmed, one miss"],
)
def test_only_a_confirmed_baseline_detected_in_every_run_is_gated(
    baseline: CVETargetBaseline, detected_runs: list[bool], gated: bool
):
    assert baseline.detected_runs() == detected_runs
    assert baseline.gated() is gated


@pytest.mark.parametrize(
    "baseline",
    [given.a_baseline([DETECTED] * 3), given.a_confirmation([DETECTED] * 6)],
    ids=["runs", "twice runs with a confirmation"],
)
def test_integrity_accepts_the_runs_its_conditions_claim(baseline: CVETargetBaseline):
    assert baseline_integrity(baseline) == []


@pytest.mark.parametrize(
    "baseline",
    [given.a_baseline([DETECTED] * 6), given.a_confirmation([DETECTED] * 3), given.a_baseline([])],
    ids=["twice runs without a confirmation", "runs with a confirmation", "no run"],
)
def test_integrity_names_a_run_count_its_conditions_do_not_claim(baseline: CVETargetBaseline):
    assert len(baseline_integrity(baseline)) == 1


def test_a_written_baseline_loads_back_keyed_by_its_cve(tmp_path: Path):
    baseline = given.a_confirmation([DETECTED, DETECTED, MISSED] * 2)

    write_baseline(tmp_path / "cve", baseline)

    assert load_baselines(tmp_path / "cve") == {baseline.cve_id: baseline}


def test_a_missing_directory_loads_as_no_baseline(tmp_path: Path):
    assert load_baselines(tmp_path / "absent") == {}


def test_a_file_named_after_another_cve_is_refused(tmp_path: Path):
    baseline = given.a_baseline([DETECTED] * 3)
    (tmp_path / "CVE-2025-65513.json").write_text(baseline.model_dump_json())

    with pytest.raises(ValueError, match="CVE-2025-65513"):
        load_baselines(tmp_path)
