import dataclasses
import json

import tests.unit.support.test_cve_layout_check_golden_given as given
from evals.cve_layout_check import admission_gave_up
from evals.cve_route import RouteObservations
from evals.cve_targets import CVE_TARGETS, LaunchMode

_A_TARGET = CVE_TARGETS[0]


def _observed(*, started: bool) -> RouteObservations:
    return RouteObservations(
        launch_command=(),
        scope=None,
        tool_names=(),
        responses=(),
        call_errored=(),
        tools_list_succeeded=started,
    )


def test_a_fallback_mode_target_gives_up_when_its_fallback_launch_fails_to_start():
    target = dataclasses.replace(_A_TARGET, launch_mode=LaunchMode.FALLBACK)

    assert (
        admission_gave_up(target, _observed(started=False)) == "the container cannot run the server"
    )


def test_a_fallback_mode_target_does_not_give_up_when_its_fallback_launch_starts():
    target = dataclasses.replace(_A_TARGET, launch_mode=LaunchMode.FALLBACK)

    assert admission_gave_up(target, _observed(started=True)) is None


def test_a_normal_mode_target_does_not_give_up_even_when_its_launch_fails():
    assert _A_TARGET.launch_mode is LaunchMode.NORMAL
    assert admission_gave_up(_A_TARGET, _observed(started=False)) is None


def test_the_layout_breaks_when_tools_list_is_lost_with_the_layout():
    assert given.golden_entries()["tools_list_lost_with_the_layout"]["breaks"] is True


def test_the_layout_breaks_when_a_call_errors_only_with_the_layout():
    assert given.golden_entries()["call_errors_only_with_the_layout"]["breaks"] is True


def test_no_break_when_both_surfaces_are_healthy():
    assert given.golden_entries()["both_healthy_no_break"]["breaks"] is False


def test_a_discovery_symlink_in_a_listing_is_not_a_break():
    assert (
        given.golden_entries()["discovery_symlink_in_a_listing_is_not_a_break"]["breaks"] is False
    )


def test_a_shifted_head_sha_is_not_a_break():
    assert given.golden_entries()["shifted_head_sha_is_not_a_break"]["breaks"] is False


def test_the_anti_leak_guard_flags_a_nonce_in_the_ordinary_surface():
    assert given.golden_entries()["nonce_leaks_into_the_ordinary_surface"]["leaks"] is True


def test_the_anti_leak_guard_passes_when_no_nonce_surfaces():
    assert given.golden_entries()["no_nonce_in_the_ordinary_surface"]["leaks"] is False


def test_layout_check_verdicts_match_the_golden_master():
    assert given.golden_entries() == json.loads(given.GOLDEN_PATH.read_text())
