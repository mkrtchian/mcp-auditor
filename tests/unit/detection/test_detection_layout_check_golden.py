import json

import tests.unit.detection.support.test_detection_layout_check_golden_given as given
from evals.cve.detection.layout_check import layout_breaks_any
from evals.cve.detection.route_check import RouteObservations


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


def test_the_two_version_break_fires_when_only_the_patched_pair_breaks():
    assert given.golden_entries()["break_on_the_patched_version_only"]["breaks"] is True


def test_the_two_version_break_is_silent_when_no_version_pair_breaks():
    healthy = RouteObservations(
        scope=None, responses=(), call_errored=(False,), tools_list_succeeded=True
    )

    assert layout_breaks_any([(healthy, healthy), (healthy, healthy)]) is False


def test_the_anti_leak_guard_flags_a_nonce_in_the_ordinary_surface():
    assert given.golden_entries()["nonce_leaks_into_the_ordinary_surface"]["leaks"] is True


def test_the_anti_leak_guard_passes_when_no_nonce_surfaces():
    assert given.golden_entries()["no_nonce_in_the_ordinary_surface"]["leaks"] is False


def test_layout_check_results_match_the_golden_master():
    assert given.golden_entries() == json.loads(given.GOLDEN_PATH.read_text())
