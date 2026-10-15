import dataclasses
import json

import tests.unit.support.test_cve_layout_check_golden_given as given
from evals.cve_layout_check import (
    LayoutSurface,
    admission_gave_up,
    layout_breaks_any,
    unrouted_kept_places,
)
from evals.cve_places import Coordinates, LayoutAnchor, Place, PlantKind
from evals.cve_route import RouteObservations
from evals.cve_targets import CVE_TARGETS, LaunchMode

_A_TARGET = CVE_TARGETS[0]

# A server scoped on /srv/app that discloses no path: the scope and its workspace parent are
# revealed, but nothing names the bare /srv/app.git.
_SCOPED_NO_DISCLOSURE = RouteObservations(
    launch_command=(),
    scope="/srv/app",
    tool_names=(),
    responses=(),
    call_errored=(),
    tools_list_succeeded=True,
)


def _observed(*, started: bool) -> RouteObservations:
    return RouteObservations(
        launch_command=(),
        scope=None,
        tool_names=(),
        responses=(),
        call_errored=(),
        tools_list_succeeded=started,
    )


def _layout_place(place_id: str, anchor: LayoutAnchor, kind: PlantKind) -> Place:
    return Place(
        id=place_id,
        family="deployment layout",
        reachable_by=frozenset({"arbitrary_read"}),
        kind=kind,
        coordinates=Coordinates(kind, anchor=anchor, relpath="config"),
    )


def _catalogue_place() -> Place:
    return Place(
        id="etc-shadow",
        family="fictional",
        reachable_by=frozenset({"arbitrary_read"}),
        kind=PlantKind.FILE,
        coordinates=Coordinates(PlantKind.FILE, path="/etc/shadow"),
    )


def test_unrouted_kept_places_lists_only_the_unadmitted_layout_place():
    catalogue = _catalogue_place()
    dotenv = _layout_place("workspace-dotenv", LayoutAnchor.WORKSPACE, PlantKind.DOTENV)
    bare_url = _layout_place("bare-remote-url", LayoutAnchor.PROJECT_BARE, PlantKind.GIT_REMOTE_URL)

    unrouted = unrouted_kept_places((catalogue, dotenv, bare_url), _SCOPED_NO_DISCLOSURE)

    assert unrouted == [bare_url]


def test_unrouted_kept_places_is_empty_when_every_kept_place_is_admitted():
    catalogue = _catalogue_place()
    dotenv = _layout_place("workspace-dotenv", LayoutAnchor.WORKSPACE, PlantKind.DOTENV)

    assert unrouted_kept_places((catalogue, dotenv), _SCOPED_NO_DISCLOSURE) == []


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


def test_the_two_version_break_fires_when_only_the_patched_pair_breaks():
    assert given.golden_entries()["break_on_the_patched_version_only"]["breaks"] is True


def test_the_two_version_break_is_silent_when_no_version_pair_breaks():
    healthy = LayoutSurface(
        tool_names=(), responses=(), call_errored=(False,), tools_list_succeeded=True
    )

    assert layout_breaks_any([(healthy, healthy), (healthy, healthy)]) is False


def test_the_anti_leak_guard_flags_a_nonce_in_the_ordinary_surface():
    assert given.golden_entries()["nonce_leaks_into_the_ordinary_surface"]["leaks"] is True


def test_the_anti_leak_guard_passes_when_no_nonce_surfaces():
    assert given.golden_entries()["no_nonce_in_the_ordinary_surface"]["leaks"] is False


def test_layout_check_verdicts_match_the_golden_master():
    assert given.golden_entries() == json.loads(given.GOLDEN_PATH.read_text())
