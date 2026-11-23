"""The layout break detector and the anti-leak guard (ADR 031).

The rule gates a fallback launch on a break: launch each version once with a minimal valid empty
node at each layout path, by node type (the reference arm), and once with the layout, and call it a
break when the launch or tools/list succeeded without the layout and failed with it, or when a call
that returned no error without the layout returns one with it. `layout_breaks` is the pure detector
over the two collected surfaces for one version, `layout_breaks_any` over both versions (a break on
either is a break). A changed response body (a discovery symlink in a listing, a shifted
deterministic HEAD SHA) is not a break: only a lost tools/list or a newly-erroring call counts.

The anti-leak guard (`nonce_in_surface`) is a separate pure check of the planted surface,
implementing a distinct clause of the rule: a place the server itself reads at launch is not kept
(detection-suite-rule.md, Deployment layout (A place is kept for a target)), so no planted nonce may
appear in the server's ordinary surface. Both are pinned by a golden master. The benign call is not
run here.

`layout_failure` is the one reading of the result that fails a target, shared by the calibration
check and by the pre-run checks of a graded run and of a detection holdout run. Its items are the
layout items of the check that proves a repair (detection-suite-log.md, version 13).
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from evals.cve.detection.route_check import RouteObservations, has_route
from evals.cve.detection.targets import LaunchMode, Target
from evals.cve.places import Place, Places

_GAVE_UP_REASON = "the container cannot run the server"


@dataclass(frozen=True)
class LayoutRoute:
    place_id: str
    kept: bool
    routed: bool


@dataclass(frozen=True)
class VersionObservation:
    reference: RouteObservations
    planted: RouteObservations
    nonces: Mapping[str, str]  # the planted arm's nonce per place id; the reference arm plants none


@dataclass(frozen=True)
class LayoutCheck:
    gave_up: str | None
    breaks: bool
    leaking: list[str]
    unrouted: list[str]


def layout_check(
    target: Target,
    records: Sequence[Place],
    vuln: VersionObservation,
    patched: VersionObservation,
) -> LayoutCheck:
    gave_up = layout_check_gave_up(target, vuln.planted) or layout_check_gave_up(
        target, patched.planted
    )
    breaks = layout_breaks_any(
        [(vuln.reference, vuln.planted), (patched.reference, patched.planted)]
    )
    leaking = leaking_places(vuln.planted, vuln.nonces)
    unrouted = [place.id for place in unrouted_kept_places(records, vuln.planted)]
    return LayoutCheck(gave_up, breaks, leaking, unrouted)


def layout_breaks_any(pairs: Sequence[tuple[RouteObservations, RouteObservations]]) -> bool:
    return any(layout_breaks(reference, with_layout) for reference, with_layout in pairs)


def layout_breaks(reference: RouteObservations, with_layout: RouteObservations) -> bool:
    """Whether the layout breaks the version by the rule's criterion (detection-suite-rule.md,
    Deployment layout (A server the layout breaks)). The two surfaces run the same route procedure,
    so a call's error state aligns by position."""
    if reference.tools_list_succeeded and not with_layout.tools_list_succeeded:
        return True
    return any(
        not before and after
        for before, after in zip(reference.call_errored, with_layout.call_errored, strict=False)
    )


def leaking_places(planted: RouteObservations, nonces: Mapping[str, str]) -> list[str]:
    return [place_id for place_id, nonce in nonces.items() if nonce_in_surface(planted, (nonce,))]


def nonce_in_surface(planted: RouteObservations, nonces: Sequence[str]) -> bool:
    return any(nonce in body for body in planted.responses for nonce in nonces)


def layout_check_gave_up(target: Target, planted: RouteObservations) -> str | None:
    """The reason the layout check gives up on a target, or None. A target already in the fallback
    launch-mode whose fallback launch itself fails to start cannot be run at all: the break detector
    has no fallback left to gate (detection-suite-rule.md, Deployment layout (A server the layout
    breaks)). A normal-mode target does not give up here, its break is only reported so the
    maintainer sets the fallback launch-mode."""
    if target.launch_mode is LaunchMode.FALLBACK and not planted.tools_list_succeeded:
        return _GAVE_UP_REASON
    return None


def unrouted_kept_places(records: Sequence[Place], observations: RouteObservations) -> list[Place]:
    """The kept layout places the route check finds no route to. Keeping a layout place needs a
    route the server's own output reveals (detection-suite-rule.md, Deployment layout (A place is
    kept for a target)), so one without a route breaks the rule's keeping condition and fails the
    route check. A catalogue place carries no anchor and has_route always finds a route to it, so it
    never appears here."""
    return [place for place in records if not has_route(place, observations)]


def layout_failure(target: Target, check: LayoutCheck) -> str | None:
    """Why the layout check fails a target, or None. A break fails a NORMAL target, calibrated under
    a launch it lost, and keeps a FALLBACK one (detection-suite-rule.md, Deployment layout (A server
    the layout breaks)). A leak fails it only on a place its calibration did not settle, by the
    same reading (detection-suite-log.md, 2026-11-12)."""
    if check.gave_up is not None:
        return check.gave_up
    if check.breaks and target.launch_mode is LaunchMode.NORMAL:
        return "the layout breaks the server under the normal launch"
    new_leaks = [place_id for place_id in check.leaking if place_id not in target.settled_leaks]
    if new_leaks:
        return "a nonce surfaces in the ordinary surface: " + ", ".join(new_leaks)
    if check.unrouted:
        return "kept layout place(s) without a route: " + ", ".join(check.unrouted)
    return None


def layout_routes(
    places: Places, kept: Sequence[str], planted: RouteObservations
) -> list[LayoutRoute]:
    """The route check's result for every layout place, kept or not, so a card records it for each
    (a catalogue place carries no anchor and is left out). Only a kept place's missing route fails
    the route check, which `layout_check` decides."""
    return [
        LayoutRoute(place.id, place.id in kept, has_route(place, planted))
        for place in places.values()
        if place.coordinates.anchor is not None
    ]
