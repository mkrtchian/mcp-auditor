"""The layout break detector and the anti-leak guard (ADR 031).

The rule gates a fallback launch on a break: launch each version once with a minimal valid empty
node at each layout path, by node type (the reference arm), and once with the layout, and call it a
break when the launch or tools/list succeeded without the layout and failed with it, or when a call
that returned no error without the layout returns one with it (holdout-rule.md, Deployment layout (A
server the layout breaks)). `layout_breaks` is the pure detector over the two collected surfaces for
one version, `layout_breaks_any` over both versions (a break on either is a break). A changed
response body (a discovery symlink in a listing, a shifted deterministic HEAD SHA) is not a break:
only a lost tools/list or a newly-erroring call counts.

The anti-leak guard (`nonce_in_surface`) is a separate pure check of the planted surface,
implementing a distinct clause of the rule: a place the server itself reads at launch is not kept
(holdout-rule.md, Deployment layout (A place is kept for a target)), so no planted nonce may appear
in the server's ordinary surface. Both are pinned by a golden master. The benign call is not run
here.

`check_layouts_and_routes` is the Docker orchestration run under the maintainer paths
(--calibration-check and --record-baseline, never a gated run), before the exploits of the
calibration check so the break is reported first. Per target it launches, on both the vulnerable
and the patched version, the reference arm (a minimal valid empty node at each layout path) then
the launch its launch-mode field selects (normal, or the fallback); it reports the break (on either
version) and, on the vulnerable version, the leak (the layout check), each kept place's route (the
route check) and each unkept layout place's route, labelled not kept, which a card records and no
decision reads. The break detector only reports; the maintainer sets the fallback launch-mode. It
gives up (`layout_check_gave_up`) only when a target already in the fallback launch-mode cannot
start even that launch. It gates nothing on the model.
"""

import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from typing import IO

from rich.markup import escape

from evals.cve.detection.calibration_check import NotLaunched, first_launch
from evals.cve.detection.route_check import RouteObservations, has_route, route_observations
from evals.cve.detection.targets import LaunchMode, Target, TargetVersion
from evals.cve.failure_text import FULL_DETAIL, ReportDetail
from evals.cve_environments import LaunchShape, connect
from evals.cve_places import Place, Places, kept_records
from evals.eval_display import console

# When a target already in the fallback launch-mode cannot start even the fallback launch, the
# layout check gives up: the container cannot run the server (holdout-rule.md, Deployment layout (A
# server the layout breaks)).
_GAVE_UP_REASON = "the container cannot run the server"


@dataclass(frozen=True)
class LayoutSurface:
    tool_names: tuple[str, ...]
    responses: tuple[str, ...]
    call_errored: tuple[bool, ...]  # per call, whether it returned an error
    tools_list_succeeded: bool  # whether tools/list itself returned (a failed launch sets it False)


@dataclass(frozen=True)
class LayoutRoute:
    place_id: str
    kept: bool
    routed: bool


@dataclass(frozen=True)
class VersionObservation:
    reference: RouteObservations
    planted: RouteObservations
    nonces: tuple[str, ...]  # the planted arm's nonces; the reference arm plants none


@dataclass(frozen=True)
class LayoutCheck:
    """The result `check_layouts_and_routes` computes inline, exposed so the holdout orchestrator
    reads it directly: the give-up reason (or None), whether the layout breaks either version, and
    the kept layout places left without a route (holdout-rule.md, Deployment layout (A place is kept
    for a target, A server the layout breaks))."""

    gave_up: str | None
    breaks: bool
    unrouted: list[str]


def layout_breaks(reference: LayoutSurface, with_layout: LayoutSurface) -> bool:
    """Whether the layout breaks the version by the rule's criterion (holdout-rule.md, Deployment
    layout (A server the layout breaks)). The two surfaces run the same route procedure, so a call's
    error state aligns by position."""
    if reference.tools_list_succeeded and not with_layout.tools_list_succeeded:
        return True
    return any(
        not before and after
        for before, after in zip(reference.call_errored, with_layout.call_errored, strict=False)
    )


def layout_breaks_any(pairs: Sequence[tuple[LayoutSurface, LayoutSurface]]) -> bool:
    """Whether the layout breaks any of the version pairs. The rule launches each version once with
    and once without the layout, and a break on either version is a break (holdout-rule.md,
    Deployment layout (A server the layout breaks))."""
    return any(layout_breaks(reference, with_layout) for reference, with_layout in pairs)


def nonce_in_surface(planted: LayoutSurface, nonces: Sequence[str]) -> bool:
    return any(nonce in body for body in planted.responses for nonce in nonces)


def layout_check_gave_up(target: Target, planted: RouteObservations) -> str | None:
    """The reason the layout check gives up on a target, or None. A target already in the fallback
    launch-mode whose fallback launch itself fails to start cannot be run at all: the break detector
    has no fallback left to gate (holdout-rule.md, Deployment layout (A server the layout breaks)).
    A normal-mode target does not give up here, its break is only reported so the maintainer sets
    the fallback launch-mode."""
    if target.launch_mode is LaunchMode.FALLBACK and not planted.tools_list_succeeded:
        return _GAVE_UP_REASON
    return None


def unrouted_kept_places(records: Sequence[Place], observations: RouteObservations) -> list[Place]:
    """The kept layout places the route check finds no route to. Keeping a layout place needs a
    route the server's own output reveals (holdout-rule.md, Deployment layout (A place is kept for a
    target)), so one without a route breaks the rule's keeping condition and fails the route
    check. A catalogue place carries no anchor and has_route always finds a route to it, so it
    never appears here."""
    return [place for place in records if not has_route(place, observations)]


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


def layout_check(
    target: Target,
    records: Sequence[Place],
    vuln: VersionObservation,
    patched: VersionObservation,
) -> LayoutCheck:
    """The layout check's result over the two versions' observations: the give-up reason, the break
    on either version, and the kept layout places with no route (holdout-rule.md, Deployment layout
    (A place is kept for a target, A server the layout breaks))."""
    gave_up = layout_check_gave_up(target, vuln.planted) or layout_check_gave_up(
        target, patched.planted
    )
    breaks = layout_breaks_any([_surface_pair(vuln), _surface_pair(patched)])
    unrouted = [place.id for place in unrouted_kept_places(records, vuln.planted)]
    return LayoutCheck(gave_up, breaks, unrouted)


async def observe_versions(
    target: Target, places: Places, *, report_detail: ReportDetail = FULL_DETAIL
) -> tuple[VersionObservation, VersionObservation]:
    """Launch and observe both versions of a target (the reference arm then the planted one on
    each), the no-LLM observation the layout check reads. `report_detail` sets how much server
    text the log shows."""
    observer = _Observer(target, places, report_detail)
    vuln = await observer.version(TargetVersion.VULNERABLE)
    patched = await observer.version(TargetVersion.PATCHED)
    return vuln, patched


async def check_layouts_and_routes(
    targets: list[Target], places: Places, ci: bool = False
) -> list[str]:
    """Report each target's layout break, nonce leak and per-layout-place route, and return the
    route check's failures: a kept layout place without a route breaks the rule's keeping condition
    (holdout-rule.md, Deployment layout (A place is kept for a target)), so the caller fails the
    maintainer run on it (never a gated run)."""
    console.print(
        "\n[bold]Layout and route checks[/bold] (no LLM): layout break then discovery route\n"
    )
    failures: list[str] = []
    for target in targets:
        if ci and target.ci_skip_reason is not None:
            console.print(f"[yellow]skip[/yellow]  {target.flaw_id}: {target.ci_skip_reason}")
            continue
        vuln, patched = await observe_versions(target, places)
        records = kept_records(target.kept_places, places)
        check = layout_check(target, records, vuln, patched)
        if check.gave_up is not None:
            _report_give_up(target.flaw_id, check.gave_up)
            continue
        _report_break(target.flaw_id, check.breaks)
        _report_leak(target.flaw_id, nonce_in_surface(_surface(vuln.planted), vuln.nonces))
        for place in records:
            _report_route(target.flaw_id, place, has_route(place, vuln.planted))
        _report_unkept_routes(
            target.flaw_id, layout_routes(places, target.kept_places, vuln.planted)
        )
        failures += [
            f"{target.flaw_id}: kept layout place {pid} has no route" for pid in check.unrouted
        ]
    if failures:
        console.print("\n[red]Kept layout places with no route[/red]: drop or route them.")
    return failures


def _report_give_up(flaw_id: str, reason: str) -> None:
    console.print(f"[red]gave up[/red]  {flaw_id}: {reason}")


def _report_break(flaw_id: str, breaks: bool) -> None:
    status = "[red]layout break[/red]" if breaks else "[green]no break[/green]"
    console.print(f"{status}  {flaw_id}")
    if breaks:
        console.print("  the layout breaks the server (set the fallback launch-mode)")


def _report_leak(flaw_id: str, leaks: bool) -> None:
    if leaks:
        console.print(f"[red]nonce leak[/red]  {flaw_id}: a nonce surfaces in the ordinary surface")


def _report_route(flaw_id: str, place: Place, routed: bool) -> None:
    status = "[green]route[/green]" if routed else "[red]no route[/red]"
    console.print(f"  {status}  {flaw_id} -> {place.id}")


def _report_unkept_routes(flaw_id: str, routes: Sequence[LayoutRoute]) -> None:
    for route in routes:
        if not route.kept:
            status = "route" if route.routed else "no route"
            console.print(f"  [dim]{status}[/dim]  {flaw_id} -> {route.place_id} (not kept)")


@dataclass(frozen=True)
class _Arm:
    kept: tuple[str, ...]
    shape: LaunchShape | None
    version: TargetVersion


@dataclass(frozen=True)
class _Observer:
    target: Target
    places: Places
    report_detail: ReportDetail

    async def version(self, version: TargetVersion) -> VersionObservation:
        empty = _Arm((), LaunchShape.EMPTY_LAYOUT, version)
        reference, _ = await self._observe(empty)
        planted, nonces = await self._observe(_Arm(self.target.kept_places, None, version))
        return VersionObservation(reference, planted, nonces)

    async def _observe(self, arm: _Arm) -> tuple[RouteObservations, tuple[str, ...]]:
        observed = await first_launch(lambda: self._launch(arm))
        return observed if observed is not None else (_failed_observation(), ())

    async def _launch(self, arm: _Arm) -> tuple[RouteObservations, tuple[str, ...]]:
        # A server that fails to start, or a connection that drops, is a break observation
        # (tools/list did not succeed), not a benchmark crash: the break detector's criterion
        # names a failed launch, so catch it here rather than let it reach the exit-4 crash
        # handler. Only a launch or handshake that fails raises NotLaunched, for a retry: a
        # failure on a launched server is observed at once. The planted arm reads shape=None, so
        # the launch-mode field picks the launch (normal, or the fallback).
        records = kept_records(arm.kept, self.places)
        with tempfile.TemporaryFile("w+") as server_stderr:
            launched = False
            try:
                async with (
                    self.target.launched(records, shape=arm.shape, version=arm.version) as planted,
                    connect(planted.launch, server_stderr) as client,
                ):
                    launched = True
                    observations = await route_observations(self.target, client, planted.launch)
                return observations, tuple(planted.nonces.values())
            except Exception as exc:
                _report_launch_error(self.target.flaw_id, exc, server_stderr, self.report_detail)
                if not launched:
                    raise NotLaunched from exc
                return _failed_observation(), ()


def _failed_observation() -> RouteObservations:
    return RouteObservations(
        launch_command=(),
        scope=None,
        tool_names=(),
        responses=(),
        call_errored=(),
        tools_list_succeeded=False,
    )


def _report_launch_error(
    flaw_id: str, exc: Exception, server_stderr: IO[str], report_detail: ReportDetail
) -> None:
    reason = report_detail.describe(exc)
    console.print(f"[yellow]{flaw_id} layout check launch error:[/yellow] {escape(reason)}")
    server_stderr.seek(0)
    for line in report_detail.server_lines(server_stderr.read().splitlines()[-10:]):
        console.print(f"  {line}", markup=False, highlight=False)


def _surface(observations: RouteObservations) -> LayoutSurface:
    return LayoutSurface(
        observations.tool_names,
        observations.responses,
        observations.call_errored,
        observations.tools_list_succeeded,
    )


def _surface_pair(observation: VersionObservation) -> tuple[LayoutSurface, LayoutSurface]:
    return _surface(observation.reference), _surface(observation.planted)
