"""The layout break detector and the anti-leak guard (ADR 031).

The rule gates a fallback launch on a break: launch each version once with a minimal valid empty
node at each layout path, by node type (the reference arm), and once with the layout, and call it a
break when the launch or tools/list succeeded without the layout and failed with it, or when a call
that returned no error without the layout returns one with it (holdout-rule.md:159). `layout_breaks`
is the pure detector over the two collected surfaces for one version, `layout_breaks_any` over both
versions (a break on either is a break). A changed response body (a discovery symlink in a listing,
a shifted deterministic HEAD SHA) is not a break: only a lost tools/list or a newly-erroring call
counts.

The anti-leak guard (`nonce_in_surface`) is a separate pure verdict on the planted surface,
implementing a distinct clause of the rule: a place the server itself reads at launch is not kept
(holdout-rule.md:157), so no planted nonce may appear in the server's ordinary surface. Both are
pinned by a golden master. The benign call is not run here.

`confirm_admission` is the Docker orchestration run under the maintainer paths (--calibrate and
--record-baseline, never a gated run), before the exploit calibration so the break is reported
first. Per target it launches, on both the vulnerable and the patched version, the reference arm (a
minimal valid empty node at each layout path) then the launch its launch-mode field selects (normal,
or the fallback); it reports the break (on either version) and, on the vulnerable version, the leak
(the layout check) and each kept place's route (the route check). The break detector only reports;
the maintainer sets the fallback launch-mode. It gives up (`admission_gave_up`) only when a target
already in the fallback launch-mode cannot start even that launch. It gates nothing on the model.
"""

import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from typing import IO

from rich.console import Console
from rich.markup import escape

from evals.cve_environments import LaunchShape, connect
from evals.cve_places import Place, Places, kept_records
from evals.cve_route import RouteObservations, route_admits, route_observations
from evals.cve_targets import CVETarget, LaunchMode, TargetVersion

console = Console()

# When a target already in the fallback launch-mode cannot start even the fallback launch, the
# admission gives up: the container cannot run the server (holdout-rule.md:159).
_GAVE_UP_REASON = "the container cannot run the server"


@dataclass(frozen=True)
class LayoutSurface:
    tool_names: tuple[str, ...]
    responses: tuple[str, ...]
    call_errored: tuple[bool, ...]  # per call, whether it returned an error
    tools_list_succeeded: bool  # whether tools/list itself returned (a failed launch sets it False)


@dataclass(frozen=True)
class VersionObservation:
    reference: RouteObservations
    planted: RouteObservations
    nonces: tuple[str, ...]  # the planted arm's nonces; the reference arm plants none


@dataclass(frozen=True)
class LayoutCheck:
    """The verdict `confirm_admission` computes inline, exposed so the holdout orchestrator reads
    it directly: the give-up reason (or None), whether the layout breaks either version, and the
    kept layout places left without a route (holdout-rule.md:157, :159)."""

    gave_up: str | None
    breaks: bool
    unrouted: list[str]


def layout_breaks(reference: LayoutSurface, with_layout: LayoutSurface) -> bool:
    """Whether the layout breaks the version by the rule's criterion (holdout-rule.md:159). The
    two surfaces run the same route procedure, so a call's error state aligns by position."""
    if reference.tools_list_succeeded and not with_layout.tools_list_succeeded:
        return True
    return any(
        not before and after
        for before, after in zip(reference.call_errored, with_layout.call_errored, strict=False)
    )


def layout_breaks_any(pairs: Sequence[tuple[LayoutSurface, LayoutSurface]]) -> bool:
    """Whether the layout breaks any of the version pairs. The rule launches each version once with
    and once without the layout, and a break on either version is a break (holdout-rule.md:159)."""
    return any(layout_breaks(reference, with_layout) for reference, with_layout in pairs)


def nonce_in_surface(planted: LayoutSurface, nonces: Sequence[str]) -> bool:
    return any(nonce in body for body in planted.responses for nonce in nonces)


def admission_gave_up(target: CVETarget, planted: RouteObservations) -> str | None:
    """The reason the admission gives up on a target, or None. A target already in the fallback
    launch-mode whose fallback launch itself fails to start cannot be run at all: the break detector
    has no fallback left to gate (holdout-rule.md:159). A normal-mode target does not give up here,
    its break is only reported so the maintainer sets the fallback launch-mode."""
    if target.launch_mode is LaunchMode.FALLBACK and not planted.tools_list_succeeded:
        return _GAVE_UP_REASON
    return None


def unrouted_kept_places(records: Sequence[Place], observations: RouteObservations) -> list[Place]:
    """The kept layout places the route check does not admit. Keeping a layout place needs a route
    the server's own output reveals (holdout-rule.md:157), so one without a route breaks the rule's
    keeping condition and fails the admission. A catalogue place carries no anchor and route_admits
    always admits it, so it never appears here."""
    return [place for place in records if not route_admits(place, observations)]


def layout_check(
    target: CVETarget,
    records: Sequence[Place],
    vuln: VersionObservation,
    patched: VersionObservation,
) -> LayoutCheck:
    """The admission verdict over the two versions' observations: the give-up reason, the break
    on either version, and the kept layout places with no route (holdout-rule.md:157, :159)."""
    gave_up = admission_gave_up(target, vuln.planted) or admission_gave_up(target, patched.planted)
    breaks = layout_breaks_any([_surface_pair(vuln), _surface_pair(patched)])
    unrouted = [place.id for place in unrouted_kept_places(records, vuln.planted)]
    return LayoutCheck(gave_up, breaks, unrouted)


async def observe_versions(
    target: CVETarget, places: Places
) -> tuple[VersionObservation, VersionObservation]:
    """Launch and observe both versions of a target (the reference arm then the planted one on
    each), the no-LLM observation the layout check reads."""
    vuln = await _observe_version(target, places, TargetVersion.VULNERABLE)
    patched = await _observe_version(target, places, TargetVersion.PATCHED)
    return vuln, patched


async def confirm_admission(
    targets: list[CVETarget], places: Places, ci: bool = False
) -> list[str]:
    """Report each target's layout break, nonce leak and per-kept-place route, and return the
    admission failures: a kept layout place without a route breaks the rule's keeping condition
    (holdout-rule.md:157), so the caller fails the maintainer run on it (never a gated run)."""
    console.print("\n[bold]Admission[/bold] (no LLM): layout break then discovery route\n")
    failures: list[str] = []
    for target in targets:
        if ci and target.ci_skip_reason is not None:
            console.print(f"[yellow]skip[/yellow]  {target.cve_id}: {target.ci_skip_reason}")
            continue
        vuln, patched = await observe_versions(target, places)
        records = kept_records(target.kept_places, places)
        check = layout_check(target, records, vuln, patched)
        if check.gave_up is not None:
            _report_give_up(target.cve_id, check.gave_up)
            continue
        _report_break(target.cve_id, check.breaks)
        _report_leak(target.cve_id, nonce_in_surface(_surface(vuln.planted), vuln.nonces))
        for place in records:
            _report_route(target.cve_id, place, route_admits(place, vuln.planted))
        failures += [
            f"{target.cve_id}: kept layout place {pid} has no route" for pid in check.unrouted
        ]
    if failures:
        console.print("\n[red]Kept layout places with no route[/red]: drop or route them.")
    return failures


def _report_give_up(cve_id: str, reason: str) -> None:
    console.print(f"[red]gave up[/red]  {cve_id}: {reason}")


def _report_break(cve_id: str, breaks: bool) -> None:
    status = "[red]layout break[/red]" if breaks else "[green]no break[/green]"
    console.print(f"{status}  {cve_id}")
    if breaks:
        console.print("  the layout breaks the server (set the fallback launch-mode)")


def _report_leak(cve_id: str, leaks: bool) -> None:
    if leaks:
        console.print(f"[red]nonce leak[/red]  {cve_id}: a nonce surfaces in the ordinary surface")


def _report_route(cve_id: str, place: Place, admits: bool) -> None:
    status = "[green]route[/green]" if admits else "[red]no route[/red]"
    console.print(f"  {status}  {cve_id} -> {place.id}")


async def _observe_version(
    target: CVETarget, places: Places, version: TargetVersion
) -> VersionObservation:
    reference, _ = await _observe(
        target, (), places, shape=LaunchShape.EMPTY_LAYOUT, version=version
    )
    planted, nonces = await _observe(target, target.kept_places, places, version=version)
    return VersionObservation(reference, planted, nonces)


async def _observe(
    target: CVETarget,
    kept: tuple[str, ...],
    places: Places,
    shape: LaunchShape | None = None,
    version: TargetVersion = TargetVersion.VULNERABLE,
) -> tuple[RouteObservations, tuple[str, ...]]:
    # A server that fails to start, or a connection that drops, is a break observation
    # (tools/list did not succeed), not a benchmark crash: the break detector's criterion names a
    # failed launch, so catch it here rather than let it reach the exit-4 crash handler. The planted
    # arm reads shape=None, so the launch-mode field picks the launch (normal, or the fallback).
    records = kept_records(kept, places)
    with tempfile.TemporaryFile("w+") as server_stderr:
        try:
            async with (
                target.launched(records, shape=shape, version=version) as planted,
                connect(planted.launch, server_stderr) as client,
            ):
                observations = await route_observations(target, client, planted.launch)
            return observations, tuple(planted.nonces.values())
        except Exception as exc:
            _report_launch_error(target.cve_id, exc, server_stderr)
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


def _report_launch_error(cve_id: str, exc: Exception, server_stderr: IO[str]) -> None:
    console.print(f"[yellow]{cve_id} admission launch error:[/yellow] {escape(str(exc))}")
    server_stderr.seek(0)
    for line in server_stderr.read().splitlines()[-10:]:
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
