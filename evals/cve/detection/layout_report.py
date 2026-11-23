"""The console report of the layout and route checks in the calibration check.

`check_layouts_and_routes` is the Docker orchestration of the calibration check
(--calibration-check), run before its exploits so the break is reported first. Per target it reports
the break (on either version) and, on the vulnerable version, the leak (the layout check), each kept
place's route (the route check) and each unkept layout place's route, labelled not kept, which a
card records and no decision reads. It reads no model.
"""

from collections.abc import Sequence

from rich.markup import escape

from evals.cve.detection.layout_check import (
    LayoutCheck,
    LayoutRoute,
    layout_check,
    layout_failure,
    layout_routes,
)
from evals.cve.detection.layout_observation import observe_versions
from evals.cve.detection.route_check import has_route
from evals.cve.detection.targets import Target
from evals.cve.places import Place, Places, kept_records
from evals.eval_display import console


async def check_layouts_and_routes(
    targets: list[Target], places: Places, ci: bool = False
) -> list[str]:
    """Report each target's layout break, nonce leak and per-layout-place route, and return one
    failure per target `layout_failure` fails, which the caller fails the maintainer run on (never
    a gated run)."""
    console.print(
        "\n[bold]Layout and route checks[/bold] (no LLM): layout check then route check\n"
    )
    failures: list[str] = []
    for target in targets:
        if ci and target.ci_skip_reason is not None:
            console.print(f"[yellow]skip[/yellow]  {target.flaw_id}: {target.ci_skip_reason}")
            continue
        failure = layout_failure(target, await _check_and_report(target, places))
        if failure is not None:
            failures.append(f"{target.flaw_id}: {failure}")
    if failures:
        console.print("\n[red]Layout and route checks failed[/red]:")
        for failure in failures:
            console.print(f"  {escape(failure)}")
    return failures


async def _check_and_report(target: Target, places: Places) -> LayoutCheck:
    vulnerable, patched = await observe_versions(target, places)
    records = kept_records(target.kept_places, places)
    check = layout_check(target, records, vulnerable, patched)
    if check.gave_up is not None:
        _report_give_up(target.flaw_id, check.gave_up)
        return check
    _report_break(target.flaw_id, check.breaks)
    _report_leaks(target, check.leaking)
    for place in records:
        _report_route(target.flaw_id, place, has_route(place, vulnerable.planted))
    _report_unkept_routes(
        target.flaw_id, layout_routes(places, target.kept_places, vulnerable.planted)
    )
    return check


def _report_give_up(flaw_id: str, reason: str) -> None:
    console.print(f"[red]gave up[/red]  {flaw_id}: {reason}")


def _report_break(flaw_id: str, breaks: bool) -> None:
    status = "[red]layout break[/red]" if breaks else "[green]no break[/green]"
    console.print(f"{status}  {flaw_id}")
    if breaks:
        console.print("  the layout breaks the server (set the fallback launch-mode)")


def _report_leaks(target: Target, leaking: Sequence[str]) -> None:
    for place_id in leaking:
        settled = place_id in target.settled_leaks
        status = "[yellow]settled nonce leak[/yellow]" if settled else "[red]nonce leak[/red]"
        console.print(f"{status}  {target.flaw_id}: {place_id} surfaces in the ordinary surface")


def _report_route(flaw_id: str, place: Place, routed: bool) -> None:
    status = "[green]route[/green]" if routed else "[red]no route[/red]"
    console.print(f"  {status}  {flaw_id} -> {place.id}")


def _report_unkept_routes(flaw_id: str, routes: Sequence[LayoutRoute]) -> None:
    for route in routes:
        if not route.kept:
            status = "route" if route.routed else "no route"
            console.print(f"  [dim]{status}[/dim]  {flaw_id} -> {route.place_id} (not kept)")
