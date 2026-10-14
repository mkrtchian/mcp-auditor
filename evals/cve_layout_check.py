"""The layout-effect check (ADR 031).

The server's ordinary surface, its tools/list and the tools called at minimal arguments, is the
same whether the tree carries neutral content (empty) or the target's nonces (planted), so the
layout's presence changes only what the flaw reaches through an exploit, never the server's
ordinary behaviour, and no nonce surfaces in that ordinary surface. The benign call is not run
here. `layout_effect` is a pure comparator over two collected surfaces, pinned by a golden master.

`confirm_admission` is the Docker orchestration run under the maintainer paths (--calibrate and
--record-baseline, never a gated run): per target it launches the empty tree, then the planted
tree it retains for the route check, compares the surfaces (the layout check) and judges each kept
place's route (the route check), reporting both. It gates nothing on the model.
"""

import tempfile
from collections.abc import Sequence
from dataclasses import dataclass

from rich.console import Console

from evals.cve_environments import connect
from evals.cve_places import Place, Places, kept_records
from evals.cve_route import RouteObservations, route_admits, route_observations
from evals.cve_targets import CVETarget

console = Console()


@dataclass(frozen=True)
class LayoutSurface:
    tool_names: tuple[str, ...]
    responses: tuple[str, ...]


@dataclass(frozen=True)
class LayoutEffect:
    surface_unchanged: bool  # the ordinary surface is identical with and without the nonces
    nonce_in_surface: bool  # a planted nonce leaked into the ordinary surface (never, when healthy)


def layout_effect(
    empty: LayoutSurface, planted: LayoutSurface, nonces: Sequence[str]
) -> LayoutEffect:
    return LayoutEffect(
        surface_unchanged=empty == planted,
        nonce_in_surface=any(nonce in body for body in planted.responses for nonce in nonces),
    )


async def confirm_admission(targets: list[CVETarget], places: Places, ci: bool = False) -> None:
    console.print("\n[bold]Admission[/bold] (no LLM): layout effect then discovery route\n")
    for target in targets:
        if ci and target.ci_skip_reason is not None:
            console.print(f"[yellow]skip[/yellow]  {target.cve_id}: {target.ci_skip_reason}")
            continue
        empty, _ = await _observe(target, (), places)
        planted, nonces = await _observe(target, target.kept_places, places)
        _report_effect(target.cve_id, layout_effect(_surface(empty), _surface(planted), nonces))
        for place in kept_records(target.kept_places, places):
            _report_route(target.cve_id, place, route_admits(place, planted))


def _report_effect(cve_id: str, effect: LayoutEffect) -> None:
    healthy = effect.surface_unchanged and not effect.nonce_in_surface
    status = "[green]layout ok[/green]" if healthy else "[red]layout effect[/red]"
    console.print(f"{status}  {cve_id}")
    if not effect.surface_unchanged:
        console.print("  the tree changes the server's ordinary surface")
    if effect.nonce_in_surface:
        console.print("  a nonce surfaces in the ordinary surface")


def _report_route(cve_id: str, place: Place, admits: bool) -> None:
    status = "[green]route[/green]" if admits else "[red]no route[/red]"
    console.print(f"  {status}  {cve_id} -> {place.id}")


async def _observe(
    target: CVETarget, kept: tuple[str, ...], places: Places
) -> tuple[RouteObservations, tuple[str, ...]]:
    records = kept_records(kept, places)
    with tempfile.TemporaryFile("w+") as server_stderr:
        async with (
            target.launched(records) as planted,
            connect(planted.launch, server_stderr) as client,
        ):
            observations = await route_observations(target, client, planted.launch)
    return observations, tuple(planted.nonces.values())


def _surface(observations: RouteObservations) -> LayoutSurface:
    return LayoutSurface(observations.tool_names, observations.responses)
