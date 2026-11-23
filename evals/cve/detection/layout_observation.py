"""The layout check's Docker observation (ADR 031).

Per target it launches, on both the vulnerable and the patched version, the reference arm (a minimal
valid empty node at each layout path) then the launch its launch-mode field selects (normal, or the
fallback). `observe_layout` gives the pre-run checks of a graded run and of a detection holdout run
the result the pure verdicts of `layout_check` compute over these observations.
"""

import tempfile
from collections.abc import Mapping
from dataclasses import dataclass

from evals.cve.detection.calibration_check import report_launch_error
from evals.cve.detection.layout_check import LayoutCheck, VersionObservation, layout_check
from evals.cve.detection.route_check import RouteObservations, route_observations
from evals.cve.detection.targets import Target, TargetVersion
from evals.cve.environments import LaunchShape, connect
from evals.cve.failure_text import FULL_DETAIL, ReportDetail
from evals.cve.launch_retry import NotLaunched, first_launch
from evals.cve.places import Places, kept_records


async def observe_layout(
    target: Target, places: Places, *, report_detail: ReportDetail = FULL_DETAIL
) -> LayoutCheck:
    vuln, patched = await observe_versions(target, places, report_detail=report_detail)
    return layout_check(target, kept_records(target.kept_places, places), vuln, patched)


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

    async def _observe(self, arm: _Arm) -> tuple[RouteObservations, Mapping[str, str]]:
        observed = await first_launch(lambda: self._launch(arm))
        return observed if observed is not None else (_failed_observation(), {})

    async def _launch(self, arm: _Arm) -> tuple[RouteObservations, Mapping[str, str]]:
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
                return observations, dict(planted.nonces)
            except Exception as exc:
                label = f"{self.target.flaw_id} layout check launch error"
                report_launch_error(label, exc, server_stderr, self.report_detail)
                if not launched:
                    raise NotLaunched from exc
                return _failed_observation(), {}


def _failed_observation() -> RouteObservations:
    return RouteObservations(scope=None, responses=(), call_errored=(), tools_list_succeeded=False)
