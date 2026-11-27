from dataclasses import replace

import tests.unit.detection.support.holdout_command_deps as command_deps
from evals.cve.closed_network import ClosedNetworkUnsupported
from evals.cve.detection.calibration_check_exit import CalibrationCheckDeps
from evals.cve.detection.holdout_command_deps import HoldoutCommandDeps
from evals.cve.detection.targets import target_services
from evals.cve.images import dockerfile_fingerprint, image_tag
from evals.cve.run_images import RunDocker
from tests.fakes import FakeContainerSweep
from tests.fakes.image_store import FakeImageStore
from tests.unit.support.acceptance_targets import an_acceptance_target


def a_drawn_command(
    *flaw_ids: str, checks: CalibrationCheckDeps, sweep: FakeContainerSweep | None = None
) -> HoldoutCommandDeps:
    """Drawn, with a closed network and current images for each, and these calibration checks."""
    targets = tuple(an_acceptance_target(flaw_id, tools_filter=None) for flaw_id in flaw_ids)
    docker = RunDocker(
        lambda: None,
        FakeImageStore(current_labels(*flaw_ids)),
        (sweep or FakeContainerSweep()).sweep,
    )
    return replace(
        command_deps.a_command_reaching_nothing(),
        drawn=targets,
        docker=docker,
        calibration_check=lambda _concurrency, _ci, _show: checks,
    )


class FlagRecordingFactory:
    """A calibration-check factory answering `checks`, recording whether each call asked to show
    the exploit responses."""

    def __init__(self, checks: CalibrationCheckDeps) -> None:
        self.shown: list[bool] = []
        self._checks = checks

    def __call__(self, _concurrency: int, _ci: bool, show: bool, /) -> CalibrationCheckDeps:
        self.shown.append(show)
        return self._checks


def current_labels(*flaw_ids: str) -> dict[str, str | None]:
    services = target_services([an_acceptance_target(flaw_id) for flaw_id in flaw_ids])
    return {image_tag(service): dockerfile_fingerprint(service) for service in services}


def a_daemon_that_cannot_close_a_network() -> None:
    raise ClosedNetworkUnsupported("invalid gateway mode: isolated")
