import dataclasses
from collections.abc import Generator
from contextlib import contextmanager

import tests.unit.support.launch_audit_fakes as launch_audit_fakes
from evals.cve.detection.targets import Target
from evals.cve.environments import Launch, LaunchShape
from evals.cve.launch_audit import Auditor
from evals.cve.planting_base import PlantingSpec
from tests.unit.detection.support.detection_audits import A_LAUNCH, TARGET


def a_target_failing_to_launch(error: Exception) -> Target:
    @contextmanager
    def failing_container(_tag: str, _spec: PlantingSpec, _shape: LaunchShape) -> Generator[Launch]:
        raise error
        yield A_LAUNCH

    return dataclasses.replace(TARGET, kept_places=(), builder=failing_container)


def an_audit_taking_the_server_as_down(audits: int = 1) -> Auditor:
    """Each of the `audits` reports holds a relaunch that failed."""
    reports = [launch_audit_fakes.a_report_with_relaunches(False) for _ in range(audits)]
    return launch_audit_fakes.an_auditor(graphs=launch_audit_fakes.graph_reporting(reports))


def an_audit_raising(error: Exception, *, grouped: bool = True) -> Auditor:
    return launch_audit_fakes.an_auditor(
        graphs=launch_audit_fakes.graph_raising(error),
        connect=launch_audit_fakes.FakeConnect(grouped=grouped),
    )
