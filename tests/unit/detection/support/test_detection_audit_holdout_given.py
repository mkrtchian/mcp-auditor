import dataclasses
from collections.abc import Generator
from contextlib import contextmanager

import tests.unit.cve.support.test_cve_launch_audit_given as launch_given
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
    reports = [launch_given.a_report_with_relaunches(False) for _ in range(audits)]
    return launch_given.an_auditor(graphs=launch_given.graph_reporting(reports))


def an_audit_raising(error: Exception, *, grouped: bool = True) -> Auditor:
    return launch_given.an_auditor(
        graphs=launch_given.graph_raising(error),
        connect=launch_given.FakeConnect(grouped=grouped),
    )
