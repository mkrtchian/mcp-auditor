import io

import pytest
from rich.console import Console
from rich.progress import Progress

from evals.audit_progress import AuditProgress


def _a_progress() -> Progress:
    return Progress(console=Console(file=io.StringIO()))


async def _audit(value: int) -> int:
    return value


async def _audit_returning_none(_: int) -> None:
    return None


async def _audit_raising(_: int) -> int:
    raise RuntimeError("launch failed")


def _task(progress: Progress, description: str):
    return next(task for task in progress.tasks if task.description == description)


def _descriptions(progress: Progress) -> list[str]:
    return [task.description for task in progress.tasks]


def test_the_bar_opens_preparing():
    progress = _a_progress()

    AuditProgress(progress)

    assert _descriptions(progress) == ["Preparing"]
    assert _task(progress, "Preparing").total is None


def test_announcing_swaps_preparing_for_auditing():
    progress = _a_progress()

    AuditProgress(progress).announce(3)

    assert _descriptions(progress) == ["Auditing"]
    assert _task(progress, "Auditing").total == 3


async def test_the_announced_completions_complete_auditing():
    progress = _a_progress()
    audit_progress = AuditProgress(progress)
    audit_progress.announce(3)
    audit = audit_progress.tracked(_audit)

    results = [await audit(index) for index in range(3)]

    assert results == [0, 1, 2]
    assert _task(progress, "Auditing").finished
    assert _descriptions(progress) == ["Auditing"]


async def test_a_completion_past_the_announced_audits_advances_replaying():
    progress = _a_progress()
    audit_progress = AuditProgress(progress)
    audit_progress.announce(3)
    audit = audit_progress.tracked(_audit)

    for index in range(4):
        await audit(index)

    replaying = _task(progress, "Replaying")
    assert replaying.total is None
    assert replaying.completed == 1
    assert _task(progress, "Auditing").completed == 3


async def test_an_audit_returning_none_advances():
    progress = _a_progress()
    audit_progress = AuditProgress(progress)
    audit_progress.announce(2)

    await audit_progress.tracked(_audit_returning_none)(0)

    assert _task(progress, "Auditing").completed == 1


async def test_a_raising_audit_propagates_without_advancing():
    progress = _a_progress()
    audit_progress = AuditProgress(progress)
    audit_progress.announce(2)

    with pytest.raises(RuntimeError, match="launch failed"):
        await audit_progress.tracked(_audit_raising)(0)

    assert _task(progress, "Auditing").completed == 0


async def test_a_completion_before_the_announce_advances_nothing():
    progress = _a_progress()
    audit_progress = AuditProgress(progress)

    await audit_progress.tracked(_audit)(0)

    assert _descriptions(progress) == ["Preparing"]
    assert _task(progress, "Preparing").completed == 0


def test_announcing_no_audit_leaves_no_task():
    progress = _a_progress()

    AuditProgress(progress).announce(0)

    assert progress.tasks == []
