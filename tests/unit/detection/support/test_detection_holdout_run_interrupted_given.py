import asyncio

from evals.cve.detection.targets import Target
from tests.unit.support.acceptance_targets import an_acceptance_target
from tests.unit.support.holdout_runs import Outcome, three_detections


def holdout_targets(*flaw_ids: str) -> tuple[Target, ...]:
    """With no tools filter, which the holdout run refuses."""
    return tuple(an_acceptance_target(flaw_id, tools_filter=None) for flaw_id in flaw_ids)


class InterruptingAudit:
    """The finished target's runs detect at once. The failing target's first run raises `error`
    once the finished target is done, and every other run waits until it is cancelled."""

    def __init__(self, finished: str, failing: str, error: Exception) -> None:
        self.cancelled: list[str] = []
        self._finished, self._failing, self._error = finished, failing, error
        self._detections = three_detections()
        self._finished_done = asyncio.Event()
        self._failing_calls = 0

    async def __call__(self, target: Target) -> Outcome:
        if target.flaw_id == self._finished:
            return self._detection()
        if target.flaw_id == self._failing:
            self._failing_calls += 1
            if self._failing_calls == 1:
                await self._finished_done.wait()
                await asyncio.sleep(0.01)  # lets the finished target's task complete
                raise self._error
        return await self._until_cancelled(target)

    def _detection(self) -> Outcome:
        outcome = self._detections.pop(0)
        if not self._detections:
            self._finished_done.set()
        return outcome

    async def _until_cancelled(self, target: Target) -> Outcome:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled.append(target.flaw_id)
            raise
        raise AssertionError("a run that never ends completed")
