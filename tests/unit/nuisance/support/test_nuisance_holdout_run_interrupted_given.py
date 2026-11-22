import asyncio

import tests.unit.support.nuisance_holdout_runs as holdout_runs
from evals.cve.nuisance.admission.admission import AdmittedServer


class InterruptingAudit:
    """The finished server's runs answer at once. The failing server's first run raises `error`
    once the finished server is done, and every other run waits until it is cancelled."""

    def __init__(self, finished: str, failing: str, error: Exception) -> None:
        self.cancelled: list[str] = []
        self._finished, self._failing, self._error = finished, failing, error
        self._reports: list[holdout_runs.Outcome] = [holdout_runs.an_audit(False) for _ in range(3)]
        self._finished_done = asyncio.Event()
        self._failing_calls = 0

    async def __call__(self, server: AdmittedServer) -> holdout_runs.Outcome:
        if server.server_package == self._finished:
            return self._report()
        if server.server_package == self._failing:
            self._failing_calls += 1
            if self._failing_calls == 1:
                await self._finished_done.wait()
                await asyncio.sleep(0.01)  # lets the finished server's task complete
                raise self._error
        return await self._until_cancelled(server)

    def _report(self) -> holdout_runs.Outcome:
        outcome = self._reports.pop(0)
        if not self._reports:
            self._finished_done.set()
        return outcome

    async def _until_cancelled(self, server: AdmittedServer) -> holdout_runs.Outcome:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled.append(server.server_package)
            raise
        raise AssertionError("a run that never ends completed")
