from evals.cve.nuisance.audit import ProviderError

PROVIDER_ERROR = ProviderError("ModelAPIError, status 500")


class ScriptedCalls[T]:
    """Each call pops the next outcome, raising it when it is an exception."""

    def __init__(self, outcomes: list[T | Exception]) -> None:
        self._outcomes = outcomes
        self.calls = 0

    async def __call__(self) -> T:
        self.calls += 1
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome
