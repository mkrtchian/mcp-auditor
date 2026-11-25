from collections.abc import Sequence

from evals.cve.audit_attempts import ProviderErrorAttempt

PROVIDER_ERROR = ProviderErrorAttempt("ModelAPIError, status 500")


class ScriptedAttempts[T]:
    """Each call pops the next outcome, raising it when it is an exception."""

    def __init__(self, outcomes: Sequence[T | BaseException]) -> None:
        self._outcomes = list(outcomes)
        self.calls = 0

    async def __call__(self) -> T:
        self.calls += 1
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome
