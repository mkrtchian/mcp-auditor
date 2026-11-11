import asyncio
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from evals.cve.detection.layout_check import LayoutCheck
from evals.cve.detection.targets import Target
from tests.unit.support.test_holdout_run_given import FILESYSTEM, GIT, KUBERNETES, a_target

TARGETS = (a_target(FILESYSTEM), a_target(KUBERNETES), a_target(GIT))
LIVE: list[str] = []
SOUND = LayoutCheck(gave_up=None, breaks=False, unrouted=[])
BROKEN = LayoutCheck(gave_up=None, breaks=True, unrouted=[])


@dataclass
class ScriptedChecks:
    """The two no-LLM checks of the pre-run check, scripted per target and per pass (the last
    entry repeats), recording when each check of each target starts and ends."""

    dead: Mapping[str, Sequence[list[str]]] = field(default_factory=dict[str, Sequence[list[str]]])
    layouts: Mapping[str, Sequence[LayoutCheck]] = field(
        default_factory=dict[str, Sequence[LayoutCheck]]
    )
    events: list[tuple[str, str]] = field(default_factory=list[tuple[str, str]])
    _passes: dict[str, int] = field(default_factory=dict[str, int])

    async def check(self, target: Target) -> list[str]:
        self._passes[target.flaw_id] = self._passes.get(target.flaw_id, 0) + 1
        await self._step("start", target)
        return _nth(self.dead.get(target.flaw_id, [LIVE]), self._passes[target.flaw_id])

    async def layout(self, target: Target) -> LayoutCheck:
        observed = _nth(self.layouts.get(target.flaw_id, [SOUND]), self._passes[target.flaw_id])
        await self._step("end", target)
        return observed

    def passes(self, cve_id: str) -> int:
        return self._passes.get(cve_id, 0)

    async def _step(self, kind: str, target: Target) -> None:
        self.events.append((kind, target.flaw_id))
        await asyncio.sleep(0)


def _nth[T](script: Sequence[T], number: int) -> T:
    return script[min(number, len(script)) - 1]
