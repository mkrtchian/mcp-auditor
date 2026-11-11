import asyncio
import traceback
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from evals.gate import (
    Cell,
    CellComparison,
    CellOutcome,
    Observation,
    RetestRule,
    apply_retests,
    observe,
)
from evals.honeypots import HoneypotConfig
from evals.metrics import VerdictMap

RetestAudit = Callable[[HoneypotConfig], Awaitable[VerdictMap]]


@dataclass(frozen=True)
class Retester:
    audit: RetestAudit
    honeypots: list[HoneypotConfig]
    announce: Callable[[str], None]
    warn: Callable[[str], None]

    async def retest_flips(
        self, cells: dict[Cell, CellComparison], rule: RetestRule
    ) -> tuple[dict[Cell, CellComparison], list[str]]:
        """Settles every flip by retesting its server alone, the servers side by side. The
        second item lists failures."""
        flipped_by_server = self._flipped_by_server(cells)
        results = await asyncio.gather(
            *(
                self._retest_or_fail(honeypot, flipped, rule)
                for honeypot, flipped in flipped_by_server
            )
        )
        settled = dict(cells)
        failures: list[str] = []
        for (_, flipped), result in zip(flipped_by_server, results, strict=True):
            if isinstance(result, str):
                failures.append(result)
                continue
            for cell in flipped:
                settled[cell] = apply_retests(cells[cell], result[cell], rule)
        return settled, failures

    def _flipped_by_server(
        self, cells: dict[Cell, CellComparison]
    ) -> list[tuple[HoneypotConfig, list[Cell]]]:
        flipped_by_server = [
            (
                honeypot,
                [cell for cell in honeypot.ground_truth if cells[cell].outcome == CellOutcome.FLIP],
            )
            for honeypot in self.honeypots
        ]
        return [(honeypot, flipped) for honeypot, flipped in flipped_by_server if flipped]

    async def _retest_or_fail(
        self, honeypot: HoneypotConfig, flipped: list[Cell], rule: RetestRule
    ) -> dict[Cell, list[bool]] | str:
        """The retests of one server, or the failure message when one of them raised."""
        try:
            return await self._retest_server(honeypot, flipped, rule)
        except Exception:
            self.announce(f"Warning: a retest of {honeypot.name} failed:")
            self.warn(traceback.format_exc())
            return f"a retest of {honeypot.name} failed"

    async def _retest_server(
        self, honeypot: HoneypotConfig, flipped: list[Cell], rule: RetestRule
    ) -> dict[Cell, list[bool]]:
        """One server run per retest, shared by the flipped cells still undecided.

        A retest is observed against its own server's ground truth: the merged one would read
        every other server's cells as uncovered.
        """
        retests: dict[Cell, list[bool]] = {cell: [] for cell in flipped}
        for attempt in range(1, rule.retests + 1):
            pending = [cell for cell in flipped if rule.decide_retests(retests[cell]) is None]
            if not pending:
                break
            self.announce(
                f"  Retesting {honeypot.name} ({attempt}/{rule.retests}), "
                f"{len(pending)} flipped cell(s)..."
            )
            observed = observe(await self.audit(honeypot), honeypot.ground_truth)
            for cell in pending:
                expected = Observation(honeypot.ground_truth[cell].value)
                retests[cell].append(observed[cell] != expected)
        return retests
