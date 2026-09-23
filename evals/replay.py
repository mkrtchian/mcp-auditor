import traceback
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from evals.gate import Cell, CellComparison, CellOutcome, Observation, ReplayRule, observe, settle
from evals.honeypots import HoneypotConfig
from evals.metrics import VerdictMap

ReplayAudit = Callable[[HoneypotConfig], Awaitable[VerdictMap]]


@dataclass(frozen=True)
class Replayer:
    audit: ReplayAudit
    honeypots: list[HoneypotConfig]
    announce: Callable[[str], None]

    async def settle_flips(
        self, cells: dict[Cell, CellComparison], rule: ReplayRule
    ) -> tuple[dict[Cell, CellComparison], list[str]]:
        """Settles every flip by replaying its server alone. The second item lists failures."""
        settled = dict(cells)
        failures: list[str] = []
        for honeypot in self.honeypots:
            flipped = [
                cell for cell in honeypot.ground_truth if cells[cell].outcome == CellOutcome.FLIP
            ]
            if not flipped:
                continue
            try:
                replays = await self._replay_server(honeypot, flipped, rule)
            except Exception:
                self.announce(traceback.format_exc())
                failures.append(f"a replay of {honeypot.name} failed")
                continue
            for cell in flipped:
                settled[cell] = settle(cells[cell], replays[cell], rule)
        return settled, failures

    async def _replay_server(
        self, honeypot: HoneypotConfig, flipped: list[Cell], rule: ReplayRule
    ) -> dict[Cell, list[bool]]:
        """One server run per replay, shared by the flipped cells still undecided.

        A replay is observed against its own server's ground truth: the merged one would read
        every other server's cells as uncovered.
        """
        replays: dict[Cell, list[bool]] = {cell: [] for cell in flipped}
        for attempt in range(1, rule.replays + 1):
            pending = [cell for cell in flipped if rule.decide_replays(replays[cell]) is None]
            if not pending:
                break
            self.announce(
                f"  Replaying {honeypot.name} ({attempt}/{rule.replays}), "
                f"{len(pending)} flipped cell(s)..."
            )
            observed = observe(await self.audit(honeypot), honeypot.ground_truth)
            for cell in pending:
                expected = Observation(honeypot.ground_truth[cell].value)
                replays[cell].append(observed[cell] != expected)
        return replays
