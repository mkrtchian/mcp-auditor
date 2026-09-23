import sys
import traceback
from dataclasses import dataclass

from evals import eval_display as display
from evals.eval_session import EvalSession
from evals.gate import Cell, CellComparison, CellOutcome, Observation, ReplayRule, observe, settle
from evals.honeypots import HONEYPOTS, HoneypotConfig, audit_honeypot
from evals.metrics import aggregate_verdicts


@dataclass(frozen=True)
class ReplayPlan:
    honeypot: HoneypotConfig
    flipped: list[Cell]
    rule: ReplayRule


async def replay_flips(
    session: EvalSession, cells: dict[Cell, CellComparison], rule: ReplayRule
) -> tuple[dict[Cell, CellComparison], list[str]]:
    """Settles every flip by replaying its server alone. The second item lists failed replays."""
    settled = dict(cells)
    failures: list[str] = []
    for honeypot in HONEYPOTS:
        flipped = [
            cell for cell in honeypot.ground_truth if cells[cell].outcome == CellOutcome.FLIP
        ]
        if not flipped:
            continue
        try:
            replays = await _replay_server(session, ReplayPlan(honeypot, flipped, rule))
        except Exception:
            traceback.print_exc(file=sys.stderr)
            failures.append(f"a replay of {honeypot.name} failed")
            continue
        for cell in flipped:
            settled[cell] = settle(cells[cell], replays[cell], rule)
    return settled, failures


async def _replay_server(session: EvalSession, plan: ReplayPlan) -> dict[Cell, list[bool]]:
    """One server run per replay, shared by the flipped cells still undecided.

    A replay is observed against its own server's ground truth: the merged one would read
    every other server's cells as uncovered.
    """
    replays: dict[Cell, list[bool]] = {cell: [] for cell in plan.flipped}
    for attempt in range(1, plan.rule.replays + 1):
        pending = [cell for cell in plan.flipped if _undecided(replays[cell], plan.rule)]
        if not pending:
            break
        display.console.print(
            f"  Replaying [bold]{plan.honeypot.name}[/bold] ({attempt}/{plan.rule.replays}), "
            f"{len(pending)} flipped cell(s)..."
        )
        report = await audit_honeypot(session.settings, plan.honeypot, session.conditions.budget)
        observed = observe(aggregate_verdicts(report), plan.honeypot.ground_truth)
        for cell in pending:
            expected = Observation(plan.honeypot.ground_truth[cell].value)
            replays[cell].append(observed[cell] != expected)
    return replays


def _undecided(replays: list[bool], rule: ReplayRule) -> bool:
    reproduced = sum(replays)
    return rule.decide(reproduced, len(replays) - reproduced) is None
