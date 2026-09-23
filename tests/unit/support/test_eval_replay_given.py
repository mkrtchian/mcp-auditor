from pathlib import Path

from evals.gate import Cell, CellComparison, CellOutcome
from evals.honeypots import HoneypotConfig
from evals.metrics import VerdictMap
from mcp_auditor.domain.models import AuditCategory, EvalVerdict

ALPHA_CELL: Cell = ("alpha_tool", AuditCategory.INPUT_VALIDATION)
ALPHA_OTHER_CELL: Cell = ("alpha_tool", AuditCategory.INJECTION)
BETA_CELL: Cell = ("beta_tool", AuditCategory.INPUT_VALIDATION)

ALPHA = HoneypotConfig(
    "alpha",
    Path("never_opened_alpha.py"),
    {ALPHA_CELL: EvalVerdict.FAIL, ALPHA_OTHER_CELL: EvalVerdict.FAIL},
)
BETA = HoneypotConfig("beta", Path("never_opened_beta.py"), {BETA_CELL: EvalVerdict.FAIL})
HONEYPOTS = [ALPHA, BETA]


class FakeAudit:
    """Returns each honeypot's scripted verdict maps in order, or raises for a failing one."""

    def __init__(
        self,
        scripts: dict[str, list[VerdictMap]],
        failing: frozenset[str] = frozenset(),
        honeypots: list[HoneypotConfig] = HONEYPOTS,
    ):
        self._scripts = scripts
        self._failing = failing
        self.calls = {honeypot.name: 0 for honeypot in honeypots}

    async def __call__(self, honeypot: HoneypotConfig) -> VerdictMap:
        self.calls[honeypot.name] += 1
        if honeypot.name in self._failing:
            raise RuntimeError(f"{honeypot.name} crashed")
        return self._scripts[honeypot.name].pop(0)


def a_replay(reproducing: tuple[Cell, ...] = (), clearing: tuple[Cell, ...] = ()) -> VerdictMap:
    """A server run that misses every reproducing cell and finds every clearing one."""
    verdicts: VerdictMap = {cell: EvalVerdict.PASS for cell in reproducing}
    verdicts.update({cell: EvalVerdict.FAIL for cell in clearing})
    return verdicts


def cells_flipping(*flipped: Cell) -> dict[Cell, CellComparison]:
    all_cells = [cell for honeypot in HONEYPOTS for cell in honeypot.ground_truth]
    return {
        cell: CellComparison(outcome=CellOutcome.FLIP if cell in flipped else CellOutcome.UNCHANGED)
        for cell in all_cells
    }
