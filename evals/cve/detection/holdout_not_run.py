"""The holdout report's not-run section: every target dropped with its reason, opened by the
targets dropped during the run counted per cause against the targets launched, the N the rule
starts from, and closed by the targets that ran only after a clean solo second pass of the pre-run
check. The pre-run check's reasons carry per-target detail, so they get no count line."""

from collections import Counter
from collections.abc import Sequence

from pydantic import BaseModel

from evals.cve.detection.holdout_results import DROPPED_RUN_REASONS, NotRunCause, NotRunTarget


class NotRunLine(BaseModel):
    flaw_id: str
    reason: str
    cause: NotRunCause

    @classmethod
    def of(cls, target: NotRunTarget) -> "NotRunLine":
        return cls(flaw_id=target.flaw_id, reason=target.reason, cause=target.cause)


def not_run_section(
    not_run: Sequence[NotRunLine], audited_targets: int, second_pass: Sequence[str]
) -> list[str]:
    lines = [f"- {line.flaw_id}: {line.reason}" for line in not_run] or ["- none"]
    second = [
        f"- run after a clean solo second pass of the pre-run check: {', '.join(second_pass)}"
    ]
    return [
        "## Not run",
        *_dropped_during_the_run(not_run, audited_targets),
        *lines,
        *(second if second_pass else []),
        "",
    ]


def _dropped_during_the_run(not_run: Sequence[NotRunLine], audited_targets: int) -> list[str]:
    causes = Counter(line.cause for line in not_run)
    launched = audited_targets + sum(causes[cause] for cause in DROPPED_RUN_REASONS)
    return [
        f"- {causes[cause]} of the {launched} target(s) launched: {reason}"
        for cause, reason in DROPPED_RUN_REASONS.items()
        if causes[cause]
    ]
