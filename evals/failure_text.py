"""How much of a failure a run's log may show. The acceptance gate and calibration show it all,
since repairing a fixture needs it. The holdout and nuisance runs show no text the server or the
model wrote: exception types and missed-step causes only."""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import cast

from mcp_auditor.domain.models import MissedStep
from mcp_auditor.domain.rendering import MISS_CAUSE_LABELS


@dataclass(frozen=True)
class ReportDetail:
    shows_server_text: bool

    def describe(self, error: BaseException) -> str:
        if self.shows_server_text:
            return str(error)
        return ", ".join(type(original).__name__ for original in _original_errors(error))

    def missed_detail(self, missed: MissedStep) -> str:
        cause = f"{MISS_CAUSE_LABELS[missed.cause]}, {missed.tool_name}: {missed.step}"
        return f"{cause}, {missed.detail}" if self.shows_server_text else cause

    def server_lines[T](self, lines: Sequence[T]) -> list[T]:
        return list(lines) if self.shows_server_text else []


FULL_DETAIL = ReportDetail(shows_server_text=True)
TYPES_ONLY = ReportDetail(shows_server_text=False)


def _original_errors(error: BaseException) -> list[BaseException]:
    # The wrappers say nothing: `LaunchError(str(exc)) from exc` around a task group's
    # "unhandled errors in a TaskGroup (1 sub-exception)".
    if error.__cause__ is not None:
        return _original_errors(error.__cause__)
    if isinstance(error, BaseExceptionGroup):
        group = cast("BaseExceptionGroup[BaseException]", error)
        return [original for leaf in group.exceptions for original in _original_errors(leaf)]
    return [error]
