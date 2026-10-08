"""The grammar's input vocabulary, which imports nothing of the auditor. What the grammar grades:
a case or a whole chain, as the report records it, or a sequence of calibration exchanges. A
chain blocked at its first step keeps no step in the report and is read on its planned first
step."""

from collections.abc import Sequence
from enum import StrEnum
from typing import Any, NamedTuple, NewType


class Verdict(StrEnum):
    PASS = "pass"
    FAIL = "fail"


JudgeCategory = NewType("JudgeCategory", str)


class Step(NamedTuple):
    arguments: dict[str, Any]
    outputs: tuple[str, ...]


class Unit(NamedTuple):
    steps: tuple[Step, ...]
    verdict: Verdict | None  # None: not judged (blocked, refused, or a calibration call)
    category: JudgeCategory | None
    blocked: bool  # independent of verdict: a chain blocked after step 1 is still judged


def unit_of_exchanges(exchanges: Sequence[tuple[dict[str, Any], str]]) -> Unit:
    steps = tuple(Step(arguments, (output,)) for arguments, output in exchanges)
    return Unit(steps, verdict=None, category=None, blocked=False)
