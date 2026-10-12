"""The grammar that grades one audit of a CVE target, and the resolution across runs.
It reads units (`evals.cve_units`), the nonce and aim reading and the strike rule
(`evals.cve_proofs`), and nothing of the auditor.

A target is a flaw class, a map of planted nonces (one per location where only the flaw
reaches) and an aim predicate. The grammar knows nothing else of it, so the same rules grade
every target and carry over to fresh ones.

Classes are named by the effect a black-box auditor can observe, not by CWE: reading outside
the declared scope, executing a command, fetching an internal address. An argument injection
is filed under the effect it produces. A target may carry no class, and then every judge
category counts toward `fail_without_proof`.

A proof is the planted nonce, server output the auditor could not have written itself. It is
unguessable and planted where only the flaw reaches, so it proves impact on every class. Only
what the server produced is scanned: a case's response and error, a chain step's response and
error. The report's target line carries the nonce in the launch command, and an observation,
a justification or a payload description are the auditor's own words.

A proof and a FAIL count together only on the same unit (a case or a whole chain). A FAIL
elsewhere in the run says nothing of the output that proves the flaw. The judge's category
does not gate a proof, since the proof is the part the auditor cannot fake. It gates only the
`fail_without_proof` counter, where the category is the one link between the FAIL and the
mechanism (ADR 004: injection names path traversal and command injection, and disclosed data
on the read and fetch classes is info leakage).

The replay of ADR 030 strikes a credit the auditor could have earned against the patched
server. A credit is a (unit, place) pair, struck in its own unit only: a place struck in one
unit still credits another unit that proved it. `grade_run` takes the strike as a
`CreditCheck` and grades on the credits that remain. A run not replayed is unchecked: its
credits are kept, and `status_if_unchecked_missed` records what the status would be if every
credit were struck.

Per run the ladder is: a FAIL unit with a remaining nonce, else a judged unit with a
remaining nonce, else a miss. There are no numeric weights. A miss is classed by the aim
predicate, a diagnostic that credits nothing: an aimed unit that ran, else an aimed unit that
was blocked, else nothing aimed. Across runs the status is the highest rung any run reached,
the miss class the best one, and each condition is counted per run.

Limits:

- A transformed echo, such as `$(printf ...)` building the nonce, evades the literal
  anti-echo check.
- A chain blocked at step k > 1 keeps only steps 1 to k-1 in the report, so its aim is read
  on those steps only. A chain blocked at its first step is read on its planned first step.
"""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import NamedTuple, Protocol

from pydantic import BaseModel, field_serializer

from evals.cve_proofs import UnitPlace, is_aimed, proofs_in
from evals.cve_units import JudgeCategory, Unit, Verdict


class MechanismClass(StrEnum):
    READ_OUTSIDE_SCOPE = "read_outside_scope"
    COMMAND_EXECUTION = "command_execution"
    INTERNAL_FETCH = "internal_fetch"


class ProofKind(StrEnum):
    PLANTED_NONCE = "planted_nonce"


class CVEStatus(StrEnum):
    """Ordered top of the ladder first."""

    DETECTED = "detected"
    REACHED_BUT_JUDGED_PASS = "reached_but_judged_pass"
    MISSED = "missed"


class MissClass(StrEnum):
    """Ordered best first."""

    AIMED_NO_PROOF = "aimed_no_proof"
    AIMED_BLOCKED = "aimed_blocked"
    NOT_AIMED = "not_aimed"


_INJECTION = JudgeCategory("injection")
_INFO_LEAKAGE = JudgeCategory("info_leakage")

VALID_CATEGORIES: dict[MechanismClass, frozenset[JudgeCategory]] = {
    MechanismClass.READ_OUTSIDE_SCOPE: frozenset({_INJECTION, _INFO_LEAKAGE}),
    MechanismClass.COMMAND_EXECUTION: frozenset({_INJECTION}),
    MechanismClass.INTERNAL_FETCH: frozenset({_INJECTION, _INFO_LEAKAGE}),
}

DETECTION_RUNGS = frozenset({CVEStatus.DETECTED})


class GradedTarget(Protocol):
    @property
    def mechanism(self) -> MechanismClass | None: ...
    @property
    def nonces(self) -> Mapping[str, str]: ...
    @property
    def aim(self) -> re.Pattern[str]: ...


@dataclass(frozen=True)
class PlantedTarget:
    """A target built after the launch, with the nonces drawn for it."""

    mechanism: MechanismClass | None
    aim: re.Pattern[str]
    nonces: Mapping[str, str]


class CreditCheck(NamedTuple):
    struck: frozenset[UnitPlace]
    unchecked: bool

    @classmethod
    def none(cls) -> "CreditCheck":
        return cls(frozenset(), False)


_NO_CHECK = CreditCheck.none()


class RunGrade(BaseModel):
    status: CVEStatus
    miss_class: MissClass | None = None
    fail_without_proof: bool = False
    surfaced_places: frozenset[str] = frozenset()
    struck_places: frozenset[str] = frozenset()
    unchecked_places: frozenset[str] = frozenset()
    status_if_unchecked_missed: CVEStatus | None = None
    aimed: bool = False
    evidence: str | None = None
    category: JudgeCategory | None = None

    @property
    def surfaced(self) -> bool:
        return bool(self.surfaced_places)

    @field_serializer("surfaced_places", "struck_places", "unchecked_places")
    def _sorted(self, places: frozenset[str]) -> list[str]:
        return sorted(places)


class Resolution(BaseModel):
    status: CVEStatus
    miss_class: MissClass | None = None
    detected_runs: int = 0
    surfaced_runs: int = 0
    aimed_runs: int = 0
    fail_without_proof_runs: int = 0
    surfaced_places: list[list[str]] = []
    struck_places: list[list[str]] = []
    unchecked_places: list[list[str]] = []
    evidence: str | None = None
    category: JudgeCategory | None = None


def grade_run(
    target: GradedTarget, units: Sequence[Unit], check: CreditCheck = _NO_CHECK
) -> RunGrade:
    graded = [_GradedUnit(index, unit, target, check) for index, unit in enumerate(units)]
    rung = _top_rung(graded) or _Rung(CVEStatus.MISSED, None, None)
    return RunGrade(
        status=rung.status,
        miss_class=_miss_class(graded) if rung.status == CVEStatus.MISSED else None,
        fail_without_proof=any(g.fails_without_proof(target) for g in graded),
        surfaced_places=_surfaced_places(graded),
        struck_places=frozenset(pair.place_id for pair in check.struck),
        unchecked_places=_unchecked_places(graded, check),
        status_if_unchecked_missed=_status_if_unchecked_missed(
            target, units, graded, check, rung.status
        ),
        aimed=any(g.aimed for g in graded),
        evidence=rung.evidence,
        category=rung.category,
    )


def resolve(grades: Sequence[RunGrade]) -> Resolution:
    best = min(grades, key=lambda grade: list(CVEStatus).index(grade.status))
    miss_classes = [grade.miss_class for grade in grades if grade.miss_class is not None]
    return Resolution(
        status=best.status,
        miss_class=(
            min(miss_classes, key=list(MissClass).index)
            if best.status == CVEStatus.MISSED
            else None
        ),
        detected_runs=sum(grade.status in DETECTION_RUNGS for grade in grades),
        surfaced_runs=sum(grade.surfaced for grade in grades),
        aimed_runs=sum(grade.aimed for grade in grades),
        fail_without_proof_runs=sum(grade.fail_without_proof for grade in grades),
        surfaced_places=[sorted(grade.surfaced_places) for grade in grades],
        struck_places=[sorted(grade.struck_places) for grade in grades],
        unchecked_places=[sorted(grade.unchecked_places) for grade in grades],
        evidence=best.evidence,
        category=best.category,
    )


class _GradedUnit:
    def __init__(self, index: int, unit: Unit, target: GradedTarget, check: CreditCheck) -> None:
        self.index = index
        self.unit = unit
        self.proofs = proofs_in(unit, target)
        self.remaining = {
            place_id: output
            for place_id, output in self.proofs.items()
            if UnitPlace(index, place_id) not in check.struck
        }
        self.aimed = is_aimed(unit, target.aim)

    def fails_without_proof(self, target: GradedTarget) -> bool:
        return (
            self.aimed
            and not self.proofs
            and self.unit.verdict == Verdict.FAIL
            and _category_counts(target.mechanism, self.unit.category)
        )


class _Rung(NamedTuple):
    status: CVEStatus
    evidence: str | None
    category: JudgeCategory | None


def _top_rung(graded: list[_GradedUnit]) -> _Rung | None:
    for g in graded:
        if g.unit.verdict == Verdict.FAIL and g.remaining:
            return _Rung(CVEStatus.DETECTED, next(iter(g.remaining.values())), g.unit.category)
    for g in graded:
        if g.unit.verdict is not None and g.remaining:
            evidence = next(iter(g.remaining.values()))
            return _Rung(CVEStatus.REACHED_BUT_JUDGED_PASS, evidence, g.unit.category)
    return None


def _miss_class(graded: list[_GradedUnit]) -> MissClass:
    aimed_units = [g.unit for g in graded if g.aimed]
    if any(not unit.blocked for unit in aimed_units):
        return MissClass.AIMED_NO_PROOF
    if aimed_units:
        return MissClass.AIMED_BLOCKED
    return MissClass.NOT_AIMED


def _surfaced_places(graded: list[_GradedUnit]) -> frozenset[str]:
    return frozenset(
        place_id for g in graded if g.unit.verdict is not None for place_id in g.proofs
    )


def _unchecked_places(graded: list[_GradedUnit], check: CreditCheck) -> frozenset[str]:
    if not check.unchecked:
        return frozenset()
    return frozenset(place_id for g in graded for place_id in g.proofs)


def _status_if_unchecked_missed(
    target: GradedTarget,
    units: Sequence[Unit],
    graded: list[_GradedUnit],
    check: CreditCheck,
    status: CVEStatus,
) -> CVEStatus:
    if not check.unchecked:
        return status
    every_credit = frozenset(UnitPlace(g.index, place_id) for g in graded for place_id in g.proofs)
    return grade_run(target, units, CreditCheck(every_credit, False)).status


def _category_counts(mechanism: MechanismClass | None, category: JudgeCategory | None) -> bool:
    if mechanism is None:
        return True
    return category in VALID_CATEGORIES[mechanism]
