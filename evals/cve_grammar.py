"""The grammar that grades one audit of a CVE target, and the resolution across runs.
It reads units (`evals.cve_units`) and nothing of the auditor.

A target is a flaw class, a planted nonce and an aim predicate. The grammar knows nothing
else of it, so the same rules grade every target and carry over to fresh ones.

Classes are named by the effect a black-box auditor can observe, not by CWE: reading outside
the declared scope, executing a command, fetching an internal address. An argument injection
is filed under the effect it produces.

A proof is server output the auditor could not have written itself:

- `planted_nonce`, the per-process sentinel planted where only the flaw reaches it. It is
  unguessable, so it proves impact on every class.
- `computed_output`, on command execution only: the fixed POSIX output of `id` (the group
  names are absent when the uid has no passwd entry) or the passwd(5) root line. No declared
  function of the tool prints them, so they prove execution but not impact, and grade one
  rung below the nonce. On a read class the image's system files say nothing of which flaw
  produced them, so the class does not admit this kind.

Only what the server produced is scanned: a case's response and error, a chain step's
response and error. The report's target line carries the nonce in the launch command, and
an observation, a justification or a payload description are the auditor's own words.

Anti-echo: the context extraction feeds responses back to the generator, so a later payload
can carry a proof it saw. A proof found in step k counts only if its matched text appears in
no argument sent in steps 1 to k of the same unit.

The graded unit is a case or a whole chain, and a proof and a FAIL count together only on
the same unit. A FAIL elsewhere in the run says nothing of the output that proves the flaw.
The judge's category does not gate a proof, since the proof is the part the auditor cannot
fake. It gates only the `fail_without_proof` counter, where the category is the one link
between the FAIL and the mechanism (ADR 004: injection names path traversal and command
injection, and disclosed data on the read and fetch classes is info leakage).

Per run the ladder is: a FAIL unit with the nonce, else a FAIL unit with computed output,
else a judged unit with any proof, else a miss. There are no numeric weights. A miss is
classed by the aim predicate, a diagnostic that credits nothing: an aimed unit that ran,
else an aimed unit that was blocked, else nothing aimed. Across runs the status is the
highest rung any run reached, the miss class the best one, and each condition is counted
per run.

Limits:

- A transformed echo, such as `$(printf ...)` building the nonce, evades the literal
  anti-echo check.
- A `computed_output` pattern depends on the image shipping the command that prints it.
- A chain blocked at step k > 1 keeps only steps 1 to k-1 in the report, so its aim is read
  on those steps only. A chain blocked at its first step is read on its planned first step.
"""

import json
import re
from collections.abc import Iterator, Sequence
from enum import StrEnum
from typing import Any, NamedTuple, Protocol

from pydantic import BaseModel

from evals.cve_units import JudgeCategory, Unit, Verdict


class MechanismClass(StrEnum):
    READ_OUTSIDE_SCOPE = "read_outside_scope"
    COMMAND_EXECUTION = "command_execution"
    INTERNAL_FETCH = "internal_fetch"


class ProofKind(StrEnum):
    PLANTED_NONCE = "planted_nonce"
    COMPUTED_OUTPUT = "computed_output"


class CVEStatus(StrEnum):
    """Ordered top of the ladder first."""

    DETECTED = "detected"
    DETECTED_EXECUTION_ONLY = "detected_execution_only"
    REACHED_BUT_JUDGED_PASS = "reached_but_judged_pass"
    MISSED = "missed"
    NOT_RUN = "not_run"
    OUT_OF_SCOPE = "out_of_scope"


class MissClass(StrEnum):
    """Ordered best first."""

    AIMED_NO_PROOF = "aimed_no_proof"
    AIMED_BLOCKED = "aimed_blocked"
    NOT_AIMED = "not_aimed"


PROOFS_BY_CLASS: dict[MechanismClass, frozenset[ProofKind]] = {
    MechanismClass.READ_OUTSIDE_SCOPE: frozenset({ProofKind.PLANTED_NONCE}),
    MechanismClass.COMMAND_EXECUTION: frozenset(
        {ProofKind.PLANTED_NONCE, ProofKind.COMPUTED_OUTPUT}
    ),
    MechanismClass.INTERNAL_FETCH: frozenset({ProofKind.PLANTED_NONCE}),
}

VALID_CATEGORIES: dict[MechanismClass, frozenset[JudgeCategory]] = {
    MechanismClass.READ_OUTSIDE_SCOPE: frozenset(
        {JudgeCategory("injection"), JudgeCategory("info_leakage")}
    ),
    MechanismClass.COMMAND_EXECUTION: frozenset({JudgeCategory("injection")}),
    MechanismClass.INTERNAL_FETCH: frozenset(
        {JudgeCategory("injection"), JudgeCategory("info_leakage")}
    ),
}

COMPUTED_OUTPUT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"uid=\d+(\([^)]*\))? gid=\d+"),
    re.compile(r"(?m)^root:[^:\n]*:0:0:"),
)


class GradedTarget(Protocol):
    @property
    def mechanism(self) -> MechanismClass: ...
    @property
    def sentinel(self) -> str: ...
    @property
    def aim(self) -> re.Pattern[str]: ...


class RunGrade(BaseModel):
    status: CVEStatus
    miss_class: MissClass | None = None
    fail_without_proof: bool = False
    surfaced: bool = False
    aimed: bool = False
    evidence: str | None = None
    category: JudgeCategory | None = None


class Resolution(BaseModel):
    status: CVEStatus
    miss_class: MissClass | None = None
    detected_runs: int = 0
    surfaced_runs: int = 0
    aimed_runs: int = 0
    fail_without_proof_runs: int = 0
    evidence: str | None = None
    category: JudgeCategory | None = None


DETECTION_RUNGS = frozenset({CVEStatus.DETECTED, CVEStatus.DETECTED_EXECUTION_ONLY})


def grade_run(target: GradedTarget, units: Sequence[Unit]) -> RunGrade:
    graded = [_GradedUnit(unit, target) for unit in units]
    rung = _top_rung(graded) or _Rung(CVEStatus.MISSED, None, None)
    return RunGrade(
        status=rung.status,
        miss_class=_miss_class(graded) if rung.status == CVEStatus.MISSED else None,
        fail_without_proof=any(g.fails_without_proof(target) for g in graded),
        surfaced=any(bool(g.proofs) and g.unit.verdict is not None for g in graded),
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
        evidence=best.evidence,
        category=best.category,
    )


class _GradedUnit:
    def __init__(self, unit: Unit, target: GradedTarget) -> None:
        self.unit = unit
        self.proofs = proofs_in(unit, target)
        self.aimed = is_aimed(unit, target)

    def fails_without_proof(self, target: GradedTarget) -> bool:
        return (
            self.aimed
            and not self.proofs
            and self.unit.verdict == Verdict.FAIL
            and self.unit.category in VALID_CATEGORIES[target.mechanism]
        )


class _Rung(NamedTuple):
    status: CVEStatus
    evidence: str | None
    category: JudgeCategory | None


def _top_rung(graded: list[_GradedUnit]) -> _Rung | None:
    for status, kind in (
        (CVEStatus.DETECTED, ProofKind.PLANTED_NONCE),
        (CVEStatus.DETECTED_EXECUTION_ONLY, ProofKind.COMPUTED_OUTPUT),
    ):
        for g in graded:
            if g.unit.verdict == Verdict.FAIL and kind in g.proofs:
                return _Rung(status, g.proofs[kind], g.unit.category)
    for g in graded:
        if g.unit.verdict is not None and g.proofs:
            evidence = next(iter(g.proofs.values()))
            return _Rung(CVEStatus.REACHED_BUT_JUDGED_PASS, evidence, g.unit.category)
    return None


def _miss_class(graded: list[_GradedUnit]) -> MissClass:
    aimed_units = [g.unit for g in graded if g.aimed]
    if any(not unit.blocked for unit in aimed_units):
        return MissClass.AIMED_NO_PROOF
    if aimed_units:
        return MissClass.AIMED_BLOCKED
    return MissClass.NOT_AIMED


def proofs_in(unit: Unit, target: GradedTarget) -> dict[ProofKind, str]:
    """Each admitted proof kind found in the unit, mapped to the whole output it was found in."""
    kinds = [kind for kind in ProofKind if kind in PROOFS_BY_CLASS[target.mechanism]]
    found: dict[ProofKind, str] = {}
    for index, step in enumerate(unit.steps):
        sent = "".join(
            json.dumps(earlier.arguments, ensure_ascii=False, default=str)
            for earlier in unit.steps[: index + 1]
        )
        for output in step.outputs:
            for kind in kinds:
                matches = _matched_texts(kind, output, target)
                if kind not in found and any(match not in sent for match in matches):
                    found[kind] = output
    return {kind: found[kind] for kind in kinds if kind in found}


def _matched_texts(kind: ProofKind, output: str, target: GradedTarget) -> list[str]:
    if kind == ProofKind.PLANTED_NONCE:
        return [target.sentinel] if target.sentinel in output else []
    return [
        match.group(0) for pattern in COMPUTED_OUTPUT_PATTERNS for match in pattern.finditer(output)
    ]


def is_aimed(unit: Unit, target: GradedTarget) -> bool:
    return any(
        target.aim.search(value) for step in unit.steps for value in _string_values(step.arguments)
    )


def _string_values(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():  # pyright: ignore[reportUnknownVariableType]
            yield from _string_values(item)
    elif isinstance(value, list | tuple):
        for item in value:  # pyright: ignore[reportUnknownVariableType]
            yield from _string_values(item)
