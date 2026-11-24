import pytest

import tests.unit.support.grammar_inputs as grammar
from evals.cve.audit_attempts import (
    INCOMPLETE_ATTEMPTS,
    INCOMPLETE_CAUSES,
    AttemptOutcome,
    IncompleteAttempt,
    ProviderErrorAttempt,
    ThrottledAttempt,
    graded_despite_missed_model_calls,
)
from evals.cve.detection.audit import DETECTION_GATE_WORDING, graded_or_incomplete
from evals.cve.detection.session_model import GradedAudit
from evals.cve.grammar import MissKind, RunGrade, TargetStatus
from mcp_auditor.domain.model_calls import MissedCallCause
from tests.unit.detection.support.detection_audits import TARGET, ScriptedAttempts, a_report_missing
from tests.unit.detection.support.detection_reports import a_detected_grade
from tests.unit.support.captured_console import a_captured_console

_REFUSED = frozenset({MissedCallCause.PROVIDER_REFUSAL})


async def test_a_refused_audit_is_audited_again_and_graded_by_the_first_attempt_not_refused(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    a_captured_console(capsys, monkeypatch)
    graded = GradedAudit(a_detected_grade(), grammar.a_report(server_command="second attempt"))
    attempt = ScriptedAttempts([IncompleteAttempt(grammar.a_report(), _REFUSED), graded])

    outcome = await graded_despite_missed_model_calls(
        TARGET.flaw_id, attempt, DETECTION_GATE_WORDING
    )

    assert outcome is graded
    assert attempt.calls == 2


async def test_an_audit_missing_a_model_call_at_every_attempt_is_a_run_not_completed(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    output = a_captured_console(capsys, monkeypatch)
    unreadable = IncompleteAttempt(
        grammar.a_report(), frozenset({MissedCallCause.UNREADABLE_ANSWER})
    )
    outcomes: list[AttemptOutcome[GradedAudit]] = [
        IncompleteAttempt(grammar.a_report(), _REFUSED),
        *[unreadable] * (INCOMPLETE_ATTEMPTS - 1),
    ]
    attempt = ScriptedAttempts[GradedAudit](outcomes)

    grade = await graded_despite_missed_model_calls(TARGET.flaw_id, attempt, DETECTION_GATE_WORDING)

    assert grade is None
    assert attempt.calls == INCOMPLETE_ATTEMPTS
    printed = " ".join(output.getvalue().split())
    assert f"{TARGET.flaw_id}: attempt 1/{INCOMPLETE_ATTEMPTS}: refused by the model provider" in (
        printed
    )
    assert f"{TARGET.flaw_id}: attempt 2/{INCOMPLETE_ATTEMPTS}: unreadable model answer" in printed
    assert f"{TARGET.flaw_id} run skipped" in printed
    assert "refused by the model provider and unreadable model answer" in printed


async def test_an_attempt_whose_prompt_was_too_long_names_its_cause(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    output = a_captured_console(capsys, monkeypatch)
    too_long = IncompleteAttempt(grammar.a_report(), frozenset({MissedCallCause.PROMPT_TOO_LONG}))
    graded = GradedAudit(a_detected_grade(), grammar.a_report())
    attempt = ScriptedAttempts[GradedAudit]([too_long, graded])

    await graded_despite_missed_model_calls(TARGET.flaw_id, attempt, DETECTION_GATE_WORDING)

    printed = " ".join(output.getvalue().split())
    assert (
        f"{TARGET.flaw_id}: attempt 1/{INCOMPLETE_ATTEMPTS}:"
        " prompt longer than the model's context window, not graded"
    ) in printed


@pytest.mark.parametrize(
    "thrown_away",
    [None, ProviderErrorAttempt("ModelAPIError"), ThrottledAttempt()],
    ids=["run_skipped", "provider_error", "throttled"],
)
async def test_an_attempt_thrown_away_is_not_audited_again(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    thrown_away: AttemptOutcome[GradedAudit],
):
    a_captured_console(capsys, monkeypatch)
    attempt = ScriptedAttempts[GradedAudit]([thrown_away])

    grade = await graded_despite_missed_model_calls(TARGET.flaw_id, attempt, DETECTION_GATE_WORDING)

    assert grade is None
    assert attempt.calls == 1


@pytest.mark.parametrize("cause", list(MissedCallCause))
def test_a_detection_is_kept_whatever_model_call_was_missed(cause: MissedCallCause):
    outcome = graded_or_incomplete(a_detected_grade(), a_report_missing(cause))

    assert isinstance(outcome, RunGrade)
    assert outcome.status == TargetStatus.DETECTED


@pytest.mark.parametrize("cause", sorted(INCOMPLETE_CAUSES))
def test_a_miss_with_a_missed_model_call_is_not_graded_and_carries_its_cause(
    cause: MissedCallCause,
):
    missed = grammar.a_missed_run(MissKind.AIMED_NO_PROOF)

    outcome = graded_or_incomplete(missed, a_report_missing(cause))

    assert isinstance(outcome, IncompleteAttempt)
    assert outcome.causes == {cause}


def test_a_miss_with_no_missed_model_call_is_graded_a_miss():
    missed = grammar.a_missed_run(MissKind.AIMED_NO_PROOF)

    outcome = graded_or_incomplete(missed, grammar.a_report())

    assert isinstance(outcome, RunGrade)
    assert outcome.status == TargetStatus.MISSED


def test_a_struck_only_credit_with_a_refused_model_call_reads_as_refused():
    # The replay struck the run's only credit, so the final grade is a miss. A refused model call
    # then makes it a refusal, not a genuine miss, so a refusal never poisons the gate or the
    # baseline.
    struck = RunGrade(
        status=TargetStatus.MISSED,
        miss_kind=MissKind.AIMED_NO_PROOF,
        struck_places=frozenset({grammar.PLACE}),
    )

    outcome = graded_or_incomplete(struck, a_report_missing(MissedCallCause.PROVIDER_REFUSAL))

    assert isinstance(outcome, IncompleteAttempt)
