from evals.cve_audit import LaunchError
from evals.failure_text import FULL_DETAIL, TYPES_ONLY
from mcp_auditor.domain.models import AuditStep, MissCause, MissedStep
from mcp_auditor.domain.rendering import MISS_CAUSE_LABELS

SECRET = "secret-nonce"


def test_the_full_detail_carries_the_error_message() -> None:
    assert SECRET in FULL_DETAIL.describe(ValueError(SECRET))


def test_the_types_only_detail_names_the_error_type_and_never_its_message() -> None:
    described = TYPES_ONLY.describe(ValueError(SECRET))

    assert "ValueError" in described
    assert SECRET not in described


def test_a_nested_exception_group_reads_as_the_types_of_its_leaves() -> None:
    group = ExceptionGroup(
        SECRET, [TimeoutError(SECRET), ExceptionGroup(SECRET, [ConnectionError(SECRET)])]
    )

    described = TYPES_ONLY.describe(group)

    assert "TimeoutError" in described
    assert "ConnectionError" in described
    assert "ExceptionGroup" not in described
    assert SECRET not in described


def test_a_wrapping_error_reads_as_the_original_error_it_was_raised_from() -> None:
    try:
        try:
            raise ExceptionGroup(SECRET, [TimeoutError()])
        except ExceptionGroup as group:
            raise LaunchError(SECRET) from group
    except LaunchError as error:
        described = TYPES_ONLY.describe(error)

    assert described == "TimeoutError"


def test_a_missed_step_shows_its_cause_without_the_provider_message() -> None:
    refusal = MissedStep(
        tool_name="git_init",
        step=AuditStep.CHAIN_PLANNING,
        cause=MissCause.PROVIDER_REFUSAL,
        detail=SECRET,
    )

    assert SECRET in FULL_DETAIL.missed_detail(refusal)
    assert SECRET not in TYPES_ONLY.missed_detail(refusal)
    assert MISS_CAUSE_LABELS[MissCause.PROVIDER_REFUSAL] in TYPES_ONLY.missed_detail(refusal)


def test_only_the_full_detail_shows_the_server_lines() -> None:
    lines = ["Traceback", SECRET]

    assert FULL_DETAIL.server_lines(lines) == lines
    assert TYPES_ONLY.server_lines(lines) == []
