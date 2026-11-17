from mcp_auditor.domain.models import ToolResponse
from mcp_auditor.domain.server_liveness import RelaunchCause
from mcp_auditor.domain.server_watch import SendAttempt
from tests.integration.support.test_cve_relaunch_given import container_id


def timed_out_and_left_the_ping_unanswered(attempt: SendAttempt) -> None:
    """The timeout first: a call that does not block must fail here, not pass with no relaunch."""
    assert isinstance(attempt.outcome, ToolResponse), attempt
    assert attempt.outcome.error_type == "TimeoutError", attempt
    relaunched_for(attempt, RelaunchCause.UNANSWERED_PING)


def relaunched_for(attempt: SendAttempt, cause: RelaunchCause) -> None:
    assert attempt.relaunch is not None, attempt
    assert attempt.relaunch.cause is cause, attempt
    assert attempt.relaunch.succeeded, attempt


def runs_in_a_new_container(name: str, old_container: str | None) -> None:
    assert old_container is not None
    assert container_id(old_container) is None, "the old container is still there"
    assert container_id(name) not in (None, old_container)


def is_answered(attempt: SendAttempt) -> None:
    assert isinstance(attempt.outcome, ToolResponse), attempt
    assert not attempt.outcome.is_error, attempt
    assert attempt.relaunch is None, attempt
