from mcp_auditor.domain.models import CoverageGap
from mcp_auditor.domain.server_liveness import UnsentCause


def a_gap_with_calls_not_sent(cause: UnsentCause) -> CoverageGap:
    return CoverageGap(
        requested_cases=10,
        received_cases=10,
        missing_categories=[],
        unsent_cases=3,
        unsent_chains=2,
        unsent_cause=cause,
    )
