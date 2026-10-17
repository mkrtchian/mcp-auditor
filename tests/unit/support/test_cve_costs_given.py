from evals.metrics import PhaseUsage
from evals.probe_candidates import Prices
from mcp_auditor.domain.models import ProviderUsage

ONE_DOLLAR_PER_MILLION = Prices(input=1.0, cached_input=1.0, output=1.0)
TEN_DOLLARS_PER_MILLION = Prices(input=10.0, cached_input=10.0, output=10.0)


def a_phase_usage(total: int, chain: int, judge: int, largest_request: int = 0) -> PhaseUsage:
    """Input tokens only, so a channel at one dollar per million costs its token count / 1e6."""
    return PhaseUsage(
        total=ProviderUsage(input_tokens=total, largest_input_tokens=largest_request),
        chain=ProviderUsage(input_tokens=chain),
        judge=ProviderUsage(input_tokens=judge),
    )
