"""The billing rule shared by the CVE benchmark's published costs and the model probe."""

from dataclasses import dataclass

from mcp_auditor.domain.models import ProviderUsage


@dataclass(frozen=True)
class Prices:
    """Dollars per million tokens."""

    input: float
    cached_input: float
    output: float


@dataclass(frozen=True)
class AuditPrices:
    generator: Prices
    judge: Prices

    def cost(self, generator_usage: ProviderUsage, judge_usage: ProviderUsage) -> float:
        return call_cost(generator_usage, self.generator) + call_cost(judge_usage, self.judge)


def call_cost(usage: ProviderUsage, prices: Prices) -> float:
    uncached_input = usage.input_tokens - usage.cached_input_tokens
    dollars_per_million = (
        uncached_input * prices.input
        + usage.cached_input_tokens * prices.cached_input
        + usage.output_tokens * prices.output
    )
    return dollars_per_million / 1_000_000
