"""Per-target cost of a CVE benchmark run, priced from the usage billed to each target.

Total and judge dollars are exact by role: the generator's usage (total minus judge) at the
generator's price, the judge's at the judge's. The single-step and chain columns cannot be
split by role, since the chain judgment counts in both the chain and the judge channels, so
they are priced only when generator and judge share one price, and left None otherwise.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date

from pydantic import BaseModel

from evals.metrics import PhaseUsage
from evals.probe import call_cost
from evals.probe_candidates import Prices
from mcp_auditor.domain.models import ProviderUsage

# Above this many input tokens in one request, a tiered vendor (Anthropic) bills the whole
# request at a higher rate, which the flat `Prices` cannot carry: such a cost is under-reported.
TIERED_REQUEST_INPUT_TOKENS = 100_000


class TargetCost(BaseModel):
    cve_id: str
    usage: PhaseUsage
    single_step: float | None
    chains: float | None
    judge: float
    total: float
    largest_input_tokens: int


def target_costs(
    by_target: Mapping[str, PhaseUsage], generator_prices: Prices, judge_prices: Prices
) -> list[TargetCost]:
    shared = generator_prices if generator_prices == judge_prices else None
    return [
        TargetCost(
            cve_id=cve_id,
            usage=usage,
            single_step=_priced(usage.total.sub(usage.chain), shared),
            chains=_priced(usage.chain, shared),
            judge=call_cost(usage.judge, judge_prices),
            total=call_cost(usage.total.sub(usage.judge), generator_prices)
            + call_cost(usage.judge, judge_prices),
            largest_input_tokens=usage.total.largest_input_tokens,
        )
        for cve_id, usage in sorted(by_target.items())
    ]


def _priced(usage: ProviderUsage, prices: Prices | None) -> float | None:
    return None if prices is None else call_cost(usage, prices)


@dataclass(frozen=True)
class CostPricing:
    generator: Prices
    judge: Prices
    as_of: date

    def costs(self, by_target: Mapping[str, PhaseUsage]) -> list[TargetCost]:
        return target_costs(by_target, self.generator, self.judge)


def render_cost_table(costs: Sequence[TargetCost]) -> list[str]:
    return [
        "| CVE | Input tokens | Output tokens | Largest request | Single-step | Chains | Judge "
        "| Total |",
        "|---|---|---|---|---|---|---|---|",
        *(_render_cost_row(cost) for cost in costs),
    ]


def _render_cost_row(cost: TargetCost) -> str:
    cells = [
        cost.cve_id,
        str(cost.usage.total.input_tokens),
        str(cost.usage.total.output_tokens),
        str(cost.largest_input_tokens),
        _dollars(cost.single_step),
        _dollars(cost.chains),
        _dollars(cost.judge),
        _dollars(cost.total),
    ]
    return f"| {' | '.join(cells)} |"


def _dollars(amount: float | None) -> str:
    return "-" if amount is None else f"${amount:.4f}"


def large_request_targets(costs: Sequence[TargetCost]) -> list[str]:
    return [
        cost.cve_id for cost in costs if cost.largest_input_tokens > TIERED_REQUEST_INPUT_TOKENS
    ]
