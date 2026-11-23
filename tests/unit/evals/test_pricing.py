import math

from evals.pricing import AuditPrices, Prices, call_cost
from mcp_auditor.domain.models import ProviderUsage


class TestCallCost:
    def test_prices_cached_input_apart_from_the_rest_of_the_input(self):
        usage = ProviderUsage(input_tokens=1_000_000, cached_input_tokens=400_000, output_tokens=0)
        prices = Prices(input=0.25, cached_input=0.025, output=1.50)

        assert math.isclose(call_cost(usage, prices), 0.6 * 0.25 + 0.4 * 0.025)

    def test_prices_output_at_the_output_price(self):
        usage = ProviderUsage(output_tokens=100_000)
        prices = Prices(input=0.25, cached_input=0.025, output=1.50)

        assert math.isclose(call_cost(usage, prices), 0.15)


class TestAuditPrices:
    def test_bills_each_usage_at_its_own_model_price(self):
        prices = AuditPrices(
            generator=Prices(input=1.0, cached_input=1.0, output=1.0),
            judge=Prices(input=10.0, cached_input=10.0, output=10.0),
        )

        cost = prices.cost(
            generator_usage=ProviderUsage(input_tokens=1_000_000),
            judge_usage=ProviderUsage(input_tokens=100_000),
        )

        assert math.isclose(cost, 1.0 + 1.0)
