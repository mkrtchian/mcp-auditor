import math

from evals.pricing import Prices, call_cost
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
