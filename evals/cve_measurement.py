"""A measurement run of the CVE benchmark: chain settings, tool call timeout and tools filter
forced on every target, so its cost says what a holdout run under those conditions costs.
It is always ungated: its conditions match no baseline, and they are recorded here, never in
`CVERunConditions`."""

import argparse
from collections.abc import Mapping, Sequence

from pydantic import BaseModel

from evals.concurrency import non_negative_int, positive_int
from evals.cve_audit import RunOverrides
from evals.cve_costs import CostPricing
from evals.eval_session import Refused
from evals.holdout_conditions import HoldoutConditions
from evals.probe_candidates import Prices

MEASUREMENT_UNGATED = "a measurement run is ungated: its conditions match no baseline"
MEASUREMENT_WITHOUT_AUDIT = (
    "--calibrate and --survey run no audit: a measurement flag forces nothing"
)
STEPS_WITHOUT_CHAINS = "--chain-steps needs --chains above 0: a step runs only inside a chain"


class MeasurementSettings(BaseModel):
    """Each setting left None keeps the launch's own."""

    chains: int | None = None
    chain_steps: int | None = None
    tool_call_timeout: int | None = None
    every_tool: bool = False


def add_measurement_flags(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("measurement run (with --ungated only)")
    group.add_argument("--chains", type=non_negative_int, help="Chains per tool, every target.")
    group.add_argument("--chain-steps", type=positive_int, help="Steps per chain, every target.")
    group.add_argument(
        "--tool-call-timeout", type=positive_int, help="Tool call timeout in seconds."
    )
    group.add_argument(
        "--no-tools-filter", action="store_true", help="Audit every tool of every target."
    )


def measurement_from(args: argparse.Namespace) -> MeasurementSettings | None:
    measurement = MeasurementSettings(
        chains=args.chains,
        chain_steps=args.chain_steps,
        tool_call_timeout=args.tool_call_timeout,
        every_tool=args.no_tools_filter,
    )
    return None if measurement == MeasurementSettings() else measurement


def measurement_refusal(args: argparse.Namespace) -> str | None:
    measurement = measurement_from(args)
    if measurement is None:
        return None
    if args.calibrate or args.survey:
        return MEASUREMENT_WITHOUT_AUDIT
    if not args.ungated or args.record_baseline:
        return MEASUREMENT_UNGATED
    if measurement.chain_steps is not None and not measurement.chains:
        return STEPS_WITHOUT_CHAINS
    return None


def run_overrides(measurement: MeasurementSettings) -> RunOverrides:
    return RunOverrides(
        measurement.chains,
        measurement.chain_steps,
        measurement.tool_call_timeout,
        audit_every_tool=measurement.every_tool,
    )


def missing_price(prices: Mapping[str, Prices], models: Sequence[str]) -> str | None:
    missing = [model for model in dict.fromkeys(models) if model not in prices]
    if not missing:
        return None
    return f"no price for {', '.join(missing)} in evals/holdout_conditions.json"


def cost_pricing(
    conditions: HoldoutConditions,
    models: tuple[str, str],
    measurement: MeasurementSettings | None,
) -> CostPricing | str:
    """The pricing of the run's generator and judge, or why no cost is reported. A measurement
    run exists to be priced, so one that cannot be is refused before any audit."""
    missing = missing_price(conditions.prices, models)
    if missing is not None and measurement is not None:
        raise Refused("Refused.", [missing])
    if missing is not None:
        return missing
    generator, judge = models
    prices = conditions.prices
    return CostPricing(prices[generator], prices[judge], conditions.prices_as_of)


def render_measurement(measurement: MeasurementSettings) -> str:
    chains = _forced(measurement.chains, "{} chains per tool", "the launch's own chains")
    steps = _forced(measurement.chain_steps, "{} steps per chain", "the launch's own chain steps")
    timeout = _forced(
        measurement.tool_call_timeout, "tool call timeout {} s", "the default tool call timeout"
    )
    tools = "every tool audited" if measurement.every_tool else "the target's tools filter"
    return f"Measurement run, forced settings: {chains}, {steps}, {timeout}, {tools}."


def _forced(setting: int | None, forced: str, own: str) -> str:
    return own if setting is None else forced.format(setting)
