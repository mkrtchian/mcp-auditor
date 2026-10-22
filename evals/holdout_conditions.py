"""The run conditions of a holdout run: the dataclasses and the loader for
`evals/holdout_conditions.json`. Loading never checks readiness, so inspecting the
file stays cheap; the run calls `require_ready` with its own models."""

import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, cast

from evals.eval_session import Refused
from evals.probe_candidates import Prices

CONDITIONS_PATH = Path(__file__).parent / "holdout_conditions.json"

_CHAIN_NOT_SET = (
    "chain settings and tool call timeout not set, set them in evals/holdout_conditions.json"
)


@dataclass(frozen=True)
class Cutoff:
    date: date
    type: str | None
    source: str | None
    note: str | None


@dataclass(frozen=True)
class HoldoutConditions:
    chain_budget: int | None
    max_chain_steps: int | None
    tool_call_timeout: int | None
    cutoffs: dict[str, Cutoff]
    prices: dict[str, Prices]
    prices_as_of: date

    def require_ready(self, model_ids: Sequence[str]) -> None:
        reasons = self._chain_reasons()
        for model in model_ids:
            if model in self.cutoffs:
                reasons.extend(_incomplete_cutoff_reasons(model, self.cutoffs[model]))
            else:
                reasons.append(f"no logged cutoff for {model}")
            if model not in self.prices:
                reasons.append(f"no price for {model}")
        if reasons:
            raise Refused("holdout run conditions not ready", reasons)

    def require_chain_settings(self) -> None:
        reasons = self._chain_reasons()
        if reasons:
            raise Refused("holdout run conditions not ready", reasons)

    def _chain_reasons(self) -> list[str]:
        if None in (self.chain_budget, self.max_chain_steps, self.tool_call_timeout):
            return [_CHAIN_NOT_SET]
        return []


def _incomplete_cutoff_reasons(model: str, cutoff: Cutoff) -> list[str]:
    reasons: list[str] = []
    if not (cutoff.type or "").strip():
        reasons.append(f"no cutoff type for {model}")
    if not (cutoff.source or "").strip():
        reasons.append(f"no cutoff source for {model}")
    return reasons


def load_conditions(path: Path) -> HoldoutConditions:
    if not path.exists():
        raise Refused("holdout run conditions missing", [f"no conditions file at {path}"])
    data: Any = json.loads(path.read_text())
    return HoldoutConditions(
        chain_budget=data["chain_budget"],
        max_chain_steps=data["max_chain_steps"],
        tool_call_timeout=data["tool_call_timeout"],
        cutoffs={
            model: _cutoff(entry) for model, entry in cast(dict[str, Any], data["cutoffs"]).items()
        },
        prices={
            model: _prices(entry) for model, entry in cast(dict[str, Any], data["prices"]).items()
        },
        prices_as_of=date.fromisoformat(data["prices_as_of"]),
    )


def _cutoff(entry: Any) -> Cutoff:
    return Cutoff(
        date=date.fromisoformat(entry["date"]),
        type=entry["type"],
        source=entry["source"],
        note=entry["note"],
    )


def _prices(entry: Any) -> Prices:
    return Prices(input=entry["input"], cached_input=entry["cached_input"], output=entry["output"])
