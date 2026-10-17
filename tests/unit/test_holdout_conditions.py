import json
from datetime import date
from pathlib import Path

import pytest

from evals.eval_session import Refused
from evals.holdout_conditions import (
    CONDITIONS_PATH,
    Cutoff,
    HoldoutConditions,
    load_conditions,
)
from evals.probe_candidates import Prices


def _complete_payload() -> dict[str, object]:
    return {
        "chain_budget": 3,
        "max_chain_steps": 5,
        "tool_call_timeout": 60,
        "cutoffs": {"gpt-6-luna": {"date": "2026-05-18", "type": "training data", "note": None}},
        "prices": {"gpt-6-luna": {"input": 0.10, "cached_input": 0.01, "output": 0.50}},
        "prices_as_of": "2026-10-15",
    }


def _write(tmp_path: Path, payload: dict[str, object]) -> Path:
    path = tmp_path / "conditions.json"
    path.write_text(json.dumps(payload))
    return path


def test_a_complete_file_loads(tmp_path: Path):
    conditions = load_conditions(_write(tmp_path, _complete_payload()))

    assert conditions.chain_budget == 3
    assert conditions.max_chain_steps == 5
    assert conditions.tool_call_timeout == 60
    assert conditions.prices_as_of == date(2026, 10, 15)
    assert conditions.cutoffs["gpt-6-luna"] == Cutoff(date(2026, 5, 18), "training data", None)
    assert conditions.prices["gpt-6-luna"] == Prices(input=0.10, cached_input=0.01, output=0.50)


def test_an_absent_file_refuses(tmp_path: Path):
    with pytest.raises(Refused):
        load_conditions(tmp_path / "missing.json")


def test_a_complete_file_passes_require_ready(tmp_path: Path):
    conditions = load_conditions(_write(tmp_path, _complete_payload()))

    conditions.require_ready(["gpt-6-luna"])


@pytest.mark.parametrize("missing", ["chain_budget", "max_chain_steps", "tool_call_timeout"])
def test_require_ready_refuses_a_null_chain_setting(tmp_path: Path, missing: str):
    payload = _complete_payload()
    payload[missing] = None
    conditions = load_conditions(_write(tmp_path, payload))

    with pytest.raises(Refused) as excinfo:
        conditions.require_ready(["gpt-6-luna"])

    assert any(
        "chain settings and tool call timeout not set" in reason for reason in excinfo.value.reasons
    )


def test_require_ready_refuses_a_model_with_no_cutoff(tmp_path: Path):
    conditions = load_conditions(_write(tmp_path, _complete_payload()))

    with pytest.raises(Refused) as excinfo:
        conditions.require_ready(["gpt-7-sol"])

    assert any("no logged cutoff for gpt-7-sol" in reason for reason in excinfo.value.reasons)


def test_require_ready_refuses_a_model_with_no_price(tmp_path: Path):
    payload = _complete_payload()
    payload["cutoffs"] = {"gpt-7-sol": {"date": "2026-01-01", "type": None, "note": None}}
    conditions = load_conditions(_write(tmp_path, payload))

    with pytest.raises(Refused) as excinfo:
        conditions.require_ready(["gpt-7-sol"])

    assert any("no price for gpt-7-sol" in reason for reason in excinfo.value.reasons)


def test_the_committed_file_is_ready_for_the_logged_models():
    conditions = load_conditions(CONDITIONS_PATH)

    assert conditions.chain_budget == 3
    assert conditions.max_chain_steps == 3
    assert conditions.tool_call_timeout == 30
    assert conditions.cutoffs["gpt-6-luna"].date == date(2026, 5, 18)
    assert conditions.prices["gpt-6-luna"] == Prices(input=0.10, cached_input=0.01, output=0.50)
    assert conditions.cutoffs["claude-haiku-5-5"].date == date(2026, 6, 30)
    assert conditions.prices["claude-haiku-5-5"] == Prices(
        input=0.10, cached_input=0.01, output=0.50
    )

    conditions.require_ready(["gpt-6-luna", "claude-haiku-5-5"])


def test_run_cutoff_returns_the_latest_cutoff():
    conditions = load_conditions(CONDITIONS_PATH)

    assert conditions.run_cutoff(["gpt-6-luna"]) == date(2026, 5, 18)


def test_run_cutoff_takes_the_latest_among_the_run_models():
    cutoffs = {
        "early": Cutoff(date(2026, 1, 1), None, None),
        "late": Cutoff(date(2026, 9, 1), None, None),
    }
    conditions = HoldoutConditions(
        chain_budget=3,
        max_chain_steps=5,
        tool_call_timeout=60,
        cutoffs=cutoffs,
        prices={},
        prices_as_of=date(2026, 10, 15),
    )

    assert conditions.run_cutoff(["early", "late"]) == date(2026, 9, 1)
