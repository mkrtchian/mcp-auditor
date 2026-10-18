import json
from datetime import date
from pathlib import Path
from typing import cast

import pytest

from evals.eval_session import Refused
from evals.holdout_conditions import (
    CONDITIONS_PATH,
    Cutoff,
    load_conditions,
)
from evals.probe_candidates import Prices


def _complete_payload() -> dict[str, object]:
    return {
        "chain_budget": 3,
        "max_chain_steps": 5,
        "tool_call_timeout": 60,
        "cutoffs": {
            "gpt-6-luna": {
                "date": "2026-05-18",
                "type": "training data",
                "source": "https://example.test/luna",
                "note": None,
            }
        },
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
    assert conditions.cutoffs["gpt-6-luna"] == Cutoff(
        date(2026, 5, 18), "training data", "https://example.test/luna", None
    )
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
    payload["cutoffs"] = {
        "gpt-7-sol": {"date": "2026-01-01", "type": None, "source": None, "note": None}
    }
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
    conditions.require_ready(["gpt-6-luna"])
    conditions.require_ready(["claude-haiku-5-5"])


def _payload_with_luna_cutoff(**changes: object) -> dict[str, object]:
    payload = _complete_payload()
    cutoffs = cast(dict[str, dict[str, object]], payload["cutoffs"])
    cutoffs["gpt-6-luna"] |= changes
    return payload


def _refusal_reasons(tmp_path: Path, payload: dict[str, object], models: list[str]) -> list[str]:
    conditions = load_conditions(_write(tmp_path, payload))
    with pytest.raises(Refused) as excinfo:
        conditions.require_ready(models)
    return excinfo.value.reasons


def test_require_ready_refuses_a_cutoff_with_no_type(tmp_path: Path):
    reasons = _refusal_reasons(tmp_path, _payload_with_luna_cutoff(type=None), ["gpt-6-luna"])

    assert reasons == ["no cutoff type for gpt-6-luna"]


def test_require_ready_refuses_a_cutoff_with_an_empty_source(tmp_path: Path):
    reasons = _refusal_reasons(tmp_path, _payload_with_luna_cutoff(source=""), ["gpt-6-luna"])

    assert reasons == ["no cutoff source for gpt-6-luna"]


def test_require_ready_gathers_both_missing_cutoff_fields_in_one_refusal(tmp_path: Path):
    payload = _payload_with_luna_cutoff(type="  ", source=None)

    reasons = _refusal_reasons(tmp_path, payload, ["gpt-6-luna"])

    assert reasons == ["no cutoff type for gpt-6-luna", "no cutoff source for gpt-6-luna"]


def test_a_model_with_no_cutoff_gets_no_type_or_source_reason(tmp_path: Path):
    payload = _complete_payload()
    payload["prices"] = {"gpt-7-sol": {"input": 0.10, "cached_input": 0.01, "output": 0.50}}

    reasons = _refusal_reasons(tmp_path, payload, ["gpt-7-sol"])

    assert reasons == ["no logged cutoff for gpt-7-sol"]


def test_a_cutoff_without_a_source_key_fails_to_load(tmp_path: Path):
    payload = _complete_payload()
    cutoffs = cast(dict[str, dict[str, object]], payload["cutoffs"])
    del cutoffs["gpt-6-luna"]["source"]

    with pytest.raises(KeyError):
        load_conditions(_write(tmp_path, payload))
