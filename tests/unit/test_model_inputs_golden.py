import json

import pytest

import tests.unit.support.test_model_inputs_golden_given as given


async def test_what_reaches_a_model_or_an_agent_is_as_recorded(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-placeholder")
    recorded = json.loads(given.GOLDEN_PATH.read_text())

    produced = await given.golden_entries()

    differing = [
        key for key in sorted(recorded | produced) if recorded.get(key) != produced.get(key)
    ]
    assert not differing, f"first differing key: {differing[0]}"
