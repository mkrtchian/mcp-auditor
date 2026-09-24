from pathlib import Path

import pytest

import tests.unit.support.test_probe_corpus_given as given
from evals.probe_corpus import (
    ProbeCall,
    RecordingLLM,
    load_corpus,
    sample_judge_calls,
    schema_for,
    write_corpus,
)
from mcp_auditor.domain.models import (
    AttackContext,
    AuditPayload,
    ChainPlanBatch,
    Judgment,
    StepObservation,
    TestCaseBatch,
)
from tests.fakes.llm import FakeLLM


class TestRecordingLLM:
    async def test_records_the_call_and_returns_the_inner_result(self):
        judgment = given.a_judgment()
        sink: list[ProbeCall] = []
        recording = RecordingLLM(FakeLLM([judgment]), role="judge", sink=sink)

        result, _ = await recording.generate_structured("judge this", Judgment)

        assert result is judgment
        assert [(c.schema_name, c.role, c.source, c.prompt) for c in sink] == [
            ("Judgment", "judge", "honeypot", "judge this")
        ]
        assert sink[0].call_id == "honeypot/Judgment/000"

    async def test_two_wrappers_on_one_sink_give_unique_ids_across_roles(self):
        sink: list[ProbeCall] = []
        main = RecordingLLM(FakeLLM([given.a_judgment(), given.a_judgment()]), "main", sink)
        judge = RecordingLLM(FakeLLM([given.a_judgment()]), "judge", sink)

        await main.generate_structured("first", Judgment)
        await judge.generate_structured("second", Judgment)
        await main.generate_structured("third", Judgment)

        assert len({call.call_id for call in sink}) == 3


class TestSampleJudgeCalls:
    def test_keeps_every_non_judge_call_and_draws_the_requested_number(self):
        calls = given.a_capture(main_calls=5, judge_calls=10)

        sampled = sample_judge_calls(calls, size=4, seed=1)

        assert [c for c in sampled if c.role == "main"] == [c for c in calls if c.role == "main"]
        assert len([c for c in sampled if c.role == "judge"]) == 4

    def test_the_same_seed_draws_the_same_calls(self):
        calls = given.a_capture(main_calls=5, judge_calls=10)

        assert sample_judge_calls(calls, size=4, seed=1) == sample_judge_calls(calls, 4, seed=1)

    def test_keeps_capture_order(self):
        calls = given.a_capture(main_calls=5, judge_calls=10)

        sampled = sample_judge_calls(calls, size=4, seed=1)

        positions = [calls.index(call) for call in sampled]
        assert positions == sorted(positions)

    def test_raises_naming_the_captured_count_when_too_few_judge_calls(self):
        calls = given.a_capture(main_calls=5, judge_calls=3)

        with pytest.raises(ValueError, match="3"):
            sample_judge_calls(calls, size=4, seed=1)


class TestSchemaFor:
    @pytest.mark.parametrize(
        "schema",
        [TestCaseBatch, Judgment, AttackContext, ChainPlanBatch, StepObservation, AuditPayload],
    )
    def test_maps_each_captured_schema_name(self, schema: type):
        assert schema_for(schema.__name__) is schema

    def test_raises_on_an_unknown_name(self):
        with pytest.raises(ValueError, match="Unknown"):
            schema_for("Unknown")


def test_a_written_corpus_loads_back_unchanged(tmp_path: Path):
    corpus = given.a_corpus()
    path = tmp_path / "fixtures" / "probe_corpus.json"

    write_corpus(path, corpus)

    assert load_corpus(path) == corpus
