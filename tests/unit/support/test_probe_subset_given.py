from evals.probe import CallOutcome, ProbeObservation
from evals.probe_candidates import Candidate
from evals.probe_corpus import ProbeCall, ProbeCorpus, ReferenceConditions
from tests.unit.support.test_probe_given import an_observation


def a_corpus_of(schema_names: list[str]) -> ProbeCorpus:
    return ProbeCorpus(
        captured_at="2026-09-24T10:00:00+00:00",
        commit="8457fcc",
        reference=ReferenceConditions(
            provider="google",
            model="gemini-3.1-flash-lite",
            judge_model="gemini-3.1-flash-lite",
            reasoning="minimal",
            judge_reasoning="minimal",
        ),
        budget=10,
        judge_sample_seed=7,
        judge_calls_captured=2,
        calls=[
            ProbeCall(
                call_id=f"call-{index}",
                schema_name=schema_name,
                role="main" if schema_name == "TestCaseBatch" else "judge",
                source="honeypot",
                prompt=f"prompt {index}",
            )
            for index, schema_name in enumerate(schema_names)
        ],
    )


def an_observation_of(candidate: Candidate, outcome: CallOutcome) -> ProbeObservation:
    return an_observation(outcome=outcome).model_copy(update={"candidate": candidate.name})
