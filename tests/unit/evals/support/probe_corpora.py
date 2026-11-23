from evals.model_conditions import ModelConditions
from evals.probe.corpus import ProbeCall, ProbeCorpus


def a_probe_corpus(calls: list[ProbeCall]) -> ProbeCorpus:
    return ProbeCorpus(
        captured_at="2026-09-24T10:00:00+00:00",
        commit="8457fcc",
        reference=ModelConditions(
            provider="google",
            model="gemini-3.1-flash-lite",
            judge_model="gemini-3.1-flash-lite",
            reasoning="minimal",
            judge_reasoning="minimal",
        ),
        budget=10,
        judge_sample_seed=7,
        judge_calls_captured=2,
        calls=calls,
    )
