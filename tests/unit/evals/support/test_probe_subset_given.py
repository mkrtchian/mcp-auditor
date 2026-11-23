from evals.probe.analysis import CallOutcome, ProbeObservation
from evals.probe.candidates import Candidate
from evals.probe.corpus import ProbeCall, ProbeCorpus
from tests.unit.evals.support.probe_corpora import a_probe_corpus
from tests.unit.evals.support.probe_observations import an_observation


def a_corpus_of(schema_names: list[str]) -> ProbeCorpus:
    return a_probe_corpus(
        [
            ProbeCall(
                call_id=f"call-{index}",
                schema_name=schema_name,
                role="main" if schema_name == "TestCaseBatch" else "judge",
                source="honeypot",
                prompt=f"prompt {index}",
            )
            for index, schema_name in enumerate(schema_names)
        ]
    )


def an_observation_of(candidate: Candidate, outcome: CallOutcome) -> ProbeObservation:
    return an_observation(outcome=outcome).model_copy(update={"candidate": candidate.name})
