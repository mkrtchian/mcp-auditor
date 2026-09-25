import pytest

import tests.unit.support.test_probe_subset_given as given
from evals.probe import CallOutcome
from evals.probe_candidates import CHALLENGERS, REFERENCE
from evals.probe_subset import UnknownCandidate, defect_counts, select_calls, select_candidates


class TestSelectCandidates:
    def test_returns_the_named_candidates_once_each_in_the_order_given(self):
        selected = select_candidates(["gpt-6-luna low", "gpt-6-luna none", "gpt-6-luna low"])

        assert selected == [CHALLENGERS[1], CHALLENGERS[0]]

    def test_finds_the_reference_and_the_challengers(self):
        selected = select_candidates([REFERENCE.name, CHALLENGERS[0].name])

        assert selected == [REFERENCE, CHALLENGERS[0]]

    def test_refuses_an_unknown_name_naming_the_known_candidates(self):
        with pytest.raises(UnknownCandidate) as refusal:
            select_candidates(["gpt-6-luna low", "nope"])

        assert "nope" in str(refusal.value)
        assert REFERENCE.name in str(refusal.value)
        assert "gpt-6-luna none" in str(refusal.value)


class TestSelectCalls:
    def test_keeps_the_calls_of_the_schema_in_corpus_order(self):
        corpus = given.a_corpus_of(["TestCaseBatch", "Judgment", "TestCaseBatch", "Judgment"])

        selected = select_calls(corpus, "TestCaseBatch")

        assert [call.call_id for call in selected] == ["call-0", "call-2"]

    def test_keeps_every_call_without_a_schema(self):
        corpus = given.a_corpus_of(["TestCaseBatch", "Judgment", "TestCaseBatch"])

        assert select_calls(corpus, None) == corpus.calls


class TestDefectCounts:
    def test_counts_each_candidate_on_its_own_observations_in_candidate_order(self):
        luna_none, luna_low = CHALLENGERS
        observations = [
            given.an_observation_of(luna_none, CallOutcome.PARSED),
            given.an_observation_of(luna_low, CallOutcome.PARSE_FAILURE),
            given.an_observation_of(luna_none, CallOutcome.ERROR),
        ]

        counts = defect_counts([luna_low, REFERENCE, luna_none], observations)

        assert [(row.candidate, row.calls) for row in counts] == [
            (luna_low.name, 1),
            (REFERENCE.name, 0),
            (luna_none.name, 2),
        ]
        assert (counts[0].parse_failures, counts[2].errors) == (1, 1)
