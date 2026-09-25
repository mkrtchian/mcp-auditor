import pytest

import tests.unit.support.test_probe_subset_given as given
from evals.probe_candidates import CHALLENGERS, REFERENCE, RETEST_CANDIDATES
from evals.probe_subset import UnknownCandidate, select_calls, select_candidates


class TestSelectCandidates:
    def test_returns_the_named_candidates_once_each_in_the_order_given(self):
        selected = select_candidates(["gpt-6-luna low", "gpt-6-luna none", "gpt-6-luna low"])

        assert selected == [RETEST_CANDIDATES[1], RETEST_CANDIDATES[0]]

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
