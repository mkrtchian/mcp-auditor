from evals.judge.fixture import load_fixture
from evals.run_judge_eval import FIXTURES_PATH


def test_the_committed_fixture_is_a_labeled_draw():
    fixture = load_fixture(FIXTURES_PATH)

    assert all(case.clause for case in fixture.cases)
