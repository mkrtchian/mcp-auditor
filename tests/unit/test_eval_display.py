import pytest

import tests.unit.support.test_eval_display_given as given
from evals.eval_display import print_summary


def test_the_summary_states_the_throttled_requests_and_the_concurrency(
    monkeypatch: pytest.MonkeyPatch,
):
    output = given.a_captured_console(monkeypatch)
    report = given.an_eval_report({"concurrency": 6, "throttled_requests": 4})

    print_summary(report, "output/eval_report.json")

    assert "Throttled by the model provider: 4 requests at concurrency 6" in output.getvalue()


@pytest.mark.parametrize(
    "config", [{"concurrency": 6, "throttled_requests": 0}, {"concurrency": 6}]
)
def test_the_summary_says_nothing_of_throttling_when_nothing_was_throttled(
    monkeypatch: pytest.MonkeyPatch, config: dict[str, int]
):
    output = given.a_captured_console(monkeypatch)

    print_summary(given.an_eval_report(config), "output/eval_report.json")

    assert "Throttled" not in output.getvalue()
