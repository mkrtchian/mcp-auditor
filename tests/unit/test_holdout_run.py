"""The holdout orchestrator, with the audit and the two no-LLM checks injected as fakes: the
per-target assembly, the pre-run drops, the refused-run accounting and the up-front refusals.
No Docker, no LLM."""

import dataclasses

import pytest

import tests.unit.support.test_holdout_run_given as given
from evals.cve_grammar import CVEStatus
from evals.cve_layout_check import LayoutCheck
from evals.cve_targets import LaunchMode
from evals.eval_session import Refused, TreeState
from evals.holdout_audit import DroppedRun, IncompleteRun
from evals.holdout_results import NotRunCause
from evals.holdout_run import rebuild_images, target_services
from evals.probe import call_cost
from mcp_auditor.domain.models import ProviderUsage


@pytest.fixture(autouse=True)
def _no_tracing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LANGSMITH_TRACING", raising=False)
    monkeypatch.delenv("LANGCHAIN_TRACING_V2", raising=False)


def test_target_services_dedups_images_and_patched_twins():
    first = given.a_target(images=("app",), patched_image="app-patched")
    second = given.a_target(images=("app", "sentinel"), patched_image="other-patched")

    services = target_services([first, second])

    assert services == ["app", "app-patched", "sentinel", "other-patched"]


def test_target_services_is_empty_for_no_target():
    assert target_services([]) == []


def test_a_failed_image_build_raises_with_the_tail_of_its_output(
    monkeypatch: pytest.MonkeyPatch,
):
    stdout = "\n".join(f"step {index}" for index in range(50))
    given.a_build_exiting(monkeypatch, 1, stdout, "failed to solve: no such file")

    with pytest.raises(RuntimeError) as raised:
        rebuild_images(["app", "app-patched"])

    message = str(raised.value)
    assert "app, app-patched" in message
    assert "step 49" in message
    assert "step 10" in message
    assert "step 9\n" not in message
    assert "failed to solve: no such file" in message


def test_a_successful_image_build_prints_nothing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    given.a_build_exiting(monkeypatch, 0, "built app")

    rebuild_images(["app"])

    assert capsys.readouterr() == ("", "")


async def test_a_target_is_assembled_from_its_runs():
    target = given.a_target(given.KUBERNETES)  # command_execution, NORMAL
    provider = ProviderUsage(input_tokens=1000, output_tokens=2000)
    judge = ProviderUsage(input_tokens=100, output_tokens=200)
    report = given.a_report(provider, judge)
    outcomes: list[given.Outcome] = [
        given.graded(
            CVEStatus.DETECTED, report, surfaced_places=frozenset({"etc-shadow"}), aimed=True
        ),
        given.graded(
            CVEStatus.DETECTED,
            report,
            surfaced_places=frozenset({"etc-shadow"}),
            unchecked_places=frozenset({"etc-shadow"}),
            status_if_unchecked_missed=CVEStatus.MISSED,
            aimed=True,
        ),
        given.graded(CVEStatus.MISSED, report, aimed=True, fail_without_proof=True),
    ]
    audit = given.scripted({target.cve_id: outcomes})

    result = await given.run([target], given.deps_auditing(audit))

    (assembled,) = result.targets
    assert assembled.detected_runs == 2
    assert assembled.detection_share == pytest.approx(2 / 3)
    assert assembled.detected_runs_if_unchecked_missed == 1  # the second run misses if unchecked
    assert assembled.unchecked_places == [[], ["etc-shadow"], []]
    assert assembled.aimed_runs == 3
    assert assembled.fail_without_proof_runs == 1
    assert assembled.incomplete_runs == 0
    assert assembled.tools_count == 1
    assert assembled.mechanism_label == "command_execution"
    assert assembled.run_cost == pytest.approx(3 * call_cost(provider, given.LUNA_PRICE))


async def test_a_target_records_its_backend_images_beside_its_services():
    target = given.a_target(backend_images=("apache/doris:all-in-one-4.1.3",))
    audit = given.scripted({target.cve_id: given.three_detections()})

    result = await given.run([target], given.deps_auditing(audit))

    assert result.image_ids == {
        "filesystem": "sha256:filesystem",
        "filesystem-patched": "sha256:filesystem-patched",
        "apache/doris:all-in-one-4.1.3": "sha256:apache/doris:all-in-one-4.1.3",
    }


async def test_an_incomplete_run_counts_as_not_detected_and_is_billed():
    target = given.a_target(given.KUBERNETES)
    provider = ProviderUsage(input_tokens=1000, output_tokens=2000)
    refused_report = given.a_report(provider, ProviderUsage())
    outcomes: list[given.Outcome] = [
        given.graded(CVEStatus.DETECTED, given.a_report(provider, ProviderUsage()), aimed=True),
        IncompleteRun(refused_report),
        IncompleteRun(refused_report),
    ]
    audit = given.scripted({target.cve_id: outcomes})

    result = await given.run([target], given.deps_auditing(audit))

    (assembled,) = result.targets
    assert assembled.detected_runs == 1
    assert assembled.incomplete_runs == 2
    assert result.incomplete_run_count == 2
    assert assembled.run_cost == pytest.approx(3 * call_cost(provider, given.LUNA_PRICE))


async def test_a_target_dead_on_a_version_is_not_run():
    dead, healthy = given.a_target(given.KUBERNETES), given.a_target(given.FILESYSTEM)
    audit = given.scripted({dead.cve_id: [], healthy.cve_id: given.three_detections()})
    deps = given.deps_auditing(
        audit, check={dead.cve_id: ["patched: exploit 0 still surfaces etc-shadow"]}
    )

    result = await given.run([dead, healthy], deps)

    assert [t.cve_id for t in result.targets] == [healthy.cve_id]
    (not_run,) = result.not_run
    assert not_run.cve_id == dead.cve_id
    assert "patched: exploit 0 still surfaces etc-shadow" in not_run.reason
    assert not_run.cause is NotRunCause.PRE_RUN_CHECK


async def test_a_normal_target_the_layout_breaks_is_dropped():
    broken, healthy = given.a_target(given.KUBERNETES), given.a_target(given.FILESYSTEM)
    audit = given.scripted({broken.cve_id: [], healthy.cve_id: given.three_detections()})
    deps = given.deps_auditing(
        audit, layout={broken.cve_id: LayoutCheck(gave_up=None, breaks=True, unrouted=[])}
    )

    result = await given.run([broken, healthy], deps)

    assert [t.cve_id for t in result.targets] == [healthy.cve_id]
    (not_run,) = result.not_run
    assert not_run.cve_id == broken.cve_id
    assert not_run.reason == "the layout breaks the server under the normal launch"
    assert not_run.cause is NotRunCause.PRE_RUN_CHECK


async def test_a_fallback_target_the_layout_breaks_is_kept():
    target = given.a_target(given.KUBERNETES, launch_mode=LaunchMode.FALLBACK)
    audit = given.scripted({target.cve_id: given.three_detections()})
    deps = given.deps_auditing(
        audit, layout={target.cve_id: LayoutCheck(gave_up=None, breaks=True, unrouted=[])}
    )

    result = await given.run([target], deps)

    (assembled,) = result.targets
    assert assembled.ran_in_fallback is True
    assert result.not_run == []


async def test_a_target_whose_run_fails_to_launch_is_dropped_for_the_whole_run():
    sick, healthy = given.a_target(given.KUBERNETES), given.a_target(given.FILESYSTEM)
    report = given.a_report(ProviderUsage(), ProviderUsage())
    launch_failure = DroppedRun(NotRunCause.LAUNCH_FAILURE)
    sick_outcomes: list[given.Outcome] = [
        given.graded(CVEStatus.DETECTED, report, aimed=True),
        launch_failure,
        launch_failure,
    ]
    audit = given.scripted({sick.cve_id: sick_outcomes, healthy.cve_id: given.three_detections()})

    result = await given.run([sick, healthy], given.deps_auditing(audit))

    assert [t.cve_id for t in result.targets] == [healthy.cve_id]
    (not_run,) = result.not_run
    assert not_run.cve_id == sick.cve_id
    assert not_run.reason == "a run failed to launch after retries"
    assert not_run.cause is NotRunCause.LAUNCH_FAILURE


async def test_a_target_with_any_throttled_run_is_dropped_as_throttled():
    sick, healthy = given.a_target(given.KUBERNETES), given.a_target(given.FILESYSTEM)
    report = given.a_report(ProviderUsage(), ProviderUsage())
    sick_outcomes: list[given.Outcome] = [
        DroppedRun(NotRunCause.LAUNCH_FAILURE),
        DroppedRun(NotRunCause.THROTTLED),
        given.graded(CVEStatus.DETECTED, report, aimed=True),
    ]
    audit = given.scripted({sick.cve_id: sick_outcomes, healthy.cve_id: given.three_detections()})

    result = await given.run([sick, healthy], given.deps_auditing(audit))

    (not_run,) = result.not_run
    assert not_run.cve_id == sick.cve_id
    assert not_run.reason == "throttled by the model provider past every retry"
    assert not_run.cause is NotRunCause.THROTTLED


async def test_the_run_announces_the_audits_of_the_surviving_targets_only():
    dead, healthy = given.a_target(given.KUBERNETES), given.a_target(given.FILESYSTEM)
    audit = given.scripted({dead.cve_id: [], healthy.cve_id: given.three_detections()})
    announced: list[int] = []
    deps = dataclasses.replace(
        given.deps_auditing(audit, check={dead.cve_id: ["vulnerable: no exploit surfaces"]}),
        announce_audits=announced.append,
    )

    await given.run([dead, healthy], deps, runs=3)

    assert announced == [3]


async def test_the_result_carries_the_concurrency_and_the_throttled_requests():
    target = given.a_target(given.FILESYSTEM)
    audit = given.scripted({target.cve_id: given.three_detections()})

    result = await given.run([target], given.deps_auditing(audit, throttled=7), concurrency=4)

    assert result.concurrency == 4
    assert result.throttled_requests == 7


async def test_a_drawn_target_with_a_tools_filter_refuses_before_any_check():
    target = given.a_target(given.KUBERNETES, tools_filter=frozenset({"kubectl_generic"}))

    with pytest.raises(Refused, match="tools filter"):
        await given.run([target], given.deps_reaching_nothing())


async def test_tracing_refuses_before_any_container(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("LANGSMITH_TRACING", "1")

    with pytest.raises(Refused, match="trace"):
        await given.run([given.a_target(given.KUBERNETES)], given.deps_reaching_nothing())


async def test_a_target_absent_from_the_census_refuses_before_any_dep():
    target = given.a_target(given.KUBERNETES)

    with pytest.raises(Refused, match="census"):
        await given.run([target], given.deps_reaching_nothing(), dates={})


async def test_a_dirty_tree_refuses_before_rebuild_and_audit():
    deps = dataclasses.replace(
        given.deps_reaching_nothing(), read_tree=lambda: TreeState(commit="c0ffee", dirty=True)
    )

    with pytest.raises(Refused, match="dirty"):
        await given.run([given.a_target(given.KUBERNETES)], deps)


async def test_every_target_dropped_refuses_with_the_reasons():
    dead, broken = given.a_target(given.KUBERNETES), given.a_target(given.FILESYSTEM)
    deps = given.deps_auditing(
        given.scripted({dead.cve_id: [], broken.cve_id: []}),
        check={dead.cve_id: ["patched: exploit 0 still surfaces etc-shadow"]},
        layout={broken.cve_id: LayoutCheck(gave_up=None, breaks=True, unrouted=[])},
    )

    with pytest.raises(Refused, match="no target survived") as caught:
        await given.run([dead, broken], deps)

    reasons = caught.value.reasons
    assert any("etc-shadow" in reason for reason in reasons)
    assert any("the layout breaks" in reason for reason in reasons)


async def test_a_target_with_an_unknown_kept_place_refuses_before_any_dep():
    target = given.a_target(given.KUBERNETES, kept_places=("no-such-place",))

    with pytest.raises(Refused, match="no such place"):
        await given.run([target], given.deps_reaching_nothing())
