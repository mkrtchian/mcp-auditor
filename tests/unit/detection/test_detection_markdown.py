from datetime import date

import tests.unit.detection.support.test_detection_markdown_given as given
from evals.cve.detection.gate import TargetComparison, TargetOutcome
from evals.cve.detection.markdown import render_markdown
from evals.cve.detection.measurement import MeasurementSettings
from evals.cve.detection.oracle import not_run, out_of_scope_results
from evals.cve.grammar import FlawClass, MissKind, TargetStatus
from mcp_auditor.domain.models import ProviderUsage
from tests.unit.detection.support import detection_reports


def test_render_opens_with_the_run_conditions():
    markdown = render_markdown(detection_reports.a_detection_report([]))

    conditions = markdown.splitlines()[0]
    assert "openai" in conditions
    assert "gpt-6-luna (reasoning none)" in conditions
    assert "gpt-6-judge (reasoning default)" in conditions
    assert "3 runs" in conditions
    assert "test budget 10" in conditions
    assert detection_reports.FINGERPRINT[:12] in conditions
    assert detection_reports.FINGERPRINT[:13] not in conditions


def test_render_states_the_concurrency_on_the_conditions_line():
    markdown = render_markdown(detection_reports.a_detection_report([]))

    assert f"{detection_reports.CONCURRENCY} audits at once" in markdown.splitlines()[0]


def test_render_states_the_throttled_requests_on_a_line_after_the_tally():
    report = detection_reports.a_detection_report([]).model_copy(update={"throttled_requests": 4})

    markdown = render_markdown(report)

    throttled = (
        "Throttled by the model provider: 4 requests at concurrency "
        f"{detection_reports.CONCURRENCY}"
    )
    assert throttled in markdown.splitlines()
    assert markdown.index(throttled) > markdown.index("Statuses:")
    assert "throttled" not in markdown.splitlines()[0].lower()


def test_render_leaves_throttling_out_when_nothing_was_throttled():
    markdown = render_markdown(detection_reports.a_detection_report([]))

    assert "throttled" not in markdown.lower()


def test_render_states_the_billed_tokens_on_the_conditions_line():
    usage = ProviderUsage(input_tokens=12000, output_tokens=3400)
    report = detection_reports.a_detection_report([]).model_copy(update={"provider_usage": usage})

    conditions = render_markdown(report).splitlines()[0]

    assert "12000 input tokens, 3400 output tokens" in conditions


def test_render_header_names_the_ladder_columns():
    markdown = render_markdown(detection_reports.a_detection_report([]))

    assert (
        "| Flaw | CVSS | Class | Status | Detected | Miss kind | Aimed | FAIL without proof "
        "| Awaited capability (hypothesis) | Note |"
    ) in markdown


def test_render_counts_runs_as_fractions():
    result = detection_reports.a_target_result(
        "CVE-2025-53355",
        TargetStatus.MISSED,
        aimed_runs=2,
        fail_without_proof_runs=1,
        miss_kind=MissKind.AIMED_NO_PROOF,
    )

    markdown = render_markdown(detection_reports.a_detection_report([result]))

    assert (
        "| CVE-2025-53355 | 9.1 CRITICAL | command_execution | missed | 0/3 | aimed_no_proof "
        "| 2/3 | 1/3 | cross-tool chains | test note |"
    ) in markdown


def test_render_joins_a_union_target_classes_in_its_row():
    result = detection_reports.a_target_result(
        "CVE-2025-0002",
        TargetStatus.MISSED,
        classes=(FlawClass.COMMAND_EXECUTION, FlawClass.READ_OUTSIDE_SCOPE),
    )

    markdown = render_markdown(detection_reports.a_detection_report([result]))

    assert "| CVE-2025-0002 | 9.1 CRITICAL | command_execution, read_outside_scope |" in markdown


def test_render_shows_a_dash_for_a_target_with_no_class():
    result = detection_reports.a_target_result("CVE-2025-0002", TargetStatus.MISSED, classes=())

    markdown = render_markdown(detection_reports.a_detection_report([result]))

    assert "| CVE-2025-0002 | 9.1 CRITICAL | - | missed |" in markdown


def test_render_ends_with_the_status_tally():
    results = [
        detection_reports.a_target_result("CVE-2025-53109", TargetStatus.DETECTED, detected_runs=2),
        detection_reports.a_target_result("CVE-2025-53110", TargetStatus.DETECTED, detected_runs=1),
        detection_reports.a_target_result(
            "CVE-2025-68143", TargetStatus.MISSED, miss_kind=MissKind.NOT_AIMED
        ),
    ]

    markdown = render_markdown(detection_reports.a_detection_report(results))

    assert markdown.endswith("Statuses: 2 detected, 1 missed.")


def test_render_tallies_the_ungraded_statuses_after_the_ladder():
    out_of_scope = detection_reports.FakeOutOfScopeFlaw(
        flaw_id="CVE-2025-68144", severity="CVSS 6.3 (v4.0, CNA)", reason=""
    )
    results = [
        *out_of_scope_results([out_of_scope]),
        not_run(detection_reports.FakeTarget()),
        detection_reports.a_target_result(
            "CVE-2025-68143", TargetStatus.MISSED, miss_kind=MissKind.NOT_AIMED
        ),
        detection_reports.a_target_result("CVE-2025-53109", TargetStatus.DETECTED, detected_runs=2),
    ]

    markdown = render_markdown(detection_reports.a_detection_report(results))

    assert markdown.endswith("Statuses: 1 detected, 1 missed, 1 not_run, 1 out_of_scope.")


def test_render_lists_the_not_run_reasons_in_a_section_after_the_table():
    results = [
        not_run(detection_reports.FakeTarget(), ["keeps no place", "exploit 0 not aimed"]),
        detection_reports.a_target_result("CVE-2025-53109", TargetStatus.DETECTED, detected_runs=2),
    ]

    markdown = render_markdown(detection_reports.a_detection_report(results))

    assert "Not run, pre-run check failed:" in markdown
    assert "- CVE-2025-0001: keeps no place, exploit 0 not aimed" in markdown
    assert markdown.index("Not run, pre-run check failed:") > markdown.index("Statuses:")


def test_render_lists_the_struck_and_unchecked_credits_after_the_table():
    results = [
        detection_reports.a_target_result(
            "CVE-2025-53355",
            TargetStatus.MISSED,
            miss_kind=MissKind.NOT_AIMED,
            struck_places=[["alpha", "beta"], []],
        ),
        detection_reports.a_target_result(
            "CVE-2025-53109", TargetStatus.DETECTED, detected_runs=2, unchecked_places=[["gamma"]]
        ),
    ]

    markdown = render_markdown(detection_reports.a_detection_report(results))

    assert "Replay credits (place ids):" in markdown
    assert "- CVE-2025-53355: struck (alpha, beta)" in markdown
    assert "- CVE-2025-53109: unchecked (gamma)" in markdown
    assert markdown.index("Replay credits") > markdown.index("Statuses:")


def test_render_without_replay_credits_has_no_replay_section():
    result = detection_reports.a_target_result("CVE-X", TargetStatus.MISSED)

    markdown = render_markdown(detection_reports.a_detection_report([result]))

    assert "Replay credits" not in markdown


def test_render_appends_the_gate_outcome_and_a_row_per_target():
    report = detection_reports.a_detection_report([]).model_copy(
        update={"gate": detection_reports.a_red_gate()}
    )

    markdown = render_markdown(report)

    assert "Gate: red." in markdown
    assert "- CVE-2025-53355: regression, the miss reproduced in 4 of 4 retests" in markdown
    assert "| Target | Outcome | Baseline | Run | Retests | Detail |" in markdown
    assert "| CVE-2025-53355 | regression | - | DMJ | 4/4 | - |" in markdown
    assert "| CVE-2025-53109 | held | - | DDD | - | - |" in markdown
    assert "Targets:" not in markdown


def test_render_shows_the_baseline_runs_beside_the_run_and_the_legend():
    comparison = TargetComparison(
        flaw_id="CVE-X",
        outcome=TargetOutcome.NOT_GATED,
        candidate_runs=[TargetStatus.MISSED, TargetStatus.DETECTED, TargetStatus.MISSED],
        baseline_runs=[TargetStatus.MISSED] * 3,
    )

    markdown = render_markdown(given.a_report_gated_on(comparison))

    assert "| CVE-X | not_gated | MMM | MDM | - | - |" in markdown
    assert (
        "Runs: D detected, J reached but judged PASS, M missed. "
        "Baseline: every run its file holds, both recordings once confirmed. "
        "Retests: the miss reproduced in k of n retests."
    ) in markdown.splitlines()


def test_render_counts_the_retests_as_a_fraction():
    comparison = TargetComparison(
        flaw_id="CVE-X",
        outcome=TargetOutcome.PENDING_RETEST,
        candidate_runs=[TargetStatus.MISSED],
        retests=[True, False],
    )

    markdown = render_markdown(given.a_report_gated_on(comparison))

    assert "| CVE-X | pending_retest | - | M | 1/2 | - |" in markdown


def test_render_escapes_a_pipe_in_a_not_run_detail():
    comparison = TargetComparison(
        flaw_id="CVE-X",
        outcome=TargetOutcome.NOT_RUN,
        candidate_runs=[],
        detail="exploit 0 not aimed | read a|b",
    )

    markdown = render_markdown(given.a_report_gated_on(comparison))

    assert r"| CVE-X | not_run | - | - | - | exploit 0 not aimed \| read a\|b |" in markdown


def test_render_without_a_gate_has_no_gate_section():
    markdown = render_markdown(detection_reports.a_detection_report([]))

    assert "Gate" not in markdown


def test_render_ends_with_the_reasons_a_recording_was_refused():
    report = detection_reports.a_detection_report([]).model_copy(
        update={"recording_refused": ["CVE-2025-53355: the gated target regressed"]}
    )

    markdown = render_markdown(report)

    assert markdown.endswith(
        "Recording refused, no baseline written:\n- CVE-2025-53355: the gated target regressed"
    )


def test_render_shows_a_cost_row_per_costed_target_and_the_prices_date():
    report = detection_reports.a_detection_report([]).model_copy(
        update={
            "costs": [detection_reports.a_target_cost("CVE-2025-0001")],
            "prices_as_of": date(2026, 10, 17),
        }
    )

    markdown = render_markdown(report)

    assert "prices as of 2026-10-17" in markdown
    assert "| CVE-2025-0001 | 2000 | 300 | 900 | $0.2500 | $0.5000 | $0.1250 | $0.7500 |" in (
        markdown
    )


def test_render_shows_the_forced_settings_of_a_measurement_run():
    measurement = MeasurementSettings(chains=3, chain_steps=None, tool_call_timeout=30)
    report = detection_reports.a_detection_report([]).model_copy(
        update={"measurement": measurement}
    )

    markdown = render_markdown(report)

    assert (
        "Measurement run, forced settings: 3 chains per tool, the launch's own chain steps, "
        "tool call timeout 30 s, the target's tools filter." in markdown
    )


def test_render_of_a_measurement_run_auditing_every_tool_does_not_claim_filtered_tools():
    measurement = MeasurementSettings(every_tool=True)
    report = detection_reports.a_detection_report([]).model_copy(
        update={"measurement": measurement}
    )

    markdown = render_markdown(report)

    assert "tools filtered" not in markdown
    assert ", all tools," in markdown


def test_render_without_costs_nor_measurement_has_neither_section():
    markdown = render_markdown(detection_reports.a_detection_report([]))

    assert "Measurement run" not in markdown
    assert "Cost" not in markdown
