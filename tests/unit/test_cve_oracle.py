import tests.unit.support.test_cve_oracle_given as given
from evals.cve_grammar import CVEStatus, MechanismClass, MissClass
from evals.cve_oracle import (
    UngradedStatus,
    not_run,
    out_of_scope_results,
    render_markdown,
    result_for,
)
from mcp_auditor.domain.models import AuditCategory, ProviderUsage


def test_not_run_keeps_the_target_description():
    result = not_run(given.FakeTarget())

    assert result.status == UngradedStatus.NOT_RUN
    assert result.runs == 0
    assert result.mechanism == MechanismClass.READ_OUTSIDE_SCOPE
    assert result.awaited_capability == "declared-scope awareness"


def test_out_of_scope_results_carry_no_class():
    cves = [
        given.FakeOutOfScopeCVE(cve_id="CVE-2025-68144", severity="7.8 HIGH", reason="silent write")
    ]

    results = out_of_scope_results(cves)

    assert len(results) == 1
    assert results[0].status == UngradedStatus.OUT_OF_SCOPE
    assert results[0].cve_id == "CVE-2025-68144"
    assert results[0].note == "silent write"
    assert results[0].mechanism is None


def test_result_for_a_detected_resolution():
    grades = [given.a_detected_grade(), given.a_missed_grade(MissClass.NOT_AIMED)]

    result = result_for(given.FakeTarget(), grades, budget=10)

    assert result.status == CVEStatus.DETECTED
    assert result.miss_class is None
    assert result.mechanism == MechanismClass.READ_OUTSIDE_SCOPE
    assert result.awaited_capability == "declared-scope awareness"
    assert (result.runs, result.detected_runs, result.surfaced_runs, result.aimed_runs) == (
        2,
        1,
        1,
        1,
    )
    assert result.budget == 10
    assert result.evidence is not None and given.SENTINEL in result.evidence
    assert result.category == AuditCategory.INJECTION


def test_result_for_a_missed_resolution():
    grades = [
        given.a_missed_grade(MissClass.AIMED_BLOCKED, fail_without_proof=True),
        given.a_missed_grade(MissClass.NOT_AIMED),
        given.a_missed_grade(MissClass.NOT_AIMED),
    ]

    result = result_for(given.FakeTarget(), grades, budget=10)

    assert result.status == CVEStatus.MISSED
    assert result.miss_class == MissClass.AIMED_BLOCKED
    assert (result.runs, result.detected_runs, result.aimed_runs) == (3, 0, 1)
    assert result.fail_without_proof_runs == 1
    assert result.evidence is None


def test_render_opens_with_the_run_conditions():
    markdown = render_markdown(given.a_benchmark_report([]))

    conditions = markdown.splitlines()[0]
    assert "openai" in conditions
    assert "gpt-6-luna (reasoning none)" in conditions
    assert "gpt-6-judge (reasoning default)" in conditions
    assert "3 runs" in conditions
    assert "budget 10" in conditions
    assert given.FINGERPRINT[:12] in conditions
    assert given.FINGERPRINT[:13] not in conditions


def test_render_states_the_concurrency_on_the_conditions_line():
    markdown = render_markdown(given.a_benchmark_report([]))

    assert f"{given.CONCURRENCY} audits at once" in markdown.splitlines()[0]


def test_render_states_the_throttled_requests_on_the_conditions_line():
    report = given.a_benchmark_report([]).model_copy(update={"throttled_requests": 4})

    conditions = render_markdown(report).splitlines()[0]

    assert "4 requests throttled by the model provider" in conditions


def test_render_leaves_throttling_out_when_nothing_was_throttled():
    conditions = render_markdown(given.a_benchmark_report([])).splitlines()[0]

    assert "throttled" not in conditions


def test_the_report_json_carries_the_throttled_requests():
    report = given.a_benchmark_report([]).model_copy(update={"throttled_requests": 4})

    assert '"throttled_requests":4' in report.model_dump_json()


def test_render_states_the_billed_tokens_on_the_conditions_line():
    usage = ProviderUsage(input_tokens=12000, output_tokens=3400)
    report = given.a_benchmark_report([]).model_copy(update={"provider_usage": usage})

    conditions = render_markdown(report).splitlines()[0]

    assert "12000 input tokens, 3400 output tokens" in conditions


def test_the_report_json_carries_the_provider_usage_and_the_tree():
    usage = ProviderUsage(input_tokens=12000, output_tokens=3400)
    report = given.a_benchmark_report([]).model_copy(update={"provider_usage": usage})

    dumped = report.model_dump(mode="json")

    assert dumped["provider_usage"]["input_tokens"] == 12000
    assert (dumped["commit"], dumped["dirty"]) == (given.COMMIT, False)


def test_render_header_names_the_ladder_columns():
    markdown = render_markdown(given.a_benchmark_report([]))

    assert (
        "| CVE | CVSS | Class | Status | Detected | Miss class | Aimed | FAIL without proof "
        "| Awaited capability (hypothesis) | Note |"
    ) in markdown


def test_render_counts_runs_as_fractions():
    result = given.a_cve_result(
        "CVE-2025-53355",
        CVEStatus.MISSED,
        aimed_runs=2,
        fail_without_proof_runs=1,
        miss_class=MissClass.AIMED_NO_PROOF,
    )

    markdown = render_markdown(given.a_benchmark_report([result]))

    assert (
        "| CVE-2025-53355 | 9.1 CRITICAL | command_execution | missed | 0/3 | aimed_no_proof "
        "| 2/3 | 1/3 | cross-tool chains | test note |"
    ) in markdown


def test_render_ends_with_the_status_tally():
    results = [
        given.a_cve_result("CVE-2025-53109", CVEStatus.DETECTED, detected_runs=2),
        given.a_cve_result("CVE-2025-53110", CVEStatus.DETECTED, detected_runs=1),
        given.a_cve_result("CVE-2025-68143", CVEStatus.MISSED, miss_class=MissClass.NOT_AIMED),
    ]

    markdown = render_markdown(given.a_benchmark_report(results))

    assert markdown.endswith("Statuses: 2 detected, 1 missed.")


def test_render_tallies_the_ungraded_statuses_after_the_ladder():
    out_of_scope = given.FakeOutOfScopeCVE(cve_id="CVE-2025-68144", severity="7.8 HIGH", reason="")
    results = [
        *out_of_scope_results([out_of_scope]),
        not_run(given.FakeTarget()),
        given.a_cve_result("CVE-2025-68143", CVEStatus.MISSED, miss_class=MissClass.NOT_AIMED),
        given.a_cve_result("CVE-2025-53109", CVEStatus.DETECTED, detected_runs=2),
    ]

    markdown = render_markdown(given.a_benchmark_report(results))

    assert markdown.endswith("Statuses: 1 detected, 1 missed, 1 not_run, 1 out_of_scope.")


def test_render_appends_the_gate_verdict_and_a_line_per_target():
    report = given.a_benchmark_report([]).model_copy(update={"gate": given.a_red_gate()})

    markdown = render_markdown(report)

    assert "Gate: red." in markdown
    assert "- CVE-2025-53355: regression, the miss reproduced in 4 of 4 replays" in markdown
    assert (
        "- CVE-2025-53355: regression. Runs: detected, missed, detected_execution_only. "
        "Replays: reproduced, reproduced, reproduced, reproduced."
    ) in markdown
    assert "- CVE-2025-53109: held. Runs: detected, detected, detected." in markdown


def test_render_without_a_gate_has_no_gate_section():
    markdown = render_markdown(given.a_benchmark_report([]))

    assert "Gate" not in markdown


def test_render_ends_with_the_reasons_a_recording_was_refused():
    report = given.a_benchmark_report([]).model_copy(
        update={"recording_refused": ["CVE-2025-53355: the gated target regressed"]}
    )

    markdown = render_markdown(report)

    assert markdown.endswith(
        "Recording refused, no baseline written:\n- CVE-2025-53355: the gated target regressed"
    )
