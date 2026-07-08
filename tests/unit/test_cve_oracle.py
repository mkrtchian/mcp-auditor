import tests.unit.support.test_cve_oracle_given as given
from evals.cve_oracle import (
    CVEResult,
    CVEStatus,
    detect_in_report,
    not_run,
    out_of_scope_results,
    render_markdown,
    resolve_status,
)
from mcp_auditor.domain.models import AuditCategory

SENTINEL = given.SENTINEL


def test_detects_sentinel_in_fail_response():
    target = given.a_target()
    report = given.a_report(cases=[given.a_case_with_response(response=f"leaked {SENTINEL}")])

    detection = detect_in_report(target, report)

    assert detection.sentinel_surfaced
    assert detection.sentinel_in_fail
    assert detection.evidence is not None
    assert SENTINEL in detection.evidence
    assert detection.category == AuditCategory.INFO_LEAKAGE


def test_detects_sentinel_arriving_via_error():
    target = given.a_target()
    report = given.a_report(
        cases=[given.a_case_with_response(response=None, error=f"boom {SENTINEL}")]
    )

    detection = detect_in_report(target, report)

    assert detection.sentinel_surfaced
    assert detection.sentinel_in_fail


def test_detects_sentinel_in_dict_response():
    target = given.a_target()
    report = given.a_report(cases=[given.a_case_with_response(response={"content": SENTINEL})])

    detection = detect_in_report(target, report)

    assert detection.sentinel_surfaced
    assert detection.sentinel_in_fail


def test_detects_sentinel_in_chain_step():
    target = given.a_target()
    report = given.a_report(chains=[given.a_chain_with_step(response=f"diff {SENTINEL}")])

    detection = detect_in_report(target, report)

    assert detection.sentinel_surfaced
    assert detection.sentinel_in_fail


def test_surfaced_in_pass_is_not_a_fail():
    target = given.a_target()
    report = given.a_report(
        cases=[given.a_case_with_response(response=f"leaked {SENTINEL}", verdict=given.PASS)]
    )

    detection = detect_in_report(target, report)

    assert detection.sentinel_surfaced
    assert not detection.sentinel_in_fail


def test_no_sentinel_anywhere():
    target = given.a_target()
    report = given.a_report(cases=[given.a_case_with_response(response="nothing here")])

    detection = detect_in_report(target, report)

    assert not detection.sentinel_surfaced
    assert not detection.sentinel_in_fail


def test_resolve_detected_when_any_run_hits():
    target = given.a_target()
    detections = [
        given.a_detection(surfaced=True, in_fail=True),
        given.a_detection(surfaced=True, in_fail=False),
        given.a_detection(surfaced=False, in_fail=False),
    ]

    result = resolve_status(target, detections, budget=8)

    assert result.status == CVEStatus.DETECTED
    assert result.hits == 1
    assert result.surfaced == 2
    assert result.runs == 3
    assert result.budget == 8


def test_detection_at_k_is_any_hit():
    target = given.a_target()
    detections = [
        given.a_detection(surfaced=False, in_fail=False),
        given.a_detection(surfaced=True, in_fail=True),
        given.a_detection(surfaced=False, in_fail=False),
    ]

    result = resolve_status(target, detections, budget=8)

    assert result.status == CVEStatus.DETECTED
    assert result.hits == 1
    assert result.runs == 3


def test_resolve_reached_but_judged_pass():
    target = given.a_target(blocker="declared-scope awareness")
    detections = [
        given.a_detection(surfaced=True, in_fail=False),
        given.a_detection(surfaced=True, in_fail=False),
    ]

    result = resolve_status(target, detections, budget=8)

    assert result.status == CVEStatus.REACHED_BUT_JUDGED_PASS
    assert result.hits == 0
    assert result.surfaced == 2


def test_resolve_missed_when_blocker_none():
    target = given.a_target(blocker=None)
    detections = [given.a_detection(surfaced=False, in_fail=False)]

    result = resolve_status(target, detections, budget=8)

    assert result.status == CVEStatus.MISSED


def test_resolve_missed_awaiting_capability():
    target = given.a_target(blocker="cross-tool chains")
    detections = [given.a_detection(surfaced=False, in_fail=False)]

    result = resolve_status(target, detections, budget=8)

    assert result.status == CVEStatus.MISSED_AWAITING_CAPABILITY
    assert result.blocker == "cross-tool chains"


def test_not_run_builder():
    result = not_run(given.a_target())

    assert result.status == CVEStatus.NOT_RUN
    assert result.runs == 0


def test_out_of_scope_results():
    cves = [
        given.FakeOutOfScopeCVE(cve_id="CVE-2025-68144", severity="7.8 HIGH", reason="silent write")
    ]

    results = out_of_scope_results(cves)

    assert len(results) == 1
    assert results[0].status == CVEStatus.OUT_OF_SCOPE
    assert results[0].cve_id == "CVE-2025-68144"
    assert results[0].note == "silent write"


def test_render_markdown_table():
    results = [
        CVEResult(
            cve_id="CVE-2025-53109",
            severity="7.5 HIGH",
            note="planted symlink",
            status=CVEStatus.DETECTED,
            blocker=None,
            runs=3,
            hits=2,
            surfaced=3,
            budget=8,
        ),
        CVEResult(
            cve_id="CVE-2025-68143",
            severity="8.6 HIGH",
            note="cross-tool exploit",
            status=CVEStatus.MISSED_AWAITING_CAPABILITY,
            blocker="cross-tool chains",
            runs=3,
            hits=0,
            surfaced=0,
            budget=8,
        ),
    ]

    markdown = render_markdown(results)

    assert "CVE-2025-53109" in markdown
    assert "7.5 HIGH" in markdown
    assert "detected" in markdown
    assert "2/3" in markdown
    assert "cross-tool chains" in markdown
    assert "Detected 1/2" in markdown
