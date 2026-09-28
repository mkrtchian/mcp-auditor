import json
from pathlib import Path

import pytest

from evals import run_cve_benchmark
from evals.cve_session import AuditTarget, CVEHarness, CVEOptions, CVESessionResult
from evals.eval_session import TreeState
from evals.metrics import SessionThrottles
from mcp_auditor.domain.models import AuditReport, ProviderUsage


@pytest.mark.parametrize(
    "flags",
    [
        ["--record-baseline", "--ungated"],
        ["--calibrate", "--ungated"],
        ["--calibrate", "--record-baseline"],
    ],
)
def test_incompatible_flags_are_refused_as_not_comparable(
    monkeypatch: pytest.MonkeyPatch, flags: list[str]
):
    monkeypatch.setattr("sys.argv", ["run_cve_benchmark", *flags])

    with pytest.raises(SystemExit) as exit_:
        run_cve_benchmark.main()

    assert exit_.value.code == 3


def test_a_calibration_that_cannot_reach_docker_exits_as_a_crash(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    monkeypatch.setenv("PATH", str(tmp_path))  # no docker binary to find
    monkeypatch.setattr("sys.argv", ["run_cve_benchmark", "--calibrate"])

    with pytest.raises(SystemExit) as exit_:
        run_cve_benchmark.main()

    assert exit_.value.code == 4


def test_a_concurrency_below_one_is_refused_by_the_parser(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    monkeypatch.setattr("sys.argv", ["run_cve_benchmark", "--concurrency", "0"])

    with pytest.raises(SystemExit) as exit_:
        run_cve_benchmark.main()

    assert exit_.value.code == 2
    assert "--concurrency: expected at least 1" in capsys.readouterr().err


def test_a_graded_run_reports_the_tree_it_ran_on_and_the_tokens_billed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    report_path = tmp_path / "cve_report.json"
    monkeypatch.setattr(
        "sys.argv", ["run_cve_benchmark", "--ungated", "--report", str(report_path)]
    )
    monkeypatch.setattr(run_cve_benchmark, "_preflight_ok", lambda: True)
    monkeypatch.setattr(run_cve_benchmark, "read_tree", lambda: TreeState("c0ffee", dirty=True))
    monkeypatch.setattr(run_cve_benchmark, "audit_target", _billing_audit_target)
    monkeypatch.setattr(run_cve_benchmark, "run_gated", _no_audit_session)

    with pytest.raises(SystemExit):
        run_cve_benchmark.main()

    report = json.loads(report_path.read_text())
    assert (report["commit"], report["dirty"]) == ("c0ffee", True)
    assert report["provider_usage"]["input_tokens"] == 500


def _billing_audit_target(
    budget: int, concurrency: int, throttles: SessionThrottles
) -> AuditTarget:
    usage = ProviderUsage(input_tokens=500, output_tokens=50)
    throttles.count(AuditReport(target="test", tool_reports=[], provider_usage=usage))

    async def audit(target: object) -> None:
        return None

    return audit


async def _no_audit_session(options: CVEOptions, harness: CVEHarness) -> CVESessionResult:
    return CVESessionResult(
        grades={target.cve_id: [] for target in options.targets},
        audits=[],
        gate=None,
        orphans=[],
        written=[],
        recording_refused=[],
        exit_code=0,
    )
