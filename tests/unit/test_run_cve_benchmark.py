import json
from pathlib import Path

import pytest

from evals import run_cve_benchmark
from evals.cve_audit import RunOverrides
from evals.cve_session import CVESessionResult
from evals.cve_session_model import AuditTarget, CVEHarness, CVEOptions
from evals.eval_session import TreeState
from evals.metrics import SessionThrottles
from mcp_auditor.domain.models import AuditReport, ProviderUsage


@pytest.mark.parametrize(
    "flags",
    [
        ["--record-baseline", "--ungated"],
        ["--calibrate", "--ungated"],
        ["--calibrate", "--record-baseline"],
        ["--survey", "--calibrate"],
        ["--survey", "--record-baseline"],
        ["--survey", "--ungated"],
    ],
)
def test_incompatible_flags_are_refused_as_not_comparable(
    monkeypatch: pytest.MonkeyPatch, flags: list[str]
):
    monkeypatch.setattr("sys.argv", ["run_cve_benchmark", *flags])

    with pytest.raises(SystemExit) as exit_:
        run_cve_benchmark.main()

    assert exit_.value.code == 3


@pytest.mark.parametrize(
    "flags",
    [
        ["--chains", "3"],
        ["--chain-steps", "3"],
        ["--tool-call-timeout", "30"],
        ["--no-tools-filter"],
        ["--calibrate", "--chains", "3"],
        ["--survey", "--no-tools-filter"],
        ["--record-baseline", "--tool-call-timeout", "30"],
        ["--ungated", "--chain-steps", "3"],
        ["--ungated", "--chains", "0", "--chain-steps", "3"],
    ],
)
def test_a_measurement_flag_outside_an_ungated_run_or_steps_without_chains_are_refused(
    monkeypatch: pytest.MonkeyPatch, flags: list[str]
):
    monkeypatch.setattr("sys.argv", ["run_cve_benchmark", *flags])

    with pytest.raises(SystemExit) as exit_:
        run_cve_benchmark.main()

    assert exit_.value.code == 3


@pytest.mark.parametrize("mode", ["--calibrate", "--survey"])
def test_a_measurement_flag_on_a_mode_that_runs_no_audit_is_refused_for_that_reason(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], mode: str
):
    monkeypatch.setattr("sys.argv", ["run_cve_benchmark", mode, "--chains", "3"])

    with pytest.raises(SystemExit) as exit_:
        run_cve_benchmark.main()

    assert exit_.value.code == 3
    assert "run no audit" in "".join(capsys.readouterr())


def test_a_negative_chain_count_is_refused_by_the_parser(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    monkeypatch.setattr("sys.argv", ["run_cve_benchmark", "--ungated", "--chains", "-1"])

    with pytest.raises(SystemExit) as exit_:
        run_cve_benchmark.main()

    assert exit_.value.code == 2
    assert "--chains: expected at least 0" in capsys.readouterr().err


@pytest.mark.parametrize("unpriced", ["MCP_AUDITOR_MODEL", "MCP_AUDITOR_JUDGE_MODEL"])
def test_a_measurement_run_with_an_unpriced_model_is_refused_before_any_audit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, unpriced: str
):
    _run_under(monkeypatch, model="gpt-6-luna", judge_model="gpt-6-luna")
    monkeypatch.setenv(unpriced, "an-unpriced-model")
    sessions: list[CVEOptions] = []
    monkeypatch.setattr(run_cve_benchmark, "run_gated", _recording_session(sessions))
    report_path = tmp_path / "cve_report.json"
    monkeypatch.setattr(
        "sys.argv",
        ["run_cve_benchmark", "--ungated", "--chains", "3", "--report", str(report_path)],
    )

    with pytest.raises(SystemExit) as exit_:
        run_cve_benchmark.main()

    assert exit_.value.code == 3
    assert sessions == []
    assert not report_path.exists()


def test_an_ungated_run_with_priced_models_reports_a_cost_per_billed_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    _run_under(monkeypatch, model="gpt-6-luna", judge_model="gpt-6-luna")
    monkeypatch.setattr(run_cve_benchmark, "audit_target", _billing_audit_target_per_target)
    monkeypatch.setattr(run_cve_benchmark, "run_gated", _no_audit_session)
    report_path = tmp_path / "cve_report.json"
    monkeypatch.setattr(
        "sys.argv", ["run_cve_benchmark", "--ungated", "--report", str(report_path)]
    )

    with pytest.raises(SystemExit):
        run_cve_benchmark.main()

    report = json.loads(report_path.read_text())
    assert [cost["cve_id"] for cost in report["costs"]] == ["CVE-billed"]
    assert report["prices_as_of"] is not None
    assert report["measurement"] is None


def test_a_measurement_run_forces_its_settings_on_the_audit_and_records_them(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    _run_under(monkeypatch, model="gpt-6-luna", judge_model="gpt-6-luna")
    forced: list[object] = []

    def audit_target(
        budget: int, throttles: SessionThrottles, places: object, overrides: object = None
    ) -> AuditTarget:
        forced.append(overrides)
        return _billing_audit_target(budget, throttles, places)

    monkeypatch.setattr(run_cve_benchmark, "audit_target", audit_target)
    monkeypatch.setattr(run_cve_benchmark, "run_gated", _no_audit_session)
    report_path = tmp_path / "cve_report.json"
    flags = ["--ungated", "--chains", "3", "--no-tools-filter", "--report", str(report_path)]
    monkeypatch.setattr("sys.argv", ["run_cve_benchmark", *flags])

    with pytest.raises(SystemExit):
        run_cve_benchmark.main()

    assert forced == [RunOverrides(3, None, None, audit_every_tool=True)]
    measurement = json.loads(report_path.read_text())["measurement"]
    assert (measurement["chains"], measurement["every_tool"]) == (3, True)


def test_a_calibration_that_cannot_reach_docker_exits_as_a_crash(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    monkeypatch.setenv("PATH", str(tmp_path))  # no docker binary to find
    monkeypatch.setattr("sys.argv", ["run_cve_benchmark", "--calibrate"])

    with pytest.raises(SystemExit) as exit_:
        run_cve_benchmark.main()

    assert exit_.value.code == 4


def test_a_calibration_that_raises_exits_as_a_crash(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(run_cve_benchmark, "preflight_ok", lambda: True)

    async def boom(*_args: object, **_kwargs: object) -> bool:
        raise ValueError("a kept id with no record")

    monkeypatch.setattr(run_cve_benchmark, "calibrate_all", boom)
    monkeypatch.setattr("sys.argv", ["run_cve_benchmark", "--calibrate"])

    with pytest.raises(SystemExit) as exit_:
        run_cve_benchmark.main()

    assert exit_.value.code == 4


def test_a_survey_that_raises_exits_as_a_crash(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(run_cve_benchmark, "preflight_ok", lambda: True)

    async def boom(*_args: object, **_kwargs: object) -> None:
        raise ValueError("a kept id with no record")

    monkeypatch.setattr(run_cve_benchmark, "survey_all", boom)
    monkeypatch.setattr("sys.argv", ["run_cve_benchmark", "--survey"])

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
    monkeypatch.setattr(run_cve_benchmark, "preflight_ok", lambda: True)
    monkeypatch.setattr(run_cve_benchmark, "read_tree", lambda: TreeState("c0ffee", dirty=True))
    monkeypatch.setattr(run_cve_benchmark, "audit_target", _billing_audit_target)
    monkeypatch.setattr(run_cve_benchmark, "run_gated", _no_audit_session)

    with pytest.raises(SystemExit):
        run_cve_benchmark.main()

    report = json.loads(report_path.read_text())
    assert (report["commit"], report["dirty"]) == ("c0ffee", True)
    assert report["provider_usage"]["input_tokens"] == 500


def _run_under(monkeypatch: pytest.MonkeyPatch, model: str, judge_model: str) -> None:
    monkeypatch.setenv("MCP_AUDITOR_PROVIDER", "openai")
    monkeypatch.setenv("MCP_AUDITOR_MODEL", model)
    monkeypatch.setenv("MCP_AUDITOR_JUDGE_MODEL", judge_model)
    monkeypatch.setattr(run_cve_benchmark, "preflight_ok", lambda: True)
    monkeypatch.setattr(run_cve_benchmark, "read_tree", lambda: TreeState("c0ffee", dirty=False))


def _recording_session(sessions: list[CVEOptions]):
    async def session(options: CVEOptions, harness: CVEHarness) -> CVESessionResult:
        sessions.append(options)
        return await _no_audit_session(options, harness)

    return session


def _billing_audit_target_per_target(
    budget: int, throttles: SessionThrottles, places: object, overrides: object = None
) -> AuditTarget:
    usage = ProviderUsage(input_tokens=500, output_tokens=50)
    report = AuditReport(target="test", tool_reports=[], provider_usage=usage)
    throttles.count(report, "CVE-billed")

    async def audit(target: object) -> None:
        return None

    return audit


def _billing_audit_target(
    budget: int, throttles: SessionThrottles, places: object, overrides: object = None
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
        not_run={},
        orphans=[],
        written=[],
        recording_refused=[],
        exit_code=0,
    )
