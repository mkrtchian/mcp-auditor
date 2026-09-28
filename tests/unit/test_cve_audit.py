from io import StringIO

import pytest
from rich.console import Console

from evals import cve_audit
from evals.cve_audit import audit_target
from evals.cve_targets import CVE_TARGETS
from evals.metrics import SessionThrottles
from mcp_auditor.domain.models import AuditReport, ProviderUsage

TARGET = CVE_TARGETS[0]


def test_a_misconfigured_model_fails_before_any_target_is_launched(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("MCP_AUDITOR_PROVIDER", "no-such-provider")

    with pytest.raises(ValueError):
        audit_target(budget=10, concurrency=1, throttles=SessionThrottles())


def test_a_throttled_audit_is_reported_with_its_count(monkeypatch: pytest.MonkeyPatch):
    output = _captured_console(monkeypatch)

    cve_audit._print_incidents(TARGET, _report_throttled(2))  # pyright: ignore[reportPrivateUsage]

    line = f"{TARGET.cve_id}: throttled 2 time(s) by the model provider (HTTP 429)"
    assert line in output.getvalue()


def test_an_audit_never_throttled_says_nothing_of_throttling(monkeypatch: pytest.MonkeyPatch):
    output = _captured_console(monkeypatch)

    cve_audit._print_incidents(TARGET, _report_throttled(0))  # pyright: ignore[reportPrivateUsage]

    assert "throttled" not in output.getvalue()


def _captured_console(monkeypatch: pytest.MonkeyPatch) -> StringIO:
    output = StringIO()
    monkeypatch.setattr(cve_audit, "console", Console(file=output, width=200))
    return output


def _report_throttled(times: int) -> AuditReport:
    return AuditReport(
        target="test", tool_reports=[], provider_usage=ProviderUsage(throttled_requests=times)
    )
