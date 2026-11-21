from collections.abc import Awaitable, Callable

import tests.unit.cve.support.test_cve_launch_audit_given as launch_given
from evals.cve.detection.replay import ReplayOutcome, RunToCheck
from evals.cve.grammar import PlantedTarget
from evals.cve.launch_audit import Auditor
from mcp_auditor.domain.models import AuditReport, ProviderUsage
from tests.unit.cve.support import test_cve_grammar_given as grammar
from tests.unit.detection.support.detection_audits import TARGET


def an_audit_on_a_noisy_server(*, non_protocol_lines: int, lost_calls: int) -> Auditor:
    """The graph sends one call per lost connection, each answered "Connection closed", to a
    client that read `non_protocol_lines` lines it could not parse."""
    return launch_given.an_auditor(
        graphs=launch_given.graph_calling(lost_calls),
        connect=launch_given.FakeConnect(launch_given.a_noisy_client(non_protocol_lines)),
    )


def a_report_throttled(times: int) -> AuditReport:
    usage = ProviderUsage(throttled_requests=times)
    return grammar.a_report().model_copy(update={"provider_usage": usage})


def a_run(report: AuditReport, nonces: dict[str, str] | None = None) -> RunToCheck:
    return RunToCheck(
        target=TARGET,
        run_target=PlantedTarget(TARGET.classes, TARGET.aim, nonces or {}),
        report=report,
        recorded_calls=[],
        records=(),
    )


def a_detecting_run() -> RunToCheck:
    report = grammar.a_report(
        cases=[
            grammar.a_case(
                response=f"leaked {grammar.NONCE}", arguments={"path": grammar.AIMED_PATH}
            )
        ]
    )
    return a_run(report, {grammar.PLACE: grammar.NONCE})


async def a_replay_that_must_not_run(_run: RunToCheck) -> ReplayOutcome:
    raise AssertionError("a non-detecting run must be graded without replaying")


def a_replay_returning(
    outcome: ReplayOutcome,
) -> Callable[[RunToCheck], Awaitable[ReplayOutcome]]:
    async def replay(_run: RunToCheck) -> ReplayOutcome:
        return outcome

    return replay


def a_report_billed(input_tokens: int, output_tokens: int) -> AuditReport:
    usage = ProviderUsage(input_tokens=input_tokens, output_tokens=output_tokens)
    return grammar.a_report().model_copy(update={"provider_usage": usage})
