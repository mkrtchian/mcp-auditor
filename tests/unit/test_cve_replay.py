import re

import pytest

import tests.unit.support.test_cve_replay_given as given
from evals.cve_grammar import CreditCheck, MechanismClass, PlantedTarget
from evals.cve_replay import (
    RecordedCall,
    RunToCheck,
    arguments_agree,
    lost_connection,
    replay_credit,
    replayed_units,
)
from evals.cve_report_units import units_of
from evals.cve_targets import CVE_TARGETS
from mcp_auditor.domain.models import AuditReport

AIM = re.compile(r"^/outside/")


def _agree(report: AuditReport, calls: list[RecordedCall]) -> bool:
    return arguments_agree(units_of(report), calls)


def test_a_case_attaches_its_one_call():
    assert _agree(given.a_case_report(), given.calls(given.FLAW_PATH))


def test_a_blocked_case_contributes_no_call():
    assert _agree(given.a_blocked_case_report(), [])


def test_a_chains_steps_attach_in_order():
    report = given.a_chain_report(given.FLAW_PATH, given.OTHER_PATH)

    assert _agree(report, given.calls(given.FLAW_PATH, given.OTHER_PATH))
    assert not _agree(report, given.calls(given.OTHER_PATH, given.FLAW_PATH))


def test_fewer_outputs_than_sending_steps_fill_the_first_sending_steps_in_order():
    report = given.a_blocked_case_and_chain_report(given.FLAW_PATH, given.OTHER_PATH)

    replayed = replayed_units(units_of(report), ["patched-1"])

    assert [[step.outputs for step in unit.steps] for unit in replayed] == [
        [()],
        [("patched-1",), ()],
    ]


def test_an_argument_mismatch_counts_as_a_disagreement():
    assert not _agree(given.a_case_report(), given.calls("/outside/wrong"))


async def test_an_argument_mismatch_makes_the_run_unchecked_without_launching():
    # The mismatch short-circuits before any patched launch, so CVE_TARGETS[0] is never launched.
    run = RunToCheck(
        target=CVE_TARGETS[0],
        run_target=PlantedTarget(MechanismClass.READ_OUTSIDE_SCOPE, AIM, {"planted": "nonce"}),
        report=given.a_case_report(),
        recorded_calls=given.calls("/outside/wrong"),
        records=(),
    )

    check = await replay_credit(run)

    assert check == CreditCheck(frozenset(), unchecked=True)


@pytest.mark.parametrize(
    ("error_type", "content", "lost"),
    [
        ("McpError", "Connection closed", True),
        ("ClosedResourceError", "", True),
        ("BrokenResourceError", "", True),
        ("McpError", "Invalid params", False),
        ("TimeoutError", "Tool call timed out after 2s", False),
        (None, "the flag", False),
    ],
    ids=["connection_closed", "closed_stream", "broken_stream", "other_mcp", "timeout", "ok"],
)
def test_a_lost_connection_is_read_from_the_pinned_responses(
    error_type: str | None, content: str, lost: bool
):
    response = given.a_response(error_type, content)

    assert lost_connection(response) is lost
