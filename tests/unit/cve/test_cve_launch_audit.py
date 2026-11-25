import re

import pytest
from langchain_core.exceptions import ModelAPIError

import tests.unit.support.grammar_inputs as grammar
import tests.unit.support.launch_audit_fakes as launch_audit_fakes
from evals.cve.environments import TOOL_CALL_TIMEOUT, Launch
from evals.cve.launch_audit import (
    AuditShape,
    ServerTakenAsDown,
    UndecidableLaunch,
    audit_launch,
)
from evals.cve.server_health import ServerHealth
from evals.model_provider_errors import AuditFailed, ProviderErrorKind

A_LAUNCH = Launch("docker", ["run", "server"], chain_budget=3, max_chain_steps=5)
THE_LAUNCH_OWN = AuditShape(None, None, None, None)


async def test_the_graph_audits_the_launch_on_the_auditor_budget_and_returns_its_report():
    report = grammar.a_report(server_command="audited")
    graphs = launch_audit_fakes.graph_reporting([report])

    audit = await audit_launch(
        A_LAUNCH, launch_audit_fakes.an_auditor(graphs=graphs), THE_LAUNCH_OWN
    )

    [graph_input] = graphs.graph_inputs
    assert graph_input["test_budget"] == launch_audit_fakes.TEST_BUDGET
    assert audit.report is report


async def test_the_audit_connects_to_the_launch_named_under_the_suite_label():
    connect = launch_audit_fakes.FakeConnect()

    await audit_launch(A_LAUNCH, launch_audit_fakes.an_auditor(connect=connect), THE_LAUNCH_OWN)

    [launch] = connect.launches
    assert launch.args[0] == "run" and launch.args[1] == "--name"
    assert re.fullmatch(r"mcp-auditor-cve-audit-[0-9a-f]{12}", launch.args[2])
    assert launch.args[3:] == A_LAUNCH.args[1:]


async def test_two_audits_of_one_launch_name_their_containers_apart():
    connect = launch_audit_fakes.FakeConnect()
    auditor = launch_audit_fakes.an_auditor(
        graphs=launch_audit_fakes.graph_reporting([grammar.a_report(), grammar.a_report()]),
        connect=connect,
    )

    for _ in range(2):
        await audit_launch(A_LAUNCH, auditor, THE_LAUNCH_OWN)

    first, second = (launch.args[2] for launch in connect.launches)
    assert first != second


@pytest.mark.parametrize("spelling", [["--name", "doris-server"], ["--name=doris-server"]])
async def test_a_launch_that_names_its_container_keeps_its_name(spelling: list[str]):
    launch = Launch("docker", ["run", "-i", *spelling, "image"])
    connect = launch_audit_fakes.FakeConnect()

    await audit_launch(launch, launch_audit_fakes.an_auditor(connect=connect), THE_LAUNCH_OWN)

    assert connect.launches == [launch]


@pytest.mark.parametrize(
    "args",
    [["run", "--an-unknown-option", "value", "image"], ["image"]],
    ids=["an unknown option before the image", "not a docker run"],
)
async def test_a_launch_whose_name_cannot_be_read_is_refused_before_any_connection(
    args: list[str],
):
    launch = Launch("docker", args)
    connect = launch_audit_fakes.FakeConnect()

    with pytest.raises(UndecidableLaunch):
        await audit_launch(launch, launch_audit_fakes.an_auditor(connect=connect), THE_LAUNCH_OWN)

    assert connect.launches == []


async def test_the_graph_reads_the_server_command_without_the_added_name():
    graphs = launch_audit_fakes.graph_reporting([grammar.a_report()])

    await audit_launch(A_LAUNCH, launch_audit_fakes.an_auditor(graphs=graphs), THE_LAUNCH_OWN)

    [graph_input] = graphs.graph_inputs
    assert graph_input["server_command"] == "docker run server"


async def test_an_audit_carries_the_exchanges_after_which_the_server_was_relaunched():
    connect = launch_audit_fakes.FakeConnect(launch_audit_fakes.a_noisy_client())
    auditor = launch_audit_fakes.an_auditor(
        graphs=launch_audit_fakes.graph_calling(1), connect=connect
    )

    audit = await audit_launch(A_LAUNCH, auditor, THE_LAUNCH_OWN)

    assert audit.relaunched_after == [1]


async def test_a_relaunch_that_failed_takes_the_server_as_down():
    graphs = launch_audit_fakes.graph_reporting(
        [launch_audit_fakes.a_report_with_relaunches(True, False)]
    )

    with pytest.raises(ServerTakenAsDown):
        await audit_launch(A_LAUNCH, launch_audit_fakes.an_auditor(graphs=graphs), THE_LAUNCH_OWN)


async def test_a_relaunch_that_failed_after_the_last_call_takes_the_server_as_down():
    connect = launch_audit_fakes.FakeConnect(launch_audit_fakes.a_client_whose_relaunch_fails())
    auditor = launch_audit_fakes.an_auditor(
        graphs=launch_audit_fakes.graph_calling(1), connect=connect
    )

    with pytest.raises(ServerTakenAsDown):
        await audit_launch(A_LAUNCH, auditor, THE_LAUNCH_OWN)


async def test_an_audit_whose_relaunches_all_succeeded_stands():
    report = launch_audit_fakes.a_report_with_relaunches(True, True)
    auditor = launch_audit_fakes.an_auditor(graphs=launch_audit_fakes.graph_reporting([report]))

    audit = await audit_launch(A_LAUNCH, auditor, THE_LAUNCH_OWN)

    assert audit.report is report


@pytest.mark.parametrize(
    ("shape", "chain_budget", "max_chain_steps", "timeout"),
    [
        (THE_LAUNCH_OWN, 3, 5, TOOL_CALL_TIMEOUT),
        (AuditShape(None, 7, 9, 11), 7, 9, 11),
        (AuditShape(None, None, 9, None), 3, 9, TOOL_CALL_TIMEOUT),
        (AuditShape(None, 7, None, None), 7, 5, TOOL_CALL_TIMEOUT),
    ],
)
async def test_a_forced_setting_wins_and_an_unset_one_keeps_the_launch_own(
    shape: AuditShape, chain_budget: int, max_chain_steps: int, timeout: int
):
    graphs = launch_audit_fakes.graph_reporting([grammar.a_report()])
    connect = launch_audit_fakes.FakeConnect()

    await audit_launch(
        A_LAUNCH, launch_audit_fakes.an_auditor(graphs=graphs, connect=connect), shape
    )

    [graph_input] = graphs.graph_inputs
    assert (graph_input["chain_budget"], graph_input["max_chain_steps"]) == (
        chain_budget,
        max_chain_steps,
    )
    assert connect.timeouts == [timeout]


@pytest.mark.parametrize("tools_filter", [None, frozenset({"read_file"})])
async def test_the_graph_audits_the_shape_tools_filter(tools_filter: frozenset[str] | None):
    graphs = launch_audit_fakes.graph_reporting([grammar.a_report()])

    await audit_launch(
        A_LAUNCH,
        launch_audit_fakes.an_auditor(graphs=graphs),
        AuditShape(tools_filter, None, None, None),
    )

    assert graphs.tools_filters == [tools_filter]


async def test_each_audit_runs_under_a_breaker_of_its_own():
    graphs = launch_audit_fakes.graph_reporting([grammar.a_report(), grammar.a_report()])
    auditor = launch_audit_fakes.an_auditor(graphs=graphs)

    for _ in range(2):
        await audit_launch(A_LAUNCH, auditor, THE_LAUNCH_OWN)

    first, second = graphs.breakers
    assert first is not None and second is not None
    assert first is not second


async def test_an_audit_carries_the_exchanges_and_the_health_of_a_noisy_server():
    connect = launch_audit_fakes.FakeConnect(
        launch_audit_fakes.a_noisy_client(non_protocol_lines=2)
    )
    auditor = launch_audit_fakes.an_auditor(
        graphs=launch_audit_fakes.graph_calling(1), connect=connect
    )

    audit = await audit_launch(A_LAUNCH, auditor, THE_LAUNCH_OWN)

    assert audit.health == ServerHealth(2, 1, relaunches=1)
    [(name, _, response)] = audit.exchanges
    assert (name, response.content) == ("read", "Connection closed")


_SHAPES = pytest.mark.parametrize("grouped", [True, False], ids=["grouped", "bare"])


@_SHAPES
async def test_a_provider_error_leaves_the_client_bare_and_classified(grouped: bool):
    error = ModelAPIError("status 500")
    auditor = launch_audit_fakes.an_auditor(
        graphs=launch_audit_fakes.graph_raising(error),
        connect=launch_audit_fakes.FakeConnect(grouped=grouped),
    )

    with pytest.raises(AuditFailed) as failed:
        await audit_launch(A_LAUNCH, auditor, THE_LAUNCH_OWN)

    assert failed.value.cause is error
    assert failed.value.kind is ProviderErrorKind.TRANSIENT
