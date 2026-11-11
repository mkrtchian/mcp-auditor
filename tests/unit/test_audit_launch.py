import pytest
from langchain_core.exceptions import ModelAPIError

from evals.cve_environments import TOOL_CALL_TIMEOUT, Launch
from evals.launch_audit import AuditShape, audit_launch
from evals.provider_errors import AuditFailed, ProviderErrorKind
from evals.server_health import ServerHealth
from tests.unit.support import test_audit_launch_given as given
from tests.unit.support import test_cve_grammar_given as grammar

A_LAUNCH = Launch("docker", ["run", "server"], chain_budget=3, max_chain_steps=5)
THE_LAUNCH_OWN = AuditShape(None, None, None, None)


async def test_the_graph_audits_the_launch_on_the_auditor_budget_and_returns_its_report():
    report = grammar.a_report(server_command="audited")
    graphs = given.graph_reporting([report])

    audit = await audit_launch(A_LAUNCH, given.an_auditor(graphs=graphs), THE_LAUNCH_OWN)

    [graph_input] = graphs.graph_inputs
    assert graph_input["server_command"] == "docker run server"
    assert graph_input["test_budget"] == 10
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
    graphs = given.graph_reporting([grammar.a_report()])
    connect = given.FakeConnect()

    await audit_launch(A_LAUNCH, given.an_auditor(graphs=graphs, connect=connect), shape)

    [graph_input] = graphs.graph_inputs
    assert (graph_input["chain_budget"], graph_input["max_chain_steps"]) == (
        chain_budget,
        max_chain_steps,
    )
    assert connect.timeouts == [timeout]


@pytest.mark.parametrize("tools_filter", [None, frozenset({"read_file"})])
async def test_the_graph_audits_the_shape_tools_filter(tools_filter: frozenset[str] | None):
    graphs = given.graph_reporting([grammar.a_report()])

    await audit_launch(
        A_LAUNCH, given.an_auditor(graphs=graphs), AuditShape(tools_filter, None, None, None)
    )

    assert graphs.tools_filters == [tools_filter]


async def test_each_audit_runs_under_a_breaker_of_its_own():
    graphs = given.graph_reporting([grammar.a_report(), grammar.a_report()])
    auditor = given.an_auditor(graphs=graphs)

    for _ in range(2):
        await audit_launch(A_LAUNCH, auditor, THE_LAUNCH_OWN)

    first, second = graphs.breakers
    assert first is not None and second is not None
    assert first is not second


async def test_an_audit_carries_the_exchanges_and_the_health_of_a_noisy_server():
    connect = given.FakeConnect(given.a_noisy_client(non_protocol_lines=2))
    auditor = given.an_auditor(graphs=given.graph_calling(lost_calls=1), connect=connect)

    audit = await audit_launch(A_LAUNCH, auditor, THE_LAUNCH_OWN)

    assert audit.health == ServerHealth(2, 1)
    [(name, _, response)] = audit.exchanges
    assert (name, response.content) == ("read", "Connection closed")


_SHAPES = pytest.mark.parametrize("grouped", [True, False], ids=["grouped", "bare"])


@_SHAPES
async def test_a_provider_error_leaves_the_client_bare_and_classified(grouped: bool):
    error = ModelAPIError("status 500")
    auditor = given.an_auditor(
        graphs=given.graph_raising(error), connect=given.FakeConnect(grouped=grouped)
    )

    with pytest.raises(AuditFailed) as failed:
        await audit_launch(A_LAUNCH, auditor, THE_LAUNCH_OWN)

    assert failed.value.cause is error
    assert failed.value.kind is ProviderErrorKind.TRANSIENT
