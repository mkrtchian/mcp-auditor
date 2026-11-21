import pytest

from mcp_auditor.domain.models import ExecutionRegime
from mcp_auditor.server_execution import ServerExecution, decide_launch
from tests.fakes import FakeContainerRuntime
from tests.unit.auditor.support.launch_contexts import CONTAINER_NAME, a_context


async def test_a_confined_execution_removes_its_container_and_records_the_kill_state():
    runtime = FakeContainerRuntime(oom_killed=True)
    launch = decide_launch("npx", ["a-server"], a_context(runtime)).launch

    execution = ServerExecution(launch, runtime)
    async with execution:
        assert execution.record is None

    assert runtime.removed == [CONTAINER_NAME]
    assert execution.record is not None
    assert execution.record.oom_killed is True


async def test_a_confined_execution_removes_its_container_when_the_block_raises():
    runtime = FakeContainerRuntime()
    launch = decide_launch("npx", ["a-server"], a_context(runtime)).launch

    with pytest.raises(ConnectionError):
        async with ServerExecution(launch, runtime):
            raise ConnectionError("the server died")

    assert runtime.removed == [CONTAINER_NAME]


async def test_an_unconfined_execution_reaches_no_runtime():
    runtime = FakeContainerRuntime(untouchable=True)
    context = a_context(runtime, unconfined=True)
    launch = decide_launch("python", ["server.py"], context).launch

    execution = ServerExecution(launch, runtime)
    async with execution:
        pass

    assert execution.record is not None
    assert execution.record.regime == ExecutionRegime.UNCONFINED
    assert execution.record.oom_killed is None


async def test_ending_a_confined_server_removes_its_container_and_keeps_its_kill_state():
    runtime = FakeContainerRuntime(oom_killed_in_turn=[True, False])
    launch = decide_launch("npx", ["a-server"], a_context(runtime)).launch

    execution = ServerExecution(launch, runtime)
    async with execution:
        await execution.end_server()
        assert runtime.removed == [CONTAINER_NAME]

    assert runtime.removed == [CONTAINER_NAME, CONTAINER_NAME]
    assert execution.record is not None
    assert execution.record.oom_killed is True


@pytest.mark.parametrize(
    ("answers", "oom_killed"),
    [((None, False), False), ((False, True), True), ((None, None), None)],
)
async def test_the_kill_state_is_unknown_only_when_no_container_could_be_read(
    answers: tuple[bool | None, ...], oom_killed: bool | None
):
    runtime = FakeContainerRuntime(oom_killed_in_turn=answers)
    launch = decide_launch("npx", ["a-server"], a_context(runtime)).launch

    execution = ServerExecution(launch, runtime)
    async with execution:
        await execution.end_server()

    assert execution.record is not None
    assert execution.record.oom_killed is oom_killed


@pytest.mark.parametrize(
    ("command", "args", "unconfined"),
    [("python", ["server.py"], True), ("docker", ["run", "-i", "--name", "srv", "img"], False)],
)
async def test_ending_a_server_without_a_container_of_the_auditor_reaches_no_runtime(
    command: str, args: list[str], unconfined: bool
):
    runtime = FakeContainerRuntime(untouchable=True)
    launch = decide_launch(command, args, a_context(runtime, unconfined=unconfined)).launch

    execution = ServerExecution(launch, runtime)
    async with execution:
        await execution.end_server()

    assert execution.record is not None
    assert execution.record.oom_killed is None
