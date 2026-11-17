"""The relaunch of an audited server (ADR 036) on the real fixtures of the detection suite, with
no LLM: a graded run rarely meets a server that stops answering, so each case makes one stop.

Behind CVE_RELAUNCH=1, because it stands a Kubernetes control plane and waits out a tool call
timeout and a ping per case. Under the flag it skips without Docker, and skips, naming the build
command, when an image the preflight expects is absent or stale: it builds nothing.
"""

import os

import pytest

import tests.integration.support.test_cve_relaunch_given as given
import tests.integration.support.test_cve_relaunch_then as then
from mcp_auditor.domain.server_liveness import RelaunchCause


@pytest.fixture(autouse=True, scope="module")
def _prerequisites() -> None:
    if os.environ.get("CVE_RELAUNCH") != "1":
        pytest.skip(
            "the relaunch test stands a Kubernetes control plane and waits out a tool call "
            "timeout and a ping per case; set CVE_RELAUNCH=1 to run"
        )
    missing = given.missing_prerequisite()
    if missing is not None:
        pytest.skip(missing)


async def test_a_blocked_kubernetes_server_is_relaunched_with_its_nonces_still_planted():
    async with given.an_audited_target(given.KUBERNETES) as audited:
        blocked_container = given.container_id(audited.container)

        blocked = await audited.attempt(given.BLOCKING_KUBECTL_CALL)

        then.timed_out_and_left_the_ping_unanswered(blocked)
        then.runs_in_a_new_container(audited.container, blocked_container)
        assert await given.places_surfacing_in_the_exploits(audited) == set(
            audited.target.kept_places
        )


async def test_a_relaunched_server_joins_its_namespace_holder_and_reaches_its_sentinels_again():
    async with given.an_audited_target(given.FETCH) as audited:
        assert given.joins_a_namespace_holder(audited)
        benign = await given.the_benign_call(audited)
        paused_container = given.container_id(audited.container)
        given.stops_answering(audited.container)

        unanswered = await audited.attempt(benign)

        then.timed_out_and_left_the_ping_unanswered(unanswered)
        then.runs_in_a_new_container(audited.container, paused_container)
        assert await given.places_surfacing_in_the_exploits(audited) == set(
            audited.target.kept_places
        )


async def test_a_launch_that_names_its_container_is_relaunched_under_that_name():
    name = given.a_container_name()
    async with given.an_audited_target(given.FILESYSTEM, name=name) as audited:
        benign = await given.the_benign_call(audited)
        paused_container = given.container_id(name)
        given.stops_answering(name)

        unanswered = await audited.attempt(benign)

        then.timed_out_and_left_the_ping_unanswered(unanswered)
        assert audited.container == name
        then.runs_in_a_new_container(name, paused_container)
        then.is_answered(await audited.attempt(benign))


async def test_a_named_container_that_ended_without_the_auditors_removal_is_relaunched_at_once():
    name = given.a_container_name()
    async with given.an_audited_target(given.FILESYSTEM, name=name) as audited:
        benign = await given.the_benign_call(audited)
        killed_container = given.container_id(name)
        given.ends_without_the_auditors_removal(name)

        lost = await audited.attempt(benign)

        then.relaunched_for(lost, RelaunchCause.LOST_CONNECTION)
        then.runs_in_a_new_container(name, killed_container)
        then.is_answered(await audited.attempt(benign))
