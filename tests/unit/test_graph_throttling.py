import pytest

import tests.unit.support.test_graph_throttling_given as given
from mcp_auditor.adapters.llm_throttling import one_audit
from mcp_auditor.domain.models import AuditStep, MissCause


@pytest.mark.asyncio
async def test_a_call_throttled_past_every_retry_stops_every_later_call_of_the_audit():
    chat_model = given.a_provider_throttling_the_first_generation_past_every_retry()

    with one_audit():
        result = await given.an_audit_of_two_tools(given.an_llm_over(chat_model))

    report = result["audit_report"]
    assert chat_model.calls == 2
    assert {missed.cause for missed in report.missed_steps} == {MissCause.PROVIDER_THROTTLED}
    generations = [m.tool_name for m in report.missed_steps if m.step == AuditStep.TEST_GENERATION]
    assert generations == given.TOOL_NAMES
    assert not report.is_complete
