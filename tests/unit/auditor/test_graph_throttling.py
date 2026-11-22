import tests.unit.auditor.support.scripted_llms as llms
import tests.unit.auditor.support.test_graph_throttling_given as given
from mcp_auditor.adapters.llm_throttling import one_audit
from mcp_auditor.domain.model_calls import MissedCallCause, ModelCallKind


async def test_a_call_throttled_past_every_retry_stops_every_later_call_of_the_audit():
    chat_model = given.a_provider_throttling_twice()
    llm = llms.an_llm_over(chat_model, patience=given.a_patience_of(15.0))

    with one_audit():
        result = await given.an_audit_of_two_tools(llm)

    report = result["audit_report"]
    assert chat_model.calls == 2
    assert {missed.cause for missed in report.missed_model_calls} == {
        MissedCallCause.PROVIDER_THROTTLED
    }
    generations = [
        m.tool_name for m in report.missed_model_calls if m.kind == ModelCallKind.TEST_GENERATION
    ]
    assert generations == given.TOOL_NAMES
    assert not report.is_complete
