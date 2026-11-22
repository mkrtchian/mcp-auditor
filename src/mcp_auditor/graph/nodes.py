from dataclasses import dataclass, field
from typing import Any

from langgraph.graph import END

from mcp_auditor.domain.attack_context import merge_attack_context
from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.coverage import completion_size, find_coverage_gap
from mcp_auditor.domain.model_calls import MissedModelCall, ModelCallKind
from mcp_auditor.domain.models import (
    AttackContext,
    AuditCategory,
    AuditReport,
    BlockedPayload,
    CoverageGap,
    Judgment,
    ProviderUsage,
    TestCase,
    TestCaseBatch,
    ToolDefinition,
    ToolReport,
)
from mcp_auditor.domain.ports import LLMPort
from mcp_auditor.domain.server_liveness import UnsentPayload
from mcp_auditor.domain.tool_selection import filter_tools, order_tools_for_audit
from mcp_auditor.graph.missed_model_calls import Missed, ModelCall, call_model
from mcp_auditor.graph.prompts import (
    build_attack_generation_prompt,
    build_context_extraction_prompt,
    build_judge_prompt,
)
from mcp_auditor.graph.unsent_calls import case_not_sent, coverage_gap_of_tool


def make_discover_tools(server: AuditedServer, tools_filter: frozenset[str] | None = None):
    async def discover_tools(_state: dict[str, Any]) -> dict[str, Any]:
        tools = await server.list_tools()
        filtered = filter_tools(tools, tools_filter)
        ordered = order_tools_for_audit(filtered)
        return {"discovered_tools": ordered}

    return discover_tools


async def prepare_tool(state: dict[str, Any]) -> dict[str, Any]:
    index = len(state.get("tool_reports", []))
    current = state["discovered_tools"][index]
    return {
        "current_tool": current,
        "coverage_gap": None,
        "unsent_cases": 0,
        "unsent_chains": 0,
        "unsent_cause": None,
    }


@dataclass(frozen=True)
class GenerationRequest:
    tool: ToolDefinition
    budget: int
    categories: list[AuditCategory]
    attack_context: AttackContext

    def call_for(self, categories: list[AuditCategory], budget: int) -> ModelCall[TestCaseBatch]:
        prompt = build_attack_generation_prompt(
            tool=self.tool, budget=budget, categories=categories, attack_context=self.attack_context
        )
        return ModelCall(self.tool.name, ModelCallKind.TEST_GENERATION, prompt, TestCaseBatch)

    def gap_in(self, batch: TestCaseBatch) -> CoverageGap | None:
        return find_coverage_gap(batch, self.budget, self.categories)


@dataclass(frozen=True)
class GenerationOutcome:
    batch: TestCaseBatch
    usages: list[ProviderUsage]
    missed_model_calls: list[MissedModelCall] = field(default_factory=list[MissedModelCall])

    @property
    def missed(self) -> bool:
        return bool(self.missed_model_calls)

    def retried_as(self, retry: "GenerationOutcome") -> "GenerationOutcome":
        batch = self.batch if retry.missed else retry.batch
        return self._joined(retry, batch)

    def completed_by(self, completion: "GenerationOutcome") -> "GenerationOutcome":
        return self._joined(
            completion, TestCaseBatch(cases=[*self.batch.cases, *completion.batch.cases])
        )

    def _joined(self, later: "GenerationOutcome", batch: TestCaseBatch) -> "GenerationOutcome":
        usages = [*self.usages, *later.usages]
        return GenerationOutcome(
            batch, usages, [*self.missed_model_calls, *later.missed_model_calls]
        )


def make_generate_test_cases(llm: LLMPort):
    async def generate_test_cases(state: dict[str, Any]) -> dict[str, Any]:
        request = GenerationRequest(
            tool=state["current_tool"],
            budget=state["test_budget"],
            categories=list(AuditCategory),
            attack_context=state["attack_context"],
        )
        outcome = await _generate_covering_batch(llm, request)
        return {
            "pending_cases": [TestCase(payload=p) for p in outcome.batch.cases],
            "processed_cases": [],
            "provider_usage": outcome.usages,
            "coverage_gap": request.gap_in(outcome.batch),
            "missed_model_calls": outcome.missed_model_calls,
        }

    return generate_test_cases


async def _generate_covering_batch(llm: LLMPort, request: GenerationRequest) -> GenerationOutcome:
    full_call = request.call_for(request.categories, request.budget)
    first = await _ask_for_batch(llm, full_call)
    if first.missed or request.gap_in(first.batch) is None:
        return first
    retried = first.retried_as(await _ask_for_batch(llm, full_call))
    gap = request.gap_in(retried.batch)
    if retried.missed or gap is None or not gap.missing_categories:
        return retried
    completion = await _complete_categories(llm, request, gap.missing_categories)
    return retried.completed_by(completion)


async def _complete_categories(
    llm: LLMPort, request: GenerationRequest, missing: list[AuditCategory]
) -> GenerationOutcome:
    size = completion_size(request.budget, request.categories, missing)
    completion = await _ask_for_batch(llm, request.call_for(missing, size))
    kept = [case for case in completion.batch.cases if case.category in missing][:size]
    return GenerationOutcome(
        TestCaseBatch(cases=kept), completion.usages, completion.missed_model_calls
    )


async def _ask_for_batch(llm: LLMPort, call: ModelCall[TestCaseBatch]) -> GenerationOutcome:
    answer = await call_model(llm, call)
    if isinstance(answer, Missed):
        return GenerationOutcome(TestCaseBatch(cases=[]), [answer.usage], [answer.missed_call])
    batch, usage = answer
    return GenerationOutcome(batch, [usage])


def make_execute_tool(server: AuditedServer):
    async def execute_tool(state: dict[str, Any]) -> dict[str, Any]:
        pending = list(state["pending_cases"])
        case = pending.pop(0)
        tool = state["current_tool"]
        attempt = await server.attempt(tool, case.payload)
        outcome = attempt.outcome
        if isinstance(outcome, UnsentPayload):
            return case_not_sent(state, outcome, pending)
        if isinstance(outcome, BlockedPayload):
            blocked = case.model_copy(update={"blocked_reason": outcome.reason})
            return {"processed_cases": [blocked], "current_case": None, "pending_cases": pending}
        if outcome.is_error:
            case = case.model_copy(update={"error": outcome.content, "response": None})
        else:
            case = case.model_copy(update={"response": outcome.content})
        update: dict[str, Any] = {"current_case": case, "pending_cases": pending}
        if attempt.relaunch is not None:
            update["relaunches"] = [attempt.relaunch]
        return update

    return execute_tool


def make_judge_response(llm: LLMPort):
    async def judge_response(state: dict[str, Any]) -> dict[str, Any]:
        case = state["current_case"]
        tool = state["current_tool"]
        prompt = build_judge_prompt(tool=tool, test_case=case)
        call = ModelCall(tool.name, ModelCallKind.JUDGMENT, prompt, Judgment)
        answer = await call_model(llm, call)
        if isinstance(answer, Missed):
            return {"processed_cases": [case], "current_case": None, **answer.state_update()}
        judgment, usage = answer
        judge_result = judgment.stamped(tool.name, case.payload.category, case.payload.arguments)
        judged_case = case.model_copy(update={"judge_result": judge_result})
        return {
            "processed_cases": [judged_case],
            "current_case": None,
            **call.billed(usage),
        }

    return judge_response


async def collect_generated_cases(state: dict[str, Any]) -> dict[str, Any]:
    return {"processed_cases": state["pending_cases"], "pending_cases": []}


async def build_tool_report(state: dict[str, Any]) -> dict[str, Any]:
    tool = state["current_tool"]
    cases = state["processed_cases"]
    chains = state.get("completed_chains", [])
    report = ToolReport(
        tool=tool, cases=cases, chains=chains, coverage_gap=coverage_gap_of_tool(state)
    )
    return {"tool_reports": [report]}


def make_extract_attack_context(llm: LLMPort):
    async def extract_attack_context(state: dict[str, Any]) -> dict[str, Any]:
        tool_report = state["tool_reports"][-1]
        existing_context = state["attack_context"]
        prompt = build_context_extraction_prompt(tool_report, existing_context)
        call = ModelCall(
            tool_report.tool.name, ModelCallKind.CONTEXT_EXTRACTION, prompt, AttackContext
        )
        answer = await call_model(llm, call)
        if isinstance(answer, Missed):
            return {"attack_context": existing_context, **answer.state_update()}
        reported_context, usage = answer
        merged = merge_attack_context(existing_context, reported_context, tool_report.tool.name)
        return {"attack_context": merged, **call.billed(usage)}

    return extract_attack_context


async def generate_report(state: dict[str, Any]) -> dict[str, Any]:
    reports = state.get("tool_reports", [])
    usage = _sum_provider_usage(state.get("provider_usage", []))
    report = AuditReport(
        server_command=state["server_command"],
        tool_reports=reports,
        provider_usage=usage,
        judge_usage=_sum_provider_usage(state.get("judge_usage", [])),
        chain_usage=_sum_provider_usage(state.get("chain_usage", [])),
        missed_model_calls=state.get("missed_model_calls", []),
        relaunches=state.get("relaunches", []),
    )
    return {"audit_report": report}


def _sum_provider_usage(usages: list[ProviderUsage]) -> ProviderUsage:
    total = ProviderUsage()
    for u in usages:
        total = total.add(u)
    return total


def route_after_discovery(state: dict[str, Any]) -> str:
    if state["discovered_tools"]:
        return "prepare_tool"
    return "generate_report"


def route_after_execute(state: dict[str, Any]) -> str:
    if state["current_case"] is None:
        return route_test_cases(state)
    return "judge_response"


def route_test_cases(state: dict[str, Any]) -> str:
    if state["pending_cases"]:
        return "execute_tool"
    return END


def make_route_tools(server: AuditedServer):
    def route_tools(state: dict[str, Any]) -> str:
        if len(state["tool_reports"]) == len(state["discovered_tools"]):
            return "generate_report"
        return "report_tools_left" if server.taken_as_down else "prepare_tool"

    return route_tools
