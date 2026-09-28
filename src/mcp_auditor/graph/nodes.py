from dataclasses import dataclass, field
from typing import Any

from langgraph.graph import END  # type: ignore[import-untyped]

from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.coverage import completion_size, find_coverage_gap
from mcp_auditor.domain.models import (
    AttackContext,
    AuditCategory,
    AuditReport,
    AuditStep,
    BlockedPayload,
    CoverageGap,
    EvalResult,
    Judgment,
    ProviderUsage,
    RefusedStep,
    TestCase,
    TestCaseBatch,
    ToolDefinition,
    ToolReport,
    filter_tools,
    order_tools_for_audit,
)
from mcp_auditor.domain.ports import LLMPort
from mcp_auditor.graph.prompts import (
    build_attack_generation_prompt,
    build_context_extraction_prompt,
    build_judge_prompt,
)
from mcp_auditor.graph.refusals import ModelCall, Refused, call_model


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
    return {"current_tool": current, "coverage_gap": None}


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
        return ModelCall(self.tool.name, AuditStep.TEST_GENERATION, prompt, TestCaseBatch)

    def gap_in(self, batch: TestCaseBatch) -> CoverageGap | None:
        return find_coverage_gap(batch, self.budget, self.categories)


@dataclass(frozen=True)
class GenerationOutcome:
    batch: TestCaseBatch
    usages: list[ProviderUsage]
    refused_steps: list[RefusedStep] = field(default_factory=list[RefusedStep])

    @property
    def refused(self) -> bool:
        return bool(self.refused_steps)

    def retried_as(self, retry: "GenerationOutcome") -> "GenerationOutcome":
        batch = self.batch if retry.refused else retry.batch
        return self._joined(retry, batch)

    def completed_by(self, completion: "GenerationOutcome") -> "GenerationOutcome":
        return self._joined(
            completion, TestCaseBatch(cases=[*self.batch.cases, *completion.batch.cases])
        )

    def _joined(self, later: "GenerationOutcome", batch: TestCaseBatch) -> "GenerationOutcome":
        usages = [*self.usages, *later.usages]
        return GenerationOutcome(batch, usages, [*self.refused_steps, *later.refused_steps])


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
            "judged_cases": [],
            "provider_usage": outcome.usages,
            "coverage_gap": request.gap_in(outcome.batch),
            "refused_steps": outcome.refused_steps,
        }

    return generate_test_cases


async def _generate_covering_batch(llm: LLMPort, request: GenerationRequest) -> GenerationOutcome:
    full_call = request.call_for(request.categories, request.budget)
    first = await _ask_for_batch(llm, full_call)
    if first.refused or request.gap_in(first.batch) is None:
        return first
    retried = first.retried_as(await _ask_for_batch(llm, full_call))
    gap = request.gap_in(retried.batch)
    if retried.refused or gap is None or not gap.missing_categories:
        return retried
    completion = await _complete_categories(llm, request, gap.missing_categories)
    return retried.completed_by(completion)


async def _complete_categories(
    llm: LLMPort, request: GenerationRequest, missing: list[AuditCategory]
) -> GenerationOutcome:
    size = completion_size(request.budget, request.categories, missing)
    completion = await _ask_for_batch(llm, request.call_for(missing, size))
    kept = [case for case in completion.batch.cases if case.category in missing][:size]
    return GenerationOutcome(TestCaseBatch(cases=kept), completion.usages, completion.refused_steps)


async def _ask_for_batch(llm: LLMPort, call: ModelCall[TestCaseBatch]) -> GenerationOutcome:
    answer = await call_model(llm, call)
    if isinstance(answer, Refused):
        return GenerationOutcome(TestCaseBatch(cases=[]), [answer.usage], [answer.refused_step])
    batch, usage = answer
    return GenerationOutcome(batch, [usage])


def make_execute_tool(server: AuditedServer):
    async def execute_tool(state: dict[str, Any]) -> dict[str, Any]:
        pending = list(state["pending_cases"])
        case = pending.pop(0)
        tool = state["current_tool"]
        outcome = await server.attempt(tool, case.payload)
        if isinstance(outcome, BlockedPayload):
            blocked = case.model_copy(update={"blocked_reason": outcome.reason})
            return {"judged_cases": [blocked], "current_case": None, "pending_cases": pending}
        if outcome.is_error:
            case = case.model_copy(update={"error": outcome.content, "response": None})
        else:
            case = case.model_copy(update={"response": outcome.content})
        return {"current_case": case, "pending_cases": pending}

    return execute_tool


def make_judge_response(llm: LLMPort):
    async def judge_response(state: dict[str, Any]) -> dict[str, Any]:
        case = state["current_case"]
        tool = state["current_tool"]
        prompt = build_judge_prompt(tool=tool, test_case=case)
        answer = await call_model(llm, ModelCall(tool.name, AuditStep.JUDGMENT, prompt, Judgment))
        if isinstance(answer, Refused):
            return {"judged_cases": [case], "current_case": None, **answer.state_update()}
        judgment, usage = answer
        eval_result = EvalResult(
            tool_name=tool.name,
            category=case.payload.category,
            payload=case.payload.arguments,
            verdict=judgment.verdict,
            justification=judgment.justification,
            severity=judgment.severity,
        )
        judged_case = case.model_copy(update={"eval_result": eval_result})
        return {"judged_cases": [judged_case], "current_case": None, "provider_usage": [usage]}

    return judge_response


async def collect_generated_cases(state: dict[str, Any]) -> dict[str, Any]:
    return {"judged_cases": state["pending_cases"], "pending_cases": []}


async def build_tool_report(state: dict[str, Any]) -> dict[str, Any]:
    tool = state["current_tool"]
    cases = state["judged_cases"]
    chains = state.get("completed_chains", [])
    gap = state.get("coverage_gap")
    report = ToolReport(tool=tool, cases=cases, chains=chains, coverage_gap=gap)
    return {"tool_reports": [report]}


def make_extract_attack_context(llm: LLMPort):
    async def extract_attack_context(state: dict[str, Any]) -> dict[str, Any]:
        tool_report = state["tool_reports"][-1]
        existing_context = state["attack_context"]
        prompt = build_context_extraction_prompt(tool_report, existing_context)
        call = ModelCall(tool_report.tool.name, AuditStep.CONTEXT_EXTRACTION, prompt, AttackContext)
        answer = await call_model(llm, call)
        if isinstance(answer, Refused):
            return {"attack_context": existing_context, **answer.state_update()}
        new_context, usage = answer
        return {"attack_context": new_context, "provider_usage": [usage]}

    return extract_attack_context


async def generate_report(state: dict[str, Any]) -> dict[str, Any]:
    target = state["target"]
    reports = state.get("tool_reports", [])
    usage = _sum_provider_usage(state.get("provider_usage", []))
    report = AuditReport(
        target=target,
        tool_reports=reports,
        provider_usage=usage,
        refused_steps=state.get("refused_steps", []),
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


def route_test_cases(state: dict[str, Any]) -> str:
    if state["pending_cases"]:
        return "execute_tool"
    return END


def route_after_execute(state: dict[str, Any]) -> str:
    if state["current_case"] is None:
        return route_test_cases(state)
    return "judge_response"


def route_tools(state: dict[str, Any]) -> str:
    if len(state["tool_reports"]) < len(state["discovered_tools"]):
        return "prepare_tool"
    return "generate_report"
