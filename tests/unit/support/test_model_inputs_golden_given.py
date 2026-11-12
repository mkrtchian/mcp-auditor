"""The golden of what reaches a model or an agent, recorded in `model_inputs_golden.json`.

It holds, on fixed inputs, the output of every prompt builder and prompt constant of
`graph/prompts.py` and `graph/chain_prompts.py`, the redaction notice and marker, the category
guidance, the judge prompt of every case of the judge fixture through the judge eval's own
judging path, every prompt `FakeLLM` receives on one small audit (plain and with a relayed
`--env` value), the JSON schema of the six model-facing schemas, the request body the OpenAI and
Anthropic adapters send for each, and the JSON schema of the four schemas the dossiers hand to
agents. A JSON value is kept as the string produced, since its key order is part of what is sent.

The file is regenerated only in a commit that changes what reaches a model or an agent, never
in a rename.
"""

import asyncio
import json
import os
from pathlib import Path
from typing import Any

import anthropic
import httpx2
import pytest
from langchain_anthropic import ChatAnthropic
from pydantic import BaseModel

import tests.unit.support.test_graph_given as graph
from evals.cve.census.classification import Classification
from evals.cve.detection.draw_record import CalibrationCard
from evals.cve.nuisance.admission import AdmittedServer, FlawRecord
from evals.judge.fixture import load_fixture
from evals.probe.corpus import SCHEMA_NAMES, schema_for
from evals.run_judge_eval import FIXTURES_PATH, judge_one_case
from mcp_auditor.adapters.llm import LLM, STRUCTURED_OUTPUTS
from mcp_auditor.domain.category_guidance import CATEGORY_GUIDANCE
from mcp_auditor.domain.models import (
    AttackChain,
    AttackContext,
    AuditCategory,
    AuditPayload,
    ChainGoal,
    ChainStep,
    EvalVerdict,
    JudgeResult,
    Judgment,
    Severity,
    TestCase,
    ToolDefinition,
    ToolReport,
)
from mcp_auditor.domain.redaction import marker
from mcp_auditor.graph import chain_prompts, prompts
from tests.fakes import FakeLLM
from tests.unit.support.test_llm_adapter_given import the_openai_request_body

GOLDEN_PATH = Path(__file__).parent / "model_inputs_golden.json"
_SECRET = "s3cr3t-value"


async def golden_entries() -> dict[str, str]:
    entries = _constants() | _single_step_prompts() | _chain_prompts()
    entries |= await _judge_eval_prompts()
    entries |= await _audit_prompts()
    entries |= _schemas()
    entries |= await _request_bodies()
    return dict(sorted(entries.items()))


def _constants() -> dict[str, str]:
    return {
        "constant/non_destructive": prompts.NON_DESTRUCTIVE_CONSTRAINT,
        "constant/judging_rules": prompts.JUDGING_RULES,
        "constant/redaction_notice": prompts.REDACTION_NOTICE,
        "redaction/marker": marker("API_TOKEN"),
        "redaction/with_notice": prompts.with_redaction_notice("a prompt"),
        **{f"category_guidance/{c.value}": text for c, text in CATEGORY_GUIDANCE.items()},
        **{
            f"judging_criteria/{c.value}": prompts.format_judging_criteria(c) for c in AuditCategory
        },
    }


def _single_step_prompts() -> dict[str, str]:
    categories = list(AuditCategory)
    return {
        "generation/no_context": prompts.build_attack_generation_prompt(_tool(), 3, categories),
        "generation/empty_context": prompts.build_attack_generation_prompt(
            _bare_tool(), 1, categories[:2], AttackContext()
        ),
        "generation/full_context": prompts.build_attack_generation_prompt(
            _tool(), 5, categories, _full_context()
        ),
        "tool_header/described": prompts.format_tool_header(_tool()),
        "tool_header/bare": prompts.format_tool_header(_bare_tool()),
        "context_section/none": prompts.build_context_section(None),
        "context_section/empty": prompts.build_context_section(AttackContext()),
        "context_section/full": prompts.build_context_section(_full_context()),
        "attack_context/full": prompts.format_attack_context(_full_context()),
        "attack_context/partial": prompts.format_attack_context(AttackContext(db_engine="sqlite")),
        "extraction/judged": prompts.build_context_extraction_prompt(
            _judged_tool_report(), AttackContext()
        ),
        "extraction/blocked_only_with_context": prompts.build_context_extraction_prompt(
            ToolReport(tool=_bare_tool(), cases=[_blocked_case()]), _full_context()
        ),
        "judge/text_response": prompts.build_judge_prompt(_tool(), _text_case()),
        "judge/dict_response": prompts.build_judge_prompt(_tool(), _dict_case()),
        "judge/error": prompts.build_judge_prompt(_bare_tool(), _error_case()),
        "judge/nothing": prompts.build_judge_prompt(_tool(), TestCase(payload=_payload())),
    }


def _chain_prompts() -> dict[str, str]:
    steps = [_chain_step("probe", response="row 1"), _chain_step("exploit", error="denied")]
    long_case = TestCase(payload=_payload(), response="x" * 250, judge_result=_judge_result())
    return {
        "chain_planning/empty": chain_prompts.build_chain_planning_prompt(
            _tool(), [], AttackContext(), 2
        ),
        "chain_planning/summary": chain_prompts.build_chain_planning_prompt(
            _bare_tool(),
            [_text_case(), _dict_case(), _error_case(), long_case, _blocked_case()],
            _full_context(),
            3,
        ),
        "step_planning/first": chain_prompts.build_step_planning_prompt(
            _tool(), _chain_goal(), [], ""
        ),
        "step_planning/history_and_hint": chain_prompts.build_step_planning_prompt(
            _tool(), _chain_goal(), steps, "try the admin row"
        ),
        "step_observation/first": chain_prompts.build_step_observation_prompt(
            _tool(), _chain_goal(), steps[:1]
        ),
        "step_observation/history": chain_prompts.build_step_observation_prompt(
            _bare_tool(), _chain_goal(), steps
        ),
        "step_observation/nothing": chain_prompts.build_step_observation_prompt(
            _tool(), _chain_goal(), [_chain_step("silent")]
        ),
        "chain_judge": chain_prompts.build_chain_judge_prompt(_tool(), _attack_chain(steps)),
    }


async def _judge_eval_prompts() -> dict[str, str]:
    cases = load_fixture(FIXTURES_PATH).cases
    llm = FakeLLM([_judgment() for _ in cases])
    for case in cases:
        await judge_one_case(llm, case)
    return {
        f"judge_eval/{case.id}": prompt for case, prompt in zip(cases, llm.prompts, strict=True)
    }


async def _audit_prompts() -> dict[str, str]:
    tool = _tool()
    server = graph.a_server_echoing(tool, f"token={_SECRET}")
    plain_llm = graph.a_fake_llm_for_single_tool_with_a_two_step_chain()
    redacting_llm = graph.a_fake_llm_for_single_tool_with_a_two_step_chain()
    await graph.invoke_graph(graph.a_graph(plain_llm, server), _initial_state())
    await graph.invoke_graph(
        graph.a_redacting_graph(redacting_llm, server, {"API_TOKEN": _SECRET}), _initial_state()
    )
    return {
        **{f"audit/plain/{i:02d}": prompt for i, prompt in enumerate(plain_llm.prompts)},
        **{f"audit/redacted/{i:02d}": prompt for i, prompt in enumerate(redacting_llm.prompts)},
    }


def _schemas() -> dict[str, str]:
    model_facing = {f"schema/{name}": _schema_of(schema_for(name)) for name in SCHEMA_NAMES}
    dossier_schemas = (Classification, CalibrationCard, FlawRecord, AdmittedServer)
    # Indented as the dossiers embed them.
    dossiers = {
        f"dossier_schema/{schema.__name__}": json.dumps(schema.model_json_schema(), indent=2)
        for schema in dossier_schemas
    }
    return model_facing | dossiers


def _schema_of(schema: type[BaseModel]) -> str:
    return json.dumps(schema.model_json_schema())


async def _request_bodies() -> dict[str, str]:
    entries: dict[str, str] = {}
    for name in SCHEMA_NAMES:
        schema = schema_for(name)
        entries[f"openai_request/{name}"] = json.dumps(await the_openai_request_body(schema))
        entries[f"anthropic_request/{name}"] = json.dumps(await _anthropic_request_body(schema))
    return entries


async def _anthropic_request_body(schema: type[BaseModel]) -> dict[str, Any]:
    # The recorded request is answered with a 400, which the adapter re-raises, and the client
    # does not retry, so one call sends exactly one request.
    bodies: list[dict[str, Any]] = []

    def record(request: httpx2.Request) -> httpx2.Response:
        bodies.append(json.loads(request.content))
        error = {"type": "invalid_request_error", "message": "recorded"}
        return httpx2.Response(400, json={"type": "error", "error": error})

    chat_model = ChatAnthropic(  # pyright: ignore[reportCallIssue]
        model="claude-haiku-5-5",  # pyright: ignore[reportCallIssue]
        api_key="dummy",
        thinking={"type": "adaptive"},
        effort="low",
        max_retries=0,
    )
    # ChatAnthropic takes no HTTP client: its cached async client is seeded with one that records.
    http_client = httpx2.AsyncClient(transport=httpx2.MockTransport(record))
    vars(chat_model)["_async_client"] = anthropic.AsyncClient(
        api_key="dummy", http_client=http_client, timeout=120
    )
    llm = LLM(chat_model, STRUCTURED_OUTPUTS["anthropic"], max_parse_attempts=3)
    with pytest.raises(anthropic.BadRequestError):
        await llm.generate_structured("prompt", schema)
    if len(bodies) != 1:
        raise AssertionError("expected one request")
    return bodies[0]


def _tool() -> ToolDefinition:
    schema = {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]}
    return ToolDefinition(name="get_user", description="Fetch a user by ID", input_schema=schema)


def _bare_tool() -> ToolDefinition:
    return ToolDefinition(name="list_rows", description=None, input_schema={})


def _payload(
    category: AuditCategory = AuditCategory.INJECTION, description: str = "union select"
) -> AuditPayload:
    return AuditPayload(category=category, description=description, arguments={"id": "1 OR 1=1"})


def _judge_result() -> JudgeResult:
    return JudgeResult(
        tool_name="get_user",
        category=AuditCategory.INJECTION,
        arguments={"id": "1 OR 1=1"},
        verdict=EvalVerdict.FAIL,
        justification="rows of every user came back",
        severity=Severity.HIGH,
    )


def _judgment() -> Judgment:
    return Judgment(verdict=EvalVerdict.PASS, justification="nothing shown", severity=Severity.LOW)


def _text_case() -> TestCase:
    return TestCase(payload=_payload(), response="alice, bob", judge_result=_judge_result())


def _dict_case() -> TestCase:
    payload = _payload(AuditCategory.INFO_LEAKAGE, "valid id")
    return TestCase(payload=payload, response={"email": "a@example.com", "role": "admin"})


def _error_case() -> TestCase:
    payload = _payload(AuditCategory.ERROR_HANDLING, "unknown id")
    return TestCase(payload=payload, error="Traceback (most recent call last): KeyError: '7'")


def _blocked_case() -> TestCase:
    payload = _payload(description="drop the table")
    return TestCase(payload=payload, blocked_reason="destructive SQL: DROP")


def _judged_tool_report() -> ToolReport:
    cases = [_text_case(), _dict_case(), _error_case(), _blocked_case()]
    return ToolReport(tool=_tool(), cases=cases)


def _full_context() -> AttackContext:
    return AttackContext(
        db_engine="sqlite",
        framework="FastMCP",
        language="Python",
        exposed_internals=["/srv/app/db.sqlite", "users table"],
        effective_payloads=["UNION SELECT"],
        observations="errors quote the query",
    )


def _chain_goal() -> ChainGoal:
    return ChainGoal(
        description="read another user's email",
        category=AuditCategory.INFO_LEAKAGE,
        first_step=_payload(AuditCategory.INFO_LEAKAGE, "probe"),
    )


def _chain_step(
    description: str, response: str | None = None, error: str | None = None
) -> ChainStep:
    observation = "" if response is None and error is None else f"after {description}"
    payload = _payload(AuditCategory.INFO_LEAKAGE, description)
    return ChainStep(payload=payload, response=response, error=error, observation=observation)


def _attack_chain(steps: list[ChainStep]) -> AttackChain:
    return AttackChain(goal=_chain_goal(), steps=steps)


def _initial_state() -> dict[str, Any]:
    return {
        "server_command": "python server.py",
        "discovered_tools": [],
        "test_budget": 1,
        "current_tool": None,
        "processed_cases": [],
        "tool_reports": [],
        "provider_usage": [],
        "audit_report": None,
        "attack_context": AttackContext(),
        "chain_budget": 1,
        "max_chain_steps": 3,
        "completed_chains": [],
    }


if __name__ == "__main__":
    # The OpenAI client refuses to start without a key. No request leaves the process.
    os.environ["OPENAI_API_KEY"] = "sk-placeholder"
    entries = asyncio.run(golden_entries())
    GOLDEN_PATH.write_text(json.dumps(entries, indent=2) + "\n")
