from typing import Literal

from evals.probe_corpus import ProbeCall, ProbeCorpus, ReferenceConditions
from mcp_auditor.domain.models import EvalVerdict, Judgment, Severity


def a_judgment() -> Judgment:
    return Judgment(verdict=EvalVerdict.PASS, justification="rejected", severity=Severity.LOW)


def a_capture(main_calls: int, judge_calls: int) -> list[ProbeCall]:
    """Main and judge calls interleaved, the way an audit alternates generation and judging."""
    main: list[Literal["main", "judge"]] = ["main"]
    judge: list[Literal["main", "judge"]] = ["judge"]
    roles = main * main_calls + judge * judge_calls
    interleaved = sorted(range(len(roles)), key=lambda index: index % 3)
    return [_a_call(index, roles[position]) for index, position in enumerate(interleaved)]


def a_corpus() -> ProbeCorpus:
    return ProbeCorpus(
        captured_at="2026-09-24T10:00:00+00:00",
        commit="8457fcc",
        reference=ReferenceConditions(
            provider="google",
            model="gemini-3.1-flash-lite",
            judge_model="gemini-3.1-flash-lite",
            reasoning="minimal",
            judge_reasoning="minimal",
        ),
        budget=10,
        judge_sample_seed=7,
        judge_calls_captured=2,
        calls=a_capture(main_calls=2, judge_calls=2),
    )


def _a_call(index: int, role: Literal["main", "judge"]) -> ProbeCall:
    schema_name = "TestCaseBatch" if role == "main" else "Judgment"
    return ProbeCall(
        call_id=f"honeypot/{schema_name}/{index:03d}",
        schema_name=schema_name,
        role=role,
        source="honeypot",
        prompt=f"prompt {index}",
    )
