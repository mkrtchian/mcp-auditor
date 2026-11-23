from evals.probe.corpus import ProbeCall, ProbeCorpus, Role
from mcp_auditor.domain.models import EvalVerdict, Judgment, Severity
from tests.unit.evals.support.probe_corpora import a_probe_corpus


def a_judgment() -> Judgment:
    return Judgment(verdict=EvalVerdict.PASS, justification="rejected", severity=Severity.LOW)


def a_corpus() -> ProbeCorpus:
    return a_probe_corpus(a_capture(main_calls=2, judge_calls=2))


def a_capture(main_calls: int, judge_calls: int) -> list[ProbeCall]:
    """Main and judge calls interleaved, the way an audit alternates generation and judging."""
    main: list[Role] = ["main"]
    judge: list[Role] = ["judge"]
    roles = main * main_calls + judge * judge_calls
    interleaved = sorted(range(len(roles)), key=lambda index: index % 3)
    return [_a_call(index, roles[position]) for index, position in enumerate(interleaved)]


def _a_call(index: int, role: Role) -> ProbeCall:
    schema_name = "TestCaseBatch" if role == "main" else "Judgment"
    return ProbeCall(
        call_id=f"honeypot/{schema_name}/{index:03d}",
        schema_name=schema_name,
        role=role,
        source="honeypot",
        prompt=f"prompt {index}",
    )
