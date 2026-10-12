"""Reports, recorded calls and responses the cve_replay unit tests build. No Docker, no LLM:
the attachment and lost-connection reading are pure, so they are tested without a patched launch.
"""

import tests.unit.support.test_cve_grammar_given as grammar
from evals.cve_replay import RecordedCall
from mcp_auditor.domain.models import AuditReport, ToolResponse

FLAW_PATH = "/outside/flag"
OTHER_PATH = "/outside/other"


def a_case_report(path: str = FLAW_PATH) -> AuditReport:
    return grammar.a_report(cases=[grammar.a_case(response="ok", arguments={"path": path})])


def a_chain_report(first: str, second: str) -> AuditReport:
    steps = [grammar.a_step(arguments={"path": first}), grammar.a_step(arguments={"path": second})]
    return grammar.a_report(chains=[grammar.a_chain(steps)])


def a_blocked_case_report() -> AuditReport:
    return grammar.a_report(cases=[grammar.a_blocked_case({"path": FLAW_PATH})])


def calls(*paths: str) -> list[RecordedCall]:
    return [("read", {"path": path}) for path in paths]


def a_response(error_type: str | None, content: str) -> ToolResponse:
    return ToolResponse(content=content, is_error=error_type is not None, error_type=error_type)
