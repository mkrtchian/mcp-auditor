from typing import Any

from evals.cve.detection.targets import Target
from mcp_auditor.domain.models import AuditReport, MissCause, MissedModelCall, ModelCallKind
from tests.unit.cve.support import test_cve_grammar_given as grammar
from tests.unit.support.acceptance_targets import FILESYSTEM, an_acceptance_target


def a_target(flaw_id: str = FILESYSTEM, **changes: Any) -> Target:
    """A real target, since run_holdout_targets plants its kept places and fingerprints its
    fixture."""
    return an_acceptance_target(flaw_id, **{"tools_filter": None, **changes})


def a_report_missing(*causes: MissCause) -> AuditReport:
    missed = [
        MissedModelCall(tool_name="read_file", kind=ModelCallKind.JUDGMENT, cause=cause, detail="")
        for cause in causes
    ]
    return grammar.a_report().model_copy(update={"missed_model_calls": missed})
