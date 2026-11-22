from mcp_auditor.domain.models import EvalVerdict, Judgment, Severity


def a_judgment(
    verdict: EvalVerdict = EvalVerdict.FAIL,
    severity: Severity = Severity.HIGH,
) -> Judgment:
    return Judgment(
        verdict=verdict,
        justification="path traversal succeeded",
        severity=severity,
    )
