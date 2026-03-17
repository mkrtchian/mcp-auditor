from mcp_auditor.domain.models import AuditCategory, EvalVerdict

GroundTruth = dict[tuple[str, AuditCategory], EvalVerdict]

HONEYPOT_GROUND_TRUTH: GroundTruth = {
    ("get_user", AuditCategory.INPUT_VALIDATION): EvalVerdict.FAIL,
    ("get_user", AuditCategory.ERROR_HANDLING): EvalVerdict.FAIL,
    ("get_user", AuditCategory.INFO_LEAKAGE): EvalVerdict.FAIL,
    ("get_user", AuditCategory.INJECTION): EvalVerdict.PASS,
    ("get_user", AuditCategory.RESOURCE_ABUSE): EvalVerdict.PASS,
    ("execute_query", AuditCategory.INJECTION): EvalVerdict.FAIL,
    ("execute_query", AuditCategory.INFO_LEAKAGE): EvalVerdict.FAIL,
    ("execute_query", AuditCategory.INPUT_VALIDATION): EvalVerdict.PASS,
    ("execute_query", AuditCategory.ERROR_HANDLING): EvalVerdict.PASS,
    ("execute_query", AuditCategory.RESOURCE_ABUSE): EvalVerdict.PASS,
    ("list_items", AuditCategory.INPUT_VALIDATION): EvalVerdict.PASS,
    ("list_items", AuditCategory.ERROR_HANDLING): EvalVerdict.PASS,
    ("list_items", AuditCategory.INFO_LEAKAGE): EvalVerdict.PASS,
    ("list_items", AuditCategory.INJECTION): EvalVerdict.PASS,
    ("list_items", AuditCategory.RESOURCE_ABUSE): EvalVerdict.PASS,
}
