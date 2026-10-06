"""A cell absent from a tool was removed by a rubric clause: see docs/labeling-log.md."""

from mcp_auditor.domain.models import AuditCategory, EvalVerdict

GroundTruth = dict[tuple[str, AuditCategory], EvalVerdict]

HONEYPOT_GROUND_TRUTH: GroundTruth = {
    ("get_user", AuditCategory.ERROR_HANDLING): EvalVerdict.FAIL,
    ("get_user", AuditCategory.INFO_LEAKAGE): EvalVerdict.FAIL,
    ("get_user", AuditCategory.INJECTION): EvalVerdict.PASS,
    ("get_user", AuditCategory.RESOURCE_ABUSE): EvalVerdict.PASS,
    ("search_products", AuditCategory.INJECTION): EvalVerdict.FAIL,
    ("search_products", AuditCategory.INFO_LEAKAGE): EvalVerdict.FAIL,
    ("search_products", AuditCategory.INPUT_VALIDATION): EvalVerdict.PASS,
    ("search_products", AuditCategory.ERROR_HANDLING): EvalVerdict.PASS,
    ("search_products", AuditCategory.RESOURCE_ABUSE): EvalVerdict.PASS,
    ("list_items", AuditCategory.INPUT_VALIDATION): EvalVerdict.PASS,
    ("list_items", AuditCategory.ERROR_HANDLING): EvalVerdict.PASS,
    ("list_items", AuditCategory.INFO_LEAKAGE): EvalVerdict.PASS,
    ("list_items", AuditCategory.INJECTION): EvalVerdict.PASS,
    ("list_items", AuditCategory.RESOURCE_ABUSE): EvalVerdict.PASS,
}

SUBTLE_GROUND_TRUTH: GroundTruth = {
    ("search_users", AuditCategory.INFO_LEAKAGE): EvalVerdict.FAIL,
    ("search_users", AuditCategory.INPUT_VALIDATION): EvalVerdict.PASS,
    ("search_users", AuditCategory.ERROR_HANDLING): EvalVerdict.PASS,
    ("search_users", AuditCategory.INJECTION): EvalVerdict.PASS,
    ("search_users", AuditCategory.RESOURCE_ABUSE): EvalVerdict.PASS,
    ("delete_record", AuditCategory.INPUT_VALIDATION): EvalVerdict.FAIL,
    ("delete_record", AuditCategory.ERROR_HANDLING): EvalVerdict.PASS,
    ("delete_record", AuditCategory.INFO_LEAKAGE): EvalVerdict.PASS,
    ("delete_record", AuditCategory.INJECTION): EvalVerdict.PASS,
    ("delete_record", AuditCategory.RESOURCE_ABUSE): EvalVerdict.PASS,
    ("get_service_status", AuditCategory.INPUT_VALIDATION): EvalVerdict.PASS,
    ("get_service_status", AuditCategory.ERROR_HANDLING): EvalVerdict.PASS,
    ("get_service_status", AuditCategory.INFO_LEAKAGE): EvalVerdict.PASS,
    ("get_service_status", AuditCategory.INJECTION): EvalVerdict.PASS,
    ("get_service_status", AuditCategory.RESOURCE_ABUSE): EvalVerdict.PASS,
}

CHAIN_HONEYPOT_GROUND_TRUTH: GroundTruth = {
    ("project_manager", AuditCategory.INFO_LEAKAGE): EvalVerdict.FAIL,
    ("project_manager", AuditCategory.ERROR_HANDLING): EvalVerdict.PASS,
    ("project_manager", AuditCategory.RESOURCE_ABUSE): EvalVerdict.PASS,
    ("user_directory", AuditCategory.INFO_LEAKAGE): EvalVerdict.FAIL,
    ("user_directory", AuditCategory.ERROR_HANDLING): EvalVerdict.PASS,
    ("user_directory", AuditCategory.INJECTION): EvalVerdict.PASS,
    ("user_directory", AuditCategory.RESOURCE_ABUSE): EvalVerdict.PASS,
}
