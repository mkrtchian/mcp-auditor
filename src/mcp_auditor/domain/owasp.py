from mcp_auditor.domain.models import AuditCategory, OwaspMapping

OWASP_BY_CATEGORY: dict[AuditCategory, OwaspMapping] = {
    AuditCategory.INJECTION: OwaspMapping(code="MCP-05", title="Command Injection & Execution"),
    AuditCategory.INFO_LEAKAGE: OwaspMapping(
        code="MCP-10", title="Context Injection & Over-Sharing"
    ),
}


def category_with_owasp_id(category: AuditCategory) -> str:
    mapping = owasp_mapping_for(category)
    return _category_qualified_by(category, mapping.code if mapping else None)


def owasp_mapping_for(category: AuditCategory) -> OwaspMapping | None:
    return OWASP_BY_CATEGORY.get(category)


def category_with_owasp_label(category: AuditCategory) -> str:
    mapping = owasp_mapping_for(category)
    return _category_qualified_by(category, mapping.label if mapping else None)


def _category_qualified_by(category: AuditCategory, owasp: str | None) -> str:
    return f"{category} / {owasp}" if owasp else str(category)
