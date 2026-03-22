from dataclasses import dataclass

from mcp_auditor.domain.models import AuditCategory


@dataclass(frozen=True)
class OwaspMapping:
    code: str
    title: str


OWASP_BY_CATEGORY: dict[AuditCategory, OwaspMapping] = {
    AuditCategory.INJECTION: OwaspMapping(code="MCP-05", title="Command Injection & Execution"),
    AuditCategory.INFO_LEAKAGE: OwaspMapping(
        code="MCP-10", title="Context Injection & Over-Sharing"
    ),
}


def owasp_mapping_for(category: AuditCategory) -> OwaspMapping | None:
    return OWASP_BY_CATEGORY.get(category)


def owasp_id_for(category: AuditCategory) -> str | None:
    mapping = OWASP_BY_CATEGORY.get(category)
    return mapping.code if mapping else None


def owasp_label_for(category: AuditCategory) -> str | None:
    mapping = OWASP_BY_CATEGORY.get(category)
    if mapping is None:
        return None
    return f"{mapping.code}: {mapping.title}"
