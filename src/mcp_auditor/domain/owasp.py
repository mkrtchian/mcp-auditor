from dataclasses import dataclass

from mcp_auditor.domain.models import AuditCategory


@dataclass(frozen=True)
class OwaspMapping:
    code: str
    title: str

    @property
    def label(self) -> str:
        return f"{self.code}: {self.title}"


OWASP_BY_CATEGORY: dict[AuditCategory, OwaspMapping] = {
    AuditCategory.INJECTION: OwaspMapping(code="MCP-05", title="Command Injection & Execution"),
    AuditCategory.INFO_LEAKAGE: OwaspMapping(
        code="MCP-10", title="Context Injection & Over-Sharing"
    ),
}


def owasp_mapping_for(category: AuditCategory) -> OwaspMapping | None:
    return OWASP_BY_CATEGORY.get(category)


def owasp_id_for(category: AuditCategory) -> str | None:
    mapping = owasp_mapping_for(category)
    return mapping.code if mapping else None


def owasp_label_for(category: AuditCategory) -> str | None:
    mapping = owasp_mapping_for(category)
    return mapping.label if mapping else None
