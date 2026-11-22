from mcp_auditor.domain.models import ToolDefinition

_READ_PREFIXES = (
    "get_",
    "list_",
    "read_",
    "search_",
    "find_",
    "fetch_",
    "show_",
    "describe_",
    "check_",
)


def order_tools_for_audit(tools: list[ToolDefinition]) -> list[ToolDefinition]:
    """Read-like tools first, then by parameter count ascending. Stable sort."""
    return sorted(tools, key=_audit_order_key)


def _audit_order_key(tool: ToolDefinition) -> tuple[int, int]:
    is_read = 0 if tool.name.startswith(_READ_PREFIXES) else 1
    param_count = len(tool.input_schema.get("properties", {}))
    return (is_read, param_count)


def filter_tools(
    tools: list[ToolDefinition], tools_filter: frozenset[str] | None
) -> list[ToolDefinition]:
    if tools_filter is None:
        return tools
    available_names = {t.name for t in tools}
    unknown = tools_filter - available_names
    if unknown:
        raise ValueError(f"unknown tool names: {', '.join(sorted(unknown))}")
    return [t for t in tools if t.name in tools_filter]
