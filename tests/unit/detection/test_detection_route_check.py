from evals.cve.detection.route_check import RouteObservations, has_route, minimal_calls
from evals.cve.places import LayoutAnchor, PlaceKind
from mcp_auditor.domain.models import ToolDefinition
from tests.unit.detection.support.fictional_places import a_layout_place


def test_the_route_procedure_calls_every_filtered_tool_once_in_tools_list_order():
    tools = [_path_tool("read_file"), _path_tool("list_directory"), _path_tool("write_file")]

    calls = minimal_calls(tools, frozenset({"read_file", "list_directory"}), "/srv/app")

    assert [name for name, _ in calls] == ["read_file", "list_directory"]


def _path_tool(name: str) -> ToolDefinition:
    return ToolDefinition(
        name=name,
        input_schema={
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    )


def test_the_route_procedure_reads_the_in_scope_git_config_for_a_filesystem_path_argument():
    calls = minimal_calls([_path_tool("read_file")], frozenset({"read_file"}), "/srv/app")

    assert dict(calls)["read_file"] == {"path": "/srv/app/.git/config"}


def test_a_required_array_argument_is_called_with_an_empty_list():
    calls = minimal_calls([_git_tool("git_add", with_files=True)], None, "/srv/app")

    assert dict(calls)["git_add"]["files"] == []


def _git_tool(name: str, *, with_files: bool = False) -> ToolDefinition:
    properties = {"repo_path": {"type": "string"}}
    required = ["repo_path"]
    if with_files:
        properties["files"] = {"type": "array"}
        required.append("files")
    return ToolDefinition(
        name=name,
        input_schema={"type": "object", "properties": properties, "required": required},
    )


def test_a_tool_whose_schema_sets_required_to_null_is_called_with_no_argument():
    tool = ToolDefinition(
        name="memory_show",
        input_schema={
            "type": "object",
            "properties": {"session_id": {"type": "string"}},
            "required": None,
        },
    )

    calls = minimal_calls([tool], None, "/srv/app")

    assert dict(calls)["memory_show"] == {}


def test_a_null_filter_exposes_every_tool():
    tools = [_path_tool("read_file"), _git_tool("git_init")]

    calls = minimal_calls(tools, None, "/srv/app")

    assert [name for name, _ in calls] == ["read_file", "git_init"]


def test_the_derivation_does_not_invent_the_bare_for_a_git_target_that_names_no_bare_path():
    bare = a_layout_place("layout", LayoutAnchor.PROJECT_BARE, PlaceKind.GIT_REMOTE_URL)

    assert has_route(bare, _git_scope_naming_no_bare()) is False


def _git_scope_naming_no_bare() -> RouteObservations:
    # A git target scoped on /srv/app whose tools name no bare path: no listing tool, nothing
    # emits the origin, so the server shows nothing that names /srv/app.git.
    return RouteObservations(
        scope="/srv/app",
        responses=("", "", ""),
        call_errored=(False, False, False),
        tools_list_succeeded=True,
    )


def test_the_dotenv_parent_is_admitted_by_the_dotenv_kind_not_by_a_generic_parent_rule():
    dotenv = a_layout_place("layout", LayoutAnchor.WORKSPACE, PlaceKind.DOTENV, relpath=".env")

    assert has_route(dotenv, _git_scope_naming_no_bare()) is True
