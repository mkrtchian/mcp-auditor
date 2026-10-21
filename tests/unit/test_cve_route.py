import json

import tests.unit.support.test_cve_route_golden_given as given
from evals.cve_places import Coordinates, LayoutAnchor, Place, PlantKind
from evals.cve_route import RouteObservations, minimal_calls, route_admits
from mcp_auditor.domain.models import ToolDefinition


def test_route_admits_a_layout_place_whose_anchor_the_server_reveals():
    entries = given.golden_entries()

    assert entries["bare_url_revealed_by_origin_record"] is True
    assert entries["workspace_dotenv_revealed_as_scope_parent"] is True


def test_route_refuses_a_layout_place_the_server_reveals_no_route_to():
    entries = given.golden_entries()

    assert entries["bare_url_refused_without_scope_or_disclosure"] is False
    assert entries["workspace_dotenv_refused_without_scope"] is False


def test_a_catalogue_place_is_on_the_route_by_construction():
    assert given.golden_entries()["catalogue_place_is_on_the_route"] is True


def test_route_admits_match_the_golden_master():
    assert given.golden_entries() == json.loads(given.GOLDEN_PATH.read_text())


def _path_tool(name: str) -> ToolDefinition:
    return ToolDefinition(
        name=name,
        input_schema={
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    )


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


def test_the_route_procedure_calls_every_filtered_tool_once_in_tools_list_order():
    tools = [_path_tool("read_file"), _path_tool("list_directory"), _path_tool("write_file")]

    calls = minimal_calls(tools, frozenset({"read_file", "list_directory"}), "/srv/app")

    assert [name for name, _ in calls] == ["read_file", "list_directory"]


def test_the_route_procedure_reads_the_in_scope_git_config_for_a_filesystem_path_argument():
    calls = minimal_calls([_path_tool("read_file")], frozenset({"read_file"}), "/srv/app")

    assert dict(calls)["read_file"] == {"path": "/srv/app/.git/config"}


def test_a_required_array_argument_is_called_with_an_empty_list():
    calls = minimal_calls([_git_tool("git_add", with_files=True)], None, "/srv/app")

    assert dict(calls)["git_add"]["files"] == []


def test_a_null_filter_exposes_every_tool():
    tools = [_path_tool("read_file"), _git_tool("git_init")]

    calls = minimal_calls(tools, None, "/srv/app")

    assert [name for name, _ in calls] == ["read_file", "git_init"]


def _layout_place(anchor: LayoutAnchor, relpath: str, kind: PlantKind) -> Place:
    return Place(
        id="layout",
        family="deployment layout",
        reachable_by=frozenset({"arbitrary_read"}),
        kind=kind,
        coordinates=Coordinates(kind, anchor=anchor, relpath=relpath),
    )


def _git_scope_naming_no_bare() -> RouteObservations:
    # A git target scoped on /srv/app whose tools name no bare path: no listing tool, nothing
    # emits the origin, so the server shows nothing that names /srv/app.git.
    return RouteObservations(
        launch_command=("run", "--rm", "image", "--repository", "/srv/app"),
        scope="/srv/app",
        tool_names=("git_init", "git_add", "git_diff_staged"),
        responses=("", "", ""),
        call_errored=(False, False, False),
        tools_list_succeeded=True,
    )


def test_the_derivation_does_not_invent_the_bare_for_a_git_target_that_names_no_bare_path():
    bare = _layout_place(LayoutAnchor.PROJECT_BARE, "config", PlantKind.GIT_REMOTE_URL)

    assert route_admits(bare, _git_scope_naming_no_bare()) is False


def test_the_dotenv_parent_is_admitted_by_the_dotenv_kind_not_by_a_generic_parent_rule():
    dotenv = _layout_place(LayoutAnchor.WORKSPACE, ".env", PlantKind.DOTENV)

    assert route_admits(dotenv, _git_scope_naming_no_bare()) is True
