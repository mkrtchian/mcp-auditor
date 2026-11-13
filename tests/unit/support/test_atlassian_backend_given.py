import http.client
import http.server
import os
import threading
import types
import urllib.parse
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any
from unittest import mock

from evals.cve.backends.atlassian import ATLASSIAN_RESPONDER_DOCKERFILE

# The whole queries mcp-atlassian builds, at 0.22.0 (patched) and 0.21.1 (vulnerable), for the
# benign calls and the fix-check exploits, with JIRA_PROJECTS_FILTER=PROJ and
# CONFLUENCE_SPACES_FILTER=TEAM.
PROJ_JQLS = (
    "project = PROJ",
    "((project = PROJ) AND project = PROJ) AND project = PROJ",
    'project = "PROJ"',
    '(project = "PROJ") AND project = PROJ',
    "(sprint = 10001) AND project = PROJ",
)
DEMO_JQLS = (
    "(issuetype = Task) AND project = DEMO",
    'project = "DEMO"',
    "sprint = 10001 AND project = DEMO",
)
TEAM_CQLS = ("space = TEAM", "((space = TEAM) AND (space = TEAM)) AND (space = TEAM)")
DEMO_CQL = "(type = page) AND (space = DEMO)"


@dataclass(frozen=True)
class Answer:
    status: int
    body: Any


def the_responder(demo_summary: str | None = None) -> types.ModuleType:
    """The responder program inlined in its Dockerfile, loaded as a module, not served."""
    module = types.ModuleType("atlassian_responder")
    source = _inlined_program(ATLASSIAN_RESPONDER_DOCKERFILE.read_text())
    environment = {} if demo_summary is None else {"DEMO_SUMMARY": demo_summary}
    with mock.patch.dict(os.environ, environment, clear=True):
        exec(compile(source, "responder.py", "exec"), module.__dict__)
    return module


def _inlined_program(dockerfile: str) -> str:
    start = dockerfile.index("<<'PY'\n") + len("<<'PY'\n")
    return dockerfile[start : dockerfile.index("\nPY\n", start)]


def a_jira_search(responder: types.ModuleType, jql: str) -> Answer:
    return _answer(responder, "GET", "/rest/api/2/search?" + urllib.parse.urlencode({"jql": jql}))


def a_confluence_search(responder: types.ModuleType, cql: str) -> Answer:
    return _answer(responder, "GET", "/rest/api/search?" + urllib.parse.urlencode({"cql": cql}))


def a_jira_issue(responder: types.ModuleType, key: str) -> Answer:
    return _answer(responder, "GET", f"/rest/api/2/issue/{key}?fields=summary")


def _answer(responder: types.ModuleType, method: str, target: str) -> Answer:
    status, body = responder.answer(method, target)
    return Answer(status, body)


@dataclass(frozen=True)
class Served:
    status: int
    headers: dict[str, str]
    body: bytes


@contextmanager
def serving(responder: types.ModuleType) -> Generator[http.server.HTTPServer]:
    server = http.server.HTTPServer(("127.0.0.1", 0), responder.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


def a_request(server: http.server.HTTPServer, method: str, target: str) -> Served:
    connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
    try:
        body = b"{}" if method in ("POST", "PUT", "PATCH") else None
        connection.request(method, target, body=body)
        response = connection.getresponse()
        return Served(
            response.status, {k.lower(): v for k, v in response.getheaders()}, response.read()
        )
    finally:
        connection.close()
