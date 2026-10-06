"""Honeypot MCP server for integration tests and evals.

Every behavior below, including the apparent bugs, is deliberate: `evals/ground_truth.py`
asserts the expected verdict on the (tool, category) pairs it keeps, and
`docs/labeling-log.md` records the ones it dropped. Do not fix the planted flaws, a "cleanup"
here silently invalidates the eval suite. On invalid arguments the server returns a generic
error by design, see `docs/labeling-log.md`.

`search_products` (formerly `execute_query`) is a templated catalog search over an in-memory
SQLite database: its two planted flaws are the query pasted into the statement (injection) and
a configuration path on every response (info_leakage). Every other branch of it is a PASS
control, see `docs/labeling-log.md`, entry of 2026-10-06.
"""

import json
import sqlite3
from collections.abc import Callable, Sequence
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ContentBlock
from pydantic import Strict, ValidationError


class GenericArgumentErrors(FastMCP):
    # Instrument repair (docs/labeling-log.md): the library's validation message names an
    # internal model and the pydantic version, a flaw no label planted.
    async def call_tool(
        self, name: str, arguments: dict[str, Any]
    ) -> Sequence[ContentBlock] | dict[str, Any]:
        try:
            return await super().call_tool(name, arguments)
        except ToolError as error:
            if isinstance(error.__cause__, ValidationError):
                raise ToolError(f"Error executing tool {name}: Invalid arguments") from None
            raise


app = GenericArgumentErrors("honeypot")

USERS = {42: "Alice", 1: "Bob"}
VALID_CATEGORIES = ["books", "movies", "music"]
CATALOG_SCHEMA = """
CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL, listed INTEGER);
INSERT INTO products VALUES
    (1, 'Notebook', 4.5, 1), (2, 'Desk lamp', 19.0, 1), (3, 'Backpack', 35.0, 1),
    (4, 'Unreleased headset', 149.0, 0), (5, 'Prototype drone', 890.0, 0);
"""
CONFIG_PATH = "[db: /opt/mcp-server/config/database.yml]"
READ_ACTIONS = {
    sqlite3.SQLITE_SELECT,
    sqlite3.SQLITE_READ,
    sqlite3.SQLITE_FUNCTION,
    sqlite3.SQLITE_RECURSIVE,
}
MAX_ROWS = 20
MAX_COLUMNS = 8
MAX_LENGTH = 10_000
MAX_RESPONSE = 2_000
PROGRESS_INTERVAL = 1_000
MAX_PROGRESS_CALLS = 2_000


@app.tool()
def get_user(user_id: int) -> str:
    """Look up a user by their numeric ID."""
    # Planted info_leakage: the error message discloses an internal filesystem path.
    if user_id < 0:
        raise ValueError("user_id must be positive — see /opt/mcp-server/internal/users.db")
    # Planted error_handling: unknown ids raise a raw KeyError. The creation plan filed a missing
    # type check under input_validation, which the MCP library performs before this code runs,
    # so that cell left the ground truth (labeling log, R3).
    name = USERS[user_id]
    return f"User: {name} (id={user_id})"


@app.tool()
def search_products(query: str) -> str:
    """Search the product catalog: returns the listed products whose name contains the query."""
    # Deliberate PASS control: an empty or blank query is refused.
    if not query.strip():
        raise ValueError("query must not be empty")
    # Planted injection: the query is pasted into the statement, so injected syntax changes
    # the result (unlisted rows, or a value the caller chose, come back).
    statement = f"SELECT id, name, price FROM products WHERE listed = 1 AND name LIKE '%{query}%'"
    rows = _run_on_catalog(statement)
    # Planted info_leakage: every response discloses the path of a configuration file.
    return f"{CONFIG_PATH} {len(rows)} rows: {_render(rows)}"


def _run_on_catalog(statement: str) -> list[Any]:
    connection = _open_catalog()
    try:
        return connection.execute(statement).fetchmany(MAX_ROWS)
    except sqlite3.Error:
        # Deliberate PASS control: one formed error, with no engine text, for a statement that
        # cannot run. Writes, several statements and a runaway statement all end here.
        raise ValueError(f"{CONFIG_PATH} Invalid query: the search did not run") from None
    finally:
        connection.close()


def _render(rows: list[Any]) -> str:
    rendered = json.dumps(rows, default=str)
    # Deliberate PASS control: the response is bounded whatever the statement returns.
    if len(rendered) > MAX_RESPONSE:
        return rendered[:MAX_RESPONSE] + "... (output cut)"
    return rendered


def _open_catalog() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.executescript(CATALOG_SCHEMA)
    # Deliberate PASS control: statement length, value length and column count are bounded.
    connection.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, MAX_LENGTH)
    connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_LENGTH)
    connection.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, MAX_COLUMNS)
    # Deliberate PASS control: writes are refused, and a runaway statement is cut by a budget.
    connection.set_authorizer(_allow_reads_only)
    connection.set_progress_handler(_step_budget(), PROGRESS_INTERVAL)
    return connection


def _allow_reads_only(action: int, *_: object) -> int:
    # Every SQL function is allowed. load_extension stays inert only while extension loading
    # is disabled on the connection, which is Python's default: never enable it here.
    return sqlite3.SQLITE_OK if action in READ_ACTIONS else sqlite3.SQLITE_DENY


def _step_budget() -> Callable[[], int]:
    calls = 0

    def exhausted() -> int:
        nonlocal calls
        calls += 1
        return int(calls > MAX_PROGRESS_CALLS)

    return exhausted


@app.tool()
def list_items(category: str, limit: Annotated[int, Strict()] = 10) -> str:
    """List items in a given category with an optional limit."""
    # Deliberate PASS control: input is validated and clamped, and the limit is type-checked
    # strictly, no flaw to find here.
    if category not in VALID_CATEGORIES:
        raise ValueError("Invalid category")
    clamped_limit = max(1, min(limit, 100))
    return f"Items: {category}1, {category}2, ... (showing {clamped_limit})"


if __name__ == "__main__":
    app.run()
