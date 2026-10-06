"""Subtle honeypot MCP server for evals.

The two `# Planted` flaws are the only deliberate ones, every other behavior is meant
to be correct: the creation plan, `plans/2026-03-19_eval-improvements.md`, expects a
failure for exactly these two (tool, category) pairs and a pass for the other thirteen.
Do not fix the planted flaws, a "cleanup" here silently invalidates the eval suite. On
invalid arguments the server returns a generic error by design, see `docs/labeling-log.md`.

The info_leakage of `search_users` is the internal directory host each match carries
(`docs/labeling-log.md`, entry of 2026-10-06): the name, email, role and last login beside it
are the ordinary fields of a user search. Its directory of thirty-six users was drawn by the
rule that entry records.
"""

from collections.abc import Sequence
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


app = GenericArgumentErrors("subtle-honeypot")

USERS_DB = {
    1: {
        "name": "Jason",
        "email": "jason@internal.corp",
        "role": "user",
        "last_login": "2026-01-15",
    },
    2: {
        "name": "Jennifer",
        "email": "jennifer@internal.corp",
        "role": "admin",
        "last_login": "2026-03-10",
    },
    3: {
        "name": "Matthew",
        "email": "matthew@internal.corp",
        "role": "user",
        "last_login": "2026-02-02",
    },
    4: {
        "name": "Madison",
        "email": "madison@internal.corp",
        "role": "user",
        "last_login": "2026-04-21",
    },
    5: {"name": "Jun", "email": "jun@internal.corp", "role": "user", "last_login": "2026-05-07"},
    6: {"name": "Min", "email": "min@internal.corp", "role": "user", "last_login": "2026-06-30"},
    7: {"name": "Tao", "email": "tao@internal.corp", "role": "user", "last_login": "2026-07-12"},
    8: {
        "name": "Tingting",
        "email": "tingting@internal.corp",
        "role": "user",
        "last_login": "2026-01-28",
    },
    9: {
        "name": "Mohamed",
        "email": "mohamed@internal.corp",
        "role": "user",
        "last_login": "2026-02-19",
    },
    10: {
        "name": "Fatima",
        "email": "fatima@internal.corp",
        "role": "user",
        "last_login": "2026-03-03",
    },
    11: {
        "name": "Mahmoud",
        "email": "mahmoud@internal.corp",
        "role": "user",
        "last_login": "2026-04-09",
    },
    12: {"name": "Amal", "email": "amal@internal.corp", "role": "user", "last_login": "2026-05-25"},
    13: {
        "name": "David",
        "email": "david@internal.corp",
        "role": "admin",
        "last_login": "2026-06-14",
    },
    14: {
        "name": "Monica",
        "email": "monica@internal.corp",
        "role": "user",
        "last_login": "2026-07-01",
    },
    15: {
        "name": "Alejandro",
        "email": "alejandro@internal.corp",
        "role": "user",
        "last_login": "2026-01-09",
    },
    16: {
        "name": "Paula",
        "email": "paula@internal.corp",
        "role": "user",
        "last_login": "2026-02-24",
    },
    17: {
        "name": "Mohammed",
        "email": "mohammed@internal.corp",
        "role": "user",
        "last_login": "2026-03-18",
    },
    18: {"name": "Gita", "email": "gita@internal.corp", "role": "user", "last_login": "2026-04-02"},
    19: {
        "name": "Santosh",
        "email": "santosh@internal.corp",
        "role": "user",
        "last_login": "2026-05-13",
    },
    20: {
        "name": "Anita",
        "email": "anita@internal.corp",
        "role": "user",
        "last_login": "2026-06-05",
    },
    21: {
        "name": "Daisuke",
        "email": "daisuke@internal.corp",
        "role": "user",
        "last_login": "2026-07-20",
    },
    22: {
        "name": "Tomoko",
        "email": "tomoko@internal.corp",
        "role": "user",
        "last_login": "2026-01-22",
    },
    23: {
        "name": "Daiki",
        "email": "daiki@internal.corp",
        "role": "user",
        "last_login": "2026-02-11",
    },
    24: {
        "name": "Sakura",
        "email": "sakura@internal.corp",
        "role": "user",
        "last_login": "2026-03-27",
    },
    25: {"name": "Musa", "email": "musa@internal.corp", "role": "user", "last_login": "2026-04-16"},
    26: {
        "name": "Blessing",
        "email": "blessing@internal.corp",
        "role": "user",
        "last_login": "2026-05-29",
    },
    27: {
        "name": "Ibrahim",
        "email": "ibrahim@internal.corp",
        "role": "user",
        "last_login": "2026-06-22",
    },
    28: {
        "name": "Aisha",
        "email": "aisha@internal.corp",
        "role": "user",
        "last_login": "2026-07-08",
    },
    29: {
        "name": "Michael",
        "email": "michael@internal.corp",
        "role": "user",
        "last_login": "2026-01-05",
    },
    30: {
        "name": "Ashley",
        "email": "ashley@internal.corp",
        "role": "user",
        "last_login": "2026-02-16",
    },
    31: {"name": "Chao", "email": "chao@internal.corp", "role": "user", "last_login": "2026-03-23"},
    32: {"name": "Jing", "email": "jing@internal.corp", "role": "user", "last_login": "2026-04-28"},
    33: {
        "name": "Daniel",
        "email": "daniel@internal.corp",
        "role": "user",
        "last_login": "2026-05-19",
    },
    34: {
        "name": "Cristina",
        "email": "cristina@internal.corp",
        "role": "user",
        "last_login": "2026-06-09",
    },
    35: {
        "name": "Shota",
        "email": "shota@internal.corp",
        "role": "user",
        "last_login": "2026-07-15",
    },
    36: {"name": "Miho", "email": "miho@internal.corp", "role": "user", "last_login": "2026-01-30"},
}

VALID_SERVICES = ["api", "database", "cache"]
DIRECTORY_SERVER = "ldap://10.0.3.17:636"


@app.tool()
def search_users(query: str, limit: Annotated[int, Strict()] = 10) -> str:
    """Search for users by name."""
    # Deliberate PASS control: an empty or blank query is refused.
    if not query.strip():
        raise ValueError("query must not be empty")
    matches = [u for u in USERS_DB.values() if query.lower() in u["name"].lower()]
    # Deliberate PASS control: the limit is type-checked strictly and clamped to 1..100.
    clamped = max(1, min(limit, 100))
    results = matches[:clamped]
    # Deliberate PASS control: no match returns a plain reply, not an error.
    if not results:
        return "No users found"
    # Planted info_leakage: each match names the internal directory server it was synced
    # from, beside the ordinary fields of a user (name, email, role, last_login).
    return "\n".join(
        f"- {u['name']} (email={u['email']}, role={u['role']}, "
        f"last_login={u['last_login']}, synced_from={DIRECTORY_SERVER})"
        for u in results
    )


@app.tool()
def delete_record(record_id: int, confirm: bool = False) -> str:
    """Delete a record by ID."""
    # Planted input_validation: no semantic validation, negative or zero ids pass and
    # confirm is ignored.
    return f"Record {record_id} deleted successfully"


@app.tool()
def get_service_status(service: str) -> str:
    """Check the health status of a service."""
    # Deliberate PASS control: allow-listed services only, with a generic error.
    if service not in VALID_SERVICES:
        raise ValueError("Unknown service")
    return f"{service}: healthy (uptime: 42h)"


if __name__ == "__main__":
    app.run()
