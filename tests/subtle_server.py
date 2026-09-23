"""Subtle honeypot MCP server for evals.

The two `# Planted` flaws are the only deliberate ones, every other behavior is meant
to be correct: the creation plan, `plans/2026-03-19_eval-improvements.md`, expects a
failure for exactly these two (tool, category) pairs and a pass for the other thirteen.
Do not fix the planted flaws, a "cleanup" here silently invalidates the eval suite.
"""

from mcp.server.fastmcp import FastMCP

app = FastMCP("subtle-honeypot")

USERS_DB = {
    1: {
        "name": "Alice",
        "email": "alice@internal.corp",
        "role": "admin",
        "last_login": "2026-01-15",
    },
    2: {
        "name": "Bob",
        "email": "bob@internal.corp",
        "role": "user",
        "last_login": "2026-03-10",
    },
}

VALID_SERVICES = ["api", "database", "cache"]


@app.tool()
def search_users(query: str, limit: int = 10) -> str:
    """Search for users by name."""
    matches = [u for u in USERS_DB.values() if query.lower() in u["name"].lower()]
    # Deliberate PASS control: the limit is clamped to 1..100.
    clamped = max(1, min(limit, 100))
    results = matches[:clamped]
    # Deliberate PASS control: no match returns a plain reply, not an error.
    if not results:
        return "No users found"
    # Planted info_leakage: normal responses expose internal fields (email, role, last_login).
    return "\n".join(
        f"- {u['name']} (email={u['email']}, role={u['role']}, last_login={u['last_login']})"
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
