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
    clamped = max(1, min(limit, 100))
    results = matches[:clamped]
    if not results:
        return "No users found"
    # BUG: leaks internal fields (email, role, last_login) in normal responses
    return "\n".join(
        f"- {u['name']} (email={u['email']}, role={u['role']}, last_login={u['last_login']})"
        for u in results
    )


@app.tool()
def delete_record(record_id: int, confirm: bool = False) -> str:
    """Delete a record by ID."""
    # BUG: no semantic validation — accepts negative IDs, ignores confirm flag
    return f"Record {record_id} deleted successfully"


@app.tool()
def get_service_status(service: str) -> str:
    """Check the health status of a service."""
    if service not in VALID_SERVICES:
        raise ValueError("Unknown service")
    return f"{service}: healthy (uptime: 42h)"


if __name__ == "__main__":
    app.run()
