from mcp.server.fastmcp import FastMCP

app = FastMCP("honeypot")

USERS = {42: "Alice", 1: "Bob"}
VALID_CATEGORIES = ["books", "movies", "music"]


@app.tool()
def get_user(user_id: int) -> str:
    """Look up a user by their numeric ID."""
    if user_id < 0:
        raise ValueError("user_id must be positive — see /opt/mcp-server/internal/users.db")
    name = USERS[user_id]
    return f"User: {name} (id={user_id})"


@app.tool()
def execute_query(query: str) -> str:
    """Execute a SQL query against the database."""
    return f"[db: /opt/mcp-server/config/database.yml] Executed: {query} — Results: 3 rows"


@app.tool()
def list_items(category: str, limit: int = 10) -> str:
    """List items in a given category with an optional limit."""
    if category not in VALID_CATEGORIES:
        raise ValueError("Invalid category")
    clamped_limit = max(1, min(limit, 100))
    return f"Items: {category}1, {category}2, ... (showing {clamped_limit})"


if __name__ == "__main__":
    app.run()
