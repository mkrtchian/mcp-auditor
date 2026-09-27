"""A read server for calibration tests: the nonce passed as argv sits behind `/outside/flag`."""

import sys

from mcp.server.fastmcp import FastMCP

app = FastMCP("cve-stub")


@app.tool()
def read(path: str) -> str:
    return sys.argv[1] if path == "/outside/flag" else "ok"


if __name__ == "__main__":
    app.run()
