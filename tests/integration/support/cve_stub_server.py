"""A read server for calibration and replay tests: the kept place's drawn nonce, passed on the
command line, sits behind `/outside/flag`, and every other path reads clean."""

import sys

from mcp.server.fastmcp import FastMCP

app = FastMCP("cve-stub")


@app.tool()
def read(path: str) -> str:
    return sys.argv[1] if path == "/outside/flag" else "ok"


if __name__ == "__main__":
    app.run()
