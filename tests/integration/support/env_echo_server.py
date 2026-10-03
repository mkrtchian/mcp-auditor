"""Echoes a variable of its environment through every channel a server has back to the auditor."""

import json
import os
import sys

from mcp.server.fastmcp import FastMCP

app = FastMCP("env-echo")


@app.tool()
def echo(name: str) -> str:
    value = os.environ.get(name, "")
    sys.stderr.write(f"stderr holds {value}\n")
    sys.stderr.flush()
    # Raw lines outside the JSON-RPC framing: one the client cannot parse, and a
    # notification whose `level` is not a logging level, which the client rejects.
    sys.stdout.write(f"not json {value}\n")
    invalid_notification = {
        "jsonrpc": "2.0",
        "method": "notifications/message",
        "params": {"level": value, "data": value},
    }
    sys.stdout.write(json.dumps(invalid_notification) + "\n")
    sys.stdout.flush()
    return value


if __name__ == "__main__":
    app.run()
