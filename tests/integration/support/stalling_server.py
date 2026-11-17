"""A server whose tools stall, for the ping tests of the client.

`wait_forever` never returns but leaves the event loop free, `block_loop` blocks the loop,
`echo` answers at once and `pid` answers with the server's process ID. `exit` exits without
answering, and `exit_leaving_stdout_open` exits while a child of its own keeps the server's stdout
open for `ORPHAN_SECONDS`, so the client sees no end of the stream and its next write finds no
reader. `--ignore-ping` leaves every ping unanswered, and `--error-ping` answers it with a JSON-RPC
error. `--exit-before-initialize` and `--exit-on-list-tools` write `DYING_WORDS` to stderr and exit,
before the handshake or while answering `tools/list`. `--serve-once PATH` serves the launch that
finds no file at PATH and writes it, so a second launch exits before the handshake, and
`--silent-once-served PATH` likewise, a second launch never answering `initialize`.
`--silent-with-noisy-shutdown` never answers `initialize` and logs a line to stdout once its stdin
closes.
"""

import os
import pathlib
import subprocess
import sys
import time
from typing import Any

import anyio
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.shared.exceptions import McpError
from mcp.types import (
    INTERNAL_ERROR,
    CallToolResult,
    EmptyResult,
    ErrorData,
    PingRequest,
    ServerResult,
    TextContent,
    Tool,
)

BLOCKED_LOOP_SECONDS = 3600
ORPHAN_SECONDS = 10
DYING_WORDS = "the stalling server is going away"
TOOLS = [
    Tool(name=name, inputSchema={"type": "object"})
    for name in ("wait_forever", "block_loop", "echo", "pid", "exit", "exit_leaving_stdout_open")
]

server = Server("stalling")


@server.list_tools()
async def list_tools() -> list[Tool]:
    if "--exit-on-list-tools" in sys.argv[1:]:
        _die()
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> CallToolResult:
    if name == "wait_forever":
        await anyio.sleep_forever()
    if name == "block_loop":
        time.sleep(BLOCKED_LOOP_SECONDS)
    if name == "exit":
        os._exit(0)
    if name == "exit_leaving_stdout_open":
        _orphan_holding_stdout()
        os._exit(0)
    text = str(os.getpid()) if name == "pid" else "ok"
    return CallToolResult(content=[TextContent(type="text", text=text)])


# `os._exit`, so stderr carries `DYING_WORDS` alone: a `SystemExit` raised in a handler exits too,
# but leaves through the request loop's task groups, which print a long traceback after it.
def _die() -> None:
    sys.stderr.write(f"{DYING_WORDS}\n")
    sys.stderr.flush()
    os._exit(3)


def _log_shutdown_once_stdin_closes() -> None:
    sys.stdin.read()
    os.write(1, b"shutting down\n")
    os._exit(0)


def _orphan_holding_stdout() -> None:
    subprocess.Popen(
        [sys.executable, "-c", f"import time; time.sleep({ORPHAN_SECONDS})"],
        stdin=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _served_before(marker: pathlib.Path) -> bool:
    if marker.exists():
        return True
    marker.touch()
    return False


async def _never_answered(request: PingRequest) -> ServerResult:
    await anyio.sleep_forever()
    return ServerResult(EmptyResult())


async def _answered_with_an_error(request: PingRequest) -> ServerResult:
    raise McpError(ErrorData(code=INTERNAL_ERROR, message="ping refused"))


async def main() -> None:
    if "--exit-before-initialize" in sys.argv[1:]:
        _die()
    if "--serve-once" in sys.argv[1:] and _served_before(
        pathlib.Path(sys.argv[sys.argv.index("--serve-once") + 1])
    ):
        _die()
    if "--silent-once-served" in sys.argv[1:] and _served_before(
        pathlib.Path(sys.argv[sys.argv.index("--silent-once-served") + 1])
    ):
        time.sleep(BLOCKED_LOOP_SECONDS)
    if "--silent-with-noisy-shutdown" in sys.argv[1:]:
        _log_shutdown_once_stdin_closes()
    if "--ignore-ping" in sys.argv[1:]:
        server.request_handlers[PingRequest] = _never_answered
    if "--error-ping" in sys.argv[1:]:
        server.request_handlers[PingRequest] = _answered_with_an_error
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    anyio.run(main)
