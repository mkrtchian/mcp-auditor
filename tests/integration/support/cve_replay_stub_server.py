"""A read server for the replay integration tests, modelled on cve_stub_server.py.

Each `PATH=NONCE` argument serves that nonce behind that path, `echo` makes a read return its own
path argument (so a replay sent an old nonce in an argument sees it echoed back), and
`exit_on_call=N` exits the process at the start of the N-th read, so a patched stub can be made
to die while answering a call (N=1) or after answering an earlier one (N>1). `noisy_shutdown`
logs a non-JSON line to stdout once its stdin closes, as a real server that logs its shutdown
does, after the client has stopped reading messages.
"""

import os
import sys

from mcp.server.fastmcp import FastMCP

app = FastMCP("cve-replay-stub")

_served: dict[str, str] = {}
_echo = False
_exit_on_call = 0
_noisy_shutdown = False
_calls = 0
for _arg in sys.argv[1:]:
    if _arg == "echo":
        _echo = True
    elif _arg == "noisy_shutdown":
        _noisy_shutdown = True
    elif _arg.startswith("exit_on_call="):
        _exit_on_call = int(_arg.removeprefix("exit_on_call="))
    else:
        _path, _, _nonce = _arg.partition("=")
        _served[_path] = _nonce


@app.tool()
def read(path: str) -> str:
    global _calls
    _calls += 1
    if _exit_on_call and _calls >= _exit_on_call:
        os._exit(0)
    if _echo:
        return path
    return _served.get(path, "ok")


if __name__ == "__main__":
    app.run()
    if _noisy_shutdown:
        # Straight to the descriptor: the stdio transport closed sys.stdout when the server stopped.
        os.write(1, b"Received SIGTERM, shutting down...\n")
