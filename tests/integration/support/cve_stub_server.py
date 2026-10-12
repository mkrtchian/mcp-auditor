"""A read server for the calibration and survey tests. Each `PATH=NONCE` argument on the command
line is served behind that path, each `error=PATH` makes a read of that path raise, and every
other path reads clean. The builder passes different arguments for the vulnerable and the patched
version, so the one server stands in for both."""

import sys

from mcp.server.fastmcp import FastMCP

app = FastMCP("cve-stub")

_served: dict[str, str] = {}
_errors: set[str] = set()
for _arg in sys.argv[1:]:
    if _arg.startswith("error="):
        _errors.add(_arg.removeprefix("error="))
    else:
        _path, _, _nonce = _arg.partition("=")
        _served[_path] = _nonce


@app.tool()
def read(path: str) -> str:
    if path in _errors:
        raise RuntimeError(f"cannot read {path}")
    return _served.get(path, "ok")


if __name__ == "__main__":
    app.run()
