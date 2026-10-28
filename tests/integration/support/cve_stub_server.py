"""A read server for the calibration and survey tests. Each `PATH=NONCE` argument on the command
line is served behind that path, each `error=PATH` makes a read of that path raise, and every
other path reads clean. The builder passes different arguments for the vulnerable and the patched
version, so the one server stands in for both.

`launches=COUNTER:FAILURES` appends one mark to COUNTER per launch and exits at startup while the
file held fewer than FAILURES marks before it. `broken-tools-list` makes tools/list raise on a
server that launched."""

import pathlib
import sys

from mcp.server.fastmcp import FastMCP
from mcp.types import Tool


class _BrokenToolsList(FastMCP):
    async def list_tools(self) -> list[Tool]:
        raise RuntimeError("tools/list broke")


app = (_BrokenToolsList if "broken-tools-list" in sys.argv else FastMCP)("cve-stub")

_served: dict[str, str] = {}
_errors: set[str] = set()
_launch_counter: tuple[pathlib.Path, int] | None = None
for _arg in sys.argv[1:]:
    if _arg == "broken-tools-list":
        continue
    if _arg.startswith("error="):
        _errors.add(_arg.removeprefix("error="))
    elif _arg.startswith("launches="):
        _path, _, _failures = _arg.removeprefix("launches=").rpartition(":")
        _launch_counter = (pathlib.Path(_path), int(_failures))
    else:
        _path, _, _nonce = _arg.partition("=")
        _served[_path] = _nonce


@app.tool()
def read(path: str) -> str:
    if path in _errors:
        raise RuntimeError(f"cannot read {path}")
    return _served.get(path, "ok")


def _count_launch(counter: pathlib.Path, failures: int) -> None:
    marks = len(counter.read_text()) if counter.exists() else 0
    with counter.open("a") as file:
        file.write("x")
    if marks < failures:
        sys.exit("launch failed on purpose")


if __name__ == "__main__":
    if _launch_counter is not None:
        _count_launch(*_launch_counter)
    app.run()
