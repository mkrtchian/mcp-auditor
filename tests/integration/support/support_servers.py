import pathlib
import sys

from mcp_auditor.adapters.server_launch import ServerLaunch

_SUPPORT = pathlib.Path(__file__).resolve().parent
READ_SERVER_PATH = _SUPPORT / "detection_replay_read_server.py"
STALLING_SERVER_PATH = _SUPPORT / "stalling_server.py"
A_COMMAND_NOT_FOUND = ServerLaunch.unconfined("mcp-auditor-no-such-command", [])


def a_read_server(*flags: str) -> ServerLaunch:
    return ServerLaunch.unconfined(sys.executable, [str(READ_SERVER_PATH), *flags])


def a_stalling_server(*flags: str) -> ServerLaunch:
    return ServerLaunch.unconfined(sys.executable, [str(STALLING_SERVER_PATH), *flags])
