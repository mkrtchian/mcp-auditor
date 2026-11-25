import pathlib
import sys

from mcp_auditor.adapters.server_launch import ServerLaunch

_SUPPORT = pathlib.Path(__file__).resolve().parent
CALIBRATION_READ_SERVER_PATH = _SUPPORT / "calibration_read_server.py"
ENV_ECHO_SERVER_PATH = _SUPPORT / "env_echo_server.py"
PAGINATED_SERVER_PATH = _SUPPORT / "paginated_server.py"
READ_SERVER_PATH = _SUPPORT / "read_server.py"
STALLING_SERVER_PATH = _SUPPORT / "stalling_server.py"
A_COMMAND_NOT_FOUND = ServerLaunch.unconfined("mcp-auditor-no-such-command", [])


def a_paginated_server(*flags: str) -> ServerLaunch:
    return ServerLaunch.unconfined(sys.executable, [str(PAGINATED_SERVER_PATH), *flags])


def a_read_server(*flags: str) -> ServerLaunch:
    return ServerLaunch.unconfined(sys.executable, [str(READ_SERVER_PATH), *flags])


def a_stalling_server(*flags: str) -> ServerLaunch:
    return ServerLaunch.unconfined(sys.executable, [str(STALLING_SERVER_PATH), *flags])
