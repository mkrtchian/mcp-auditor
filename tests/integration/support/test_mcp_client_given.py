import pathlib
import sys

from mcp_auditor.adapters.server_launch import ServerLaunch

PAGINATED_SERVER_PATH = pathlib.Path(__file__).resolve().parent / "paginated_server.py"


def paginated_launch(*flags: str) -> ServerLaunch:
    return ServerLaunch.unconfined(sys.executable, [str(PAGINATED_SERVER_PATH), *flags])
