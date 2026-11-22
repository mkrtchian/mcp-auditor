import sys

from mcp_auditor.adapters.server_launch import ServerLaunch
from tests.integration.support.support_servers import PAGINATED_SERVER_PATH


def paginated_launch(*flags: str) -> ServerLaunch:
    return ServerLaunch.unconfined(sys.executable, [str(PAGINATED_SERVER_PATH), *flags])
