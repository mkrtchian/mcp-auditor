from collections.abc import Sequence

from evals.cve.closed_network import ClosedNetworkUnsupported

DAEMON_MESSAGE = "invalid gateway mode: isolated"


def a_daemon_that_cannot_close_a_network() -> None:
    raise ClosedNetworkUnsupported(DAEMON_MESSAGE)


class CountingRebuild:
    def __init__(self) -> None:
        self.rebuilt: list[str] = []

    def __call__(self, services: Sequence[str]) -> None:
        self.rebuilt.extend(services)
