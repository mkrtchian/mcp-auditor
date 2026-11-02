from evals.eval_session import Refused
from tests.unit.support.test_closed_network_refusal_given import DAEMON_MESSAGE


def refused_for_the_daemon(refusal: Refused) -> None:
    assert refusal.title == "the Docker daemon cannot create a closed network"
    assert DAEMON_MESSAGE in refusal.reasons
    assert "Docker Engine 28.0 or later is required" in refusal.reasons
