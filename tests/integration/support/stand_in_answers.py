from collections.abc import Sequence

from tests.integration.support.stand_in_capture import StandInAnswer
from tests.integration.support.stand_in_fetches import Fetched


def answered_with(fetched: Fetched, answer: StandInAnswer) -> None:
    assert (fetched.status, fetched.body) == (answer.status, answer.body)
    assert fetched.headers.get("content-length") == str(len(answer.body.encode()))


def answered_by_its_route(fetched: Fetched, answer: StandInAnswer) -> None:
    assert (fetched.status, fetched.body) == (answer.status, answer.body)
    carries(fetched, answer.headers, len(answer.body.encode()))


def carries(fetched: Fetched, headers: Sequence[tuple[str, str]], length: int | None) -> None:
    computed: list[tuple[str, str]] = [] if length is None else [("Content-Length", str(length))]
    assert fetched.header_list == [*headers, *computed]
