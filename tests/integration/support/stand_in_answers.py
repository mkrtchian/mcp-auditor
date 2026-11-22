from collections.abc import Sequence

from tests.integration.support.stand_in_fetches import Fetched


def answered_with(fetched: Fetched, status: int, body: str) -> None:
    assert (fetched.status, fetched.body) == (status, body)
    assert fetched.headers.get("content-length") == str(len(body.encode()))


def answered_by_its_route(fetched: Fetched, headers: Sequence[tuple[str, str]], body: str) -> None:
    assert (fetched.status, fetched.body) == (200, body)
    carries(fetched, headers, len(body.encode()))


def carries(fetched: Fetched, headers: Sequence[tuple[str, str]], length: int | None) -> None:
    computed: list[tuple[str, str]] = [] if length is None else [("Content-Length", str(length))]
    assert fetched.header_list == [*headers, *computed]
