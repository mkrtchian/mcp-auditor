from collections.abc import Sequence

from tests.integration.support.test_cve_planting_stand_ins_given import Fetched


def answered_without_its_body(fetched: Fetched, status: int, body: str) -> None:
    assert (fetched.status, fetched.body) == (status, "")
    assert fetched.headers.get("content-length") == str(len(body.encode()))


def redirects_to(fetched: Fetched, location: str) -> None:
    assert fetched.status == 301
    assert fetched.headers.get("location") == location


def logged_its_default_for(log: str, host: str, misses: list[str]) -> None:
    prefix = f"stand-in for {host} answered with its default for: miss "
    assert all(prefix + miss in log for miss in misses), log


def answered_with(fetched: Fetched, status: int, body: str) -> None:
    assert (fetched.status, fetched.body) == (status, body)
    assert fetched.headers.get("content-length") == str(len(body.encode()))


def carries(fetched: Fetched, headers: Sequence[tuple[str, str]], length: int | None) -> None:
    computed = [] if length is None else [("Content-Length", str(length))]
    assert fetched.header_list == [*headers, *computed]


def answered_by_its_route(fetched: Fetched, headers: Sequence[tuple[str, str]], body: str) -> None:
    assert (fetched.status, fetched.body) == (200, body)
    carries(fetched, headers, len(body.encode()))
