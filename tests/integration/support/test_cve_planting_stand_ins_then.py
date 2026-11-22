from tests.integration.support.stand_in_fetches import Fetched


def answered_without_its_body(fetched: Fetched, status: int, body: str) -> None:
    assert (fetched.status, fetched.body) == (status, "")
    assert fetched.headers.get("content-length") == str(len(body.encode()))


def redirects_to(fetched: Fetched, location: str) -> None:
    assert fetched.status == 301
    assert fetched.headers.get("location") == location


def logged_its_default_for(log: str, host: str, misses: list[str]) -> None:
    prefix = f"stand-in for {host} answered with its default for: miss "
    assert all(prefix + miss in log for miss in misses), log
