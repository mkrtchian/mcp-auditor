from collections.abc import Collection

from tests.unit.support.test_nuisance_solo_given import InFlight


def played_alone(in_flight: InFlight, package: str, calls: int) -> None:
    """Each of the package's calls ran with no other call in flight, its own included, and no
    other call started beside it."""
    alone = [now for started, now in in_flight.starts if started == package]
    assert alone == [[package]] * calls
    assert all(package not in now for started, now in in_flight.starts if started != package)


def played_together(in_flight: InFlight, packages: Collection[str], peak: int) -> None:
    """The packages' calls overlapped up to `peak` at once."""
    seen = [len(now) for started, now in in_flight.starts if started in packages]
    assert max(seen) == peak
