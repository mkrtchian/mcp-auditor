from collections.abc import Collection, Sequence

from evals.cve.nuisance.admission import AdmittedServer
from tests.unit.support.test_nuisance_solo_given import InFlight


def each_played_alone_after_the_others(
    in_flight: InFlight, solo: Sequence[AdmittedServer], calls: int
) -> None:
    """Each solo server's calls ran with no other call in flight, its own included, and no other
    call started beside them, while a server played together made the first call. A command
    plays its servers phase by phase (benign calls, audits, replays), so a solo server's call
    follows the other servers' calls of its phase, not every call of the command."""
    packages = [server.server_package for server in solo]
    for package in packages:
        alone = [now for started, now in in_flight.starts if started == package]
        assert alone == [[package]] * calls
        assert all(package not in now for started, now in in_flight.starts if started != package)
    assert in_flight.starts[0][0] not in packages


def played_together(in_flight: InFlight, packages: Collection[str], peak: int) -> None:
    """The packages' calls overlapped up to `peak` at once."""
    seen = [len(now) for started, now in in_flight.starts if started in packages]
    assert max(seen) == peak
