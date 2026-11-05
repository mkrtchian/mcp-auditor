"""The counted flaws whose fix check copies a holdout calibration from a fixture that has since
changed or left the holdout: the recorded `holdout_fingerprint` differs from the drawn target's
current fixture fingerprint, or the flaw is no longer a drawn target. A `fix_check`-source record,
a flaw that does not count and a copy with no recorded fingerprint are never read (the last is
`nuisance_unrecorded`'s)."""

from collections.abc import Mapping, Sequence

from evals.nuisance_admission import AdmittedServer
from evals.nuisance_counting import counted_flaws


def stale_holdout_copies(
    servers: Sequence[AdmittedServer], current: Mapping[str, str]
) -> list[str]:
    stale: list[str] = []
    for server in servers:
        for flaw in counted_flaws(server):
            check = flaw.fix_check
            recorded = check.holdout_fingerprint
            if check.source != "holdout_calibration" or recorded is None:
                continue
            now = current.get(flaw.flaw)
            where = f"{server.server_package}: {flaw.flaw}"
            if now is None:
                stale.append(f"{where} is no longer a drawn holdout target")
            elif now != recorded:
                stale.append(f"{where} copied at {recorded}, its fixture is now at {now}")
    return stale
