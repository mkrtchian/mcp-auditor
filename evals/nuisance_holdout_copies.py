"""The counted flaws whose fix check copies a holdout calibration from a fixture that has since
changed or left the holdout: the recorded `holdout_fingerprint` differs from the drawn target's
current fixture fingerprint, or the flaw is neither a drawn target nor a sibling a drawn target's
card files. `copy_targets` maps each copyable flaw (a drawn target, or a sibling of one) to the
drawn target whose calibration it may copy, so the caller can read a sibling copy against that
target's fixture. A `fix_check`-source record, a flaw that does not count and a copy with no
recorded fingerprint are never read (the last is `nuisance_unrecorded`'s)."""

from collections.abc import Iterable, Mapping, Sequence

from evals.census_draw import DrawRecord
from evals.nuisance_admission import AdmittedServer
from evals.nuisance_counting import counted_flaws


def copy_targets(drawn: Iterable[str], draw: DrawRecord | None) -> dict[str, str]:
    mapping = {identifier: identifier for identifier in drawn}
    if draw is None:
        return mapping
    drawn_targets = frozenset(mapping)
    for card in draw.cards:
        if card.flaw in drawn_targets:
            for sibling in card.siblings:
                mapping[sibling.flaw] = card.flaw
    return mapping


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
