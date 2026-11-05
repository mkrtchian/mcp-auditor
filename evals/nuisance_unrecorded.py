"""The fields rule v3 or v4 adds that an audited server's admission does not yet record, where they
bear on what a run counts or makes: the counted tools' real-software verdicts, the declared
function of every tool of a counted flaw (those it leaves out included), the expected text and
prerequisite calls of the benign calls a vet makes, the counted flaws' relaying stand-in judgment,
the fingerprint a counted flaw's copied holdout calibration was copied at, and the server's
stand-ins, seeds and real software's releases. A removed tool and a flaw that does not count are
never read. The run and the gate refuse while one is missing; the vet only counts them."""

from collections.abc import Sequence

from evals.eval_session import Refused
from evals.nuisance_admission import AdmittedServer, FlawRecord
from evals.nuisance_benign_call import benign_calls
from evals.nuisance_counting import counted_flaws, counted_tools


def unrecorded_fields(servers: Sequence[AdmittedServer]) -> list[str]:
    gaps: list[str] = []
    for server in servers:
        fields = _unrecorded_counts(server) + _unrecorded_provenance(server)
        if fields:
            gaps.append(f"{server.server_package}: {', '.join(fields)}")
    return gaps


def refuse_unrecorded(servers: Sequence[AdmittedServer], title: str) -> None:
    gaps = unrecorded_fields(servers)
    if gaps:
        raise Refused(title, ["fields rule v3 or v4 adds are not yet recorded", *gaps])


def _unrecorded_counts(server: AdmittedServer) -> list[str]:
    flaws = counted_flaws(server)
    calls = benign_calls(server).values()
    counts = [
        ("real_software", len(_unverdicted_tools(server)), "tool"),
        ("declared_function_is_effect", len(_undeclared_tools(server)), "tool"),
        ("expect", sum(call.expect is None for call in calls), "benign call"),
        ("before", sum(call.before is None for call in calls), "benign call"),
        (
            "relies_on_relaying_stand_in",
            sum(flaw.fix_check.relies_on_relaying_stand_in is None for flaw in flaws),
            "flaw",
        ),
        ("holdout_fingerprint", sum(_unfingerprinted_copy(flaw) for flaw in flaws), "flaw"),
    ]
    return [f"{field} ({n} {noun}{'' if n == 1 else 's'})" for field, n, noun in counts if n]


def _unverdicted_tools(server: AdmittedServer) -> set[str | None]:
    counted = counted_tools(server)
    return {
        tool.patched_name
        for flaw in counted_flaws(server)
        for tool in flaw.tools
        if tool.patched_name in counted and tool.real_software is None
    }


def _undeclared_tools(server: AdmittedServer) -> set[str | None]:
    return {
        tool.patched_name
        for flaw in counted_flaws(server)
        for tool in flaw.tools
        if tool.status != "removed" and tool.declared_function_is_effect is None
    }


def _unfingerprinted_copy(flaw: FlawRecord) -> bool:
    check = flaw.fix_check
    return check.source == "holdout_calibration" and check.holdout_fingerprint is None


def _unrecorded_provenance(server: AdmittedServer) -> list[str]:
    recorded = {
        "stand_ins": server.stand_ins,
        "seeds": server.seeds,
        "software_releases": server.software_releases,
    }
    return [field for field, value in recorded.items() if value is None]
