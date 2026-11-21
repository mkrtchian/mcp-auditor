from collections.abc import Mapping, Sequence

from evals.cve.nuisance.admission.admission import AdmittedServer


class ScriptedBenignCall:
    """A nuisance benign call failing with the reason `reasons` gives a server's package: a string
    on every call, a sequence one reason per successive call (None past its end), a package it
    does not name answering every call. `calls` counts the calls per package."""

    def __init__(self, reasons: Mapping[str, str | Sequence[str | None] | None] | None = None):
        self.calls: dict[str, int] = {}
        self._reasons = reasons or {}

    async def __call__(self, server: AdmittedServer) -> str | None:
        package = server.server_package
        self.calls[package] = self.calls.get(package, 0) + 1
        scripted = self._reasons.get(package)
        if scripted is None or isinstance(scripted, str):
            return scripted
        index = self.calls[package] - 1
        return scripted[index] if index < len(scripted) else None
