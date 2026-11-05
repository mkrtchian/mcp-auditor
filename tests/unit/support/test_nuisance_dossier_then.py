from evals.nuisance_admission import AdmittedServer
from evals.nuisance_unrecorded import unrecorded_fields


def unrecorded_field_names(server: AdmittedServer) -> list[str]:
    [gap] = unrecorded_fields([server])
    listed = gap.removeprefix(f"{server.server_package}: ")
    return [item.split(" (")[0] for item in listed.split(", ")]
