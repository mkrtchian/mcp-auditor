from evals.cve.planting import RANDOM_NONCES, PlantingSpec
from tests.unit.support.fictional_planting import account_place, spec_of, unprivileged_host

_HOST = unprivileged_host(working_directory="/")


def a_spec() -> PlantingSpec:
    return spec_of([], _HOST, RANDOM_NONCES)


def a_spec_with_an_account() -> PlantingSpec:
    return spec_of([account_place()], _HOST, RANDOM_NONCES)


def options_running_as(*user_options: str) -> list[str]:
    return ["run", "-i", "--rm", "--cap-drop", "ALL", *user_options, "-e", "HOME=/tmp"]
