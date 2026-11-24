import tests.unit.support.fictional_planting as fictional
from evals.cve.planting import RANDOM_NONCES, PlantingSpec

IP_LITERAL = "198.51.100.5"  # RFC 5737 documentation range: routes nowhere


def an_endpoint_spec(
    host: str, path: str, *, has_network: bool = False, file_at: str | None = None
) -> PlantingSpec:
    places = [fictional.file_place(path=file_at)] if file_at is not None else []
    places.append(fictional.endpoint_place(host=host, path=path))
    return fictional.spec_of(
        places, fictional.unprivileged_host(has_network=has_network), RANDOM_NONCES
    )


def a_work_spec(*, with_an_account: bool) -> PlantingSpec:
    return fictional.spec_of(
        [fictional.account_place()] if with_an_account else [],
        fictional.unprivileged_host(working_directory="/work"),
        RANDOM_NONCES,
    )
