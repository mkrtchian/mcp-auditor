import pytest

from evals.holdout_census import HoldoutCensus, load_census
from evals.nuisance_admission import ADMISSION_PATH, load_admission
from evals.nuisance_commands import WALK_RECORD_PATH
from evals.nuisance_walk import NuisanceServer, nuisance_population
from evals.nuisance_walk_record import NuisanceCensus, load_walk_record
from evals.run_census import CENSUS_PATH

DYNATRACE = "npm:@dynatrace-oss/dynatrace-mcp-server"


@pytest.fixture(scope="module")
def census() -> HoldoutCensus:
    return load_census(CENSUS_PATH)


@pytest.fixture(scope="module")
def nuisance_census(census: HoldoutCensus) -> NuisanceCensus:
    return load_walk_record(WALK_RECORD_PATH, census)


@pytest.fixture(scope="module")
def population(nuisance_census: NuisanceCensus) -> list[NuisanceServer]:
    return nuisance_population(nuisance_census)


def test_the_committed_walk_record_loads(nuisance_census: NuisanceCensus):
    assert nuisance_census.record.addition.size == 43


def test_the_record_takes_no_server_out_of_the_holdout_walk_part(
    census: HoldoutCensus, nuisance_census: NuisanceCensus, population: list[NuisanceServer]
):
    bare = NuisanceCensus(
        census=census,
        record=nuisance_census.record.model_copy(update={"settlements": [], "identities": []}),
    )
    before = [s.server_package for s in nuisance_population(bare) if not s.in_addition]
    after = {s.server_package: s for s in population if not s.in_addition}

    assert len(before) == 68
    assert list(after) == before
    # The record settles GHSA-pqh8-p93p-2rx7 out of the grammar, a class the admission settles.
    assert after[DYNATRACE].version_setting == ("GHSA-pc2w-4mq8-32qw", "GHSA-pqh8-p93p-2rx7")


def test_the_addition_part_lists_the_servers_outside_the_grammar_too(
    population: list[NuisanceServer],
):
    assert len([s for s in population if s.in_addition]) == 53


def test_the_identities_merge_the_duplicate_spellings(population: list[NuisanceServer]):
    packages = {server.server_package for server in population}

    assert "https://github.com/googleapis/mcp-toolbox" not in packages
    assert "PyPI:kubectl-mcp-tool" not in packages
    assert "Go:github.com/googleapis/mcp-toolbox" in packages
    assert "PyPI:kubectl-mcp-server" in packages


def test_the_admitted_queue_servers_enter_through_the_addition(
    nuisance_census: NuisanceCensus, population: list[NuisanceServer]
):
    admission = load_admission(ADMISSION_PATH, nuisance_census)
    in_addition = {s.server_package for s in population if s.in_addition}
    admitted = {server.server_package for server in admission.servers}

    assert len(admitted & in_addition) == 25
