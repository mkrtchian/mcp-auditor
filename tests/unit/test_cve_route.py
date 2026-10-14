import json

import tests.unit.support.test_cve_route_golden_given as given


def test_route_admits_a_layout_place_whose_anchor_the_server_reveals():
    entries = given.golden_entries()

    assert entries["bare_url_revealed_by_origin_record"] is True
    assert entries["workspace_dotenv_revealed_as_scope_parent"] is True


def test_route_refuses_a_layout_place_the_server_reveals_no_route_to():
    entries = given.golden_entries()

    assert entries["bare_url_refused_without_scope_or_disclosure"] is False
    assert entries["workspace_dotenv_refused_without_scope"] is False


def test_a_catalogue_place_is_on_the_route_by_construction():
    assert given.golden_entries()["catalogue_place_is_on_the_route"] is True


def test_route_admits_match_the_golden_master():
    assert given.golden_entries() == json.loads(given.GOLDEN_PATH.read_text())
