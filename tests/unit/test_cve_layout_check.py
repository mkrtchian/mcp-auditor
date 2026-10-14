import json

import tests.unit.support.test_cve_layout_check_golden_given as given


def test_the_tree_is_invisible_to_the_servers_ordinary_surface():
    healthy = given.golden_entries()["tree_invisible_to_the_ordinary_surface"]

    assert healthy == {"surface_unchanged": True, "nonce_in_surface": False}


def test_the_check_distinguishes_a_planted_surface_that_differs():
    assert given.golden_entries()["planted_surface_differs"]["surface_unchanged"] is False


def test_the_check_catches_a_nonce_leaking_into_the_ordinary_surface():
    assert (
        given.golden_entries()["nonce_leaks_into_the_ordinary_surface"]["nonce_in_surface"] is True
    )


def test_layout_effects_match_the_golden_master():
    assert given.golden_entries() == json.loads(given.GOLDEN_PATH.read_text())
