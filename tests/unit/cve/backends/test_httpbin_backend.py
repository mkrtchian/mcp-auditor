import tests.unit.cve.backends.support.test_httpbin_backend_given as given
import tests.unit.cve.backends.support.test_httpbin_backend_then as then
from evals.cve.backends.httpbin import HTTPBIN_PARTS, httpbin_server_args


def test_the_server_joins_the_bridge_with_httpbin_org_at_the_front():
    server_args = httpbin_server_args("server", "image", given.a_host(), ["serve"])

    then.joins_the_bridge_with_httpbin_org_at_the_front(server_args)


def test_the_server_trusts_the_fixture_authority_mounted_read_only():
    server_args = httpbin_server_args("server", "image", given.a_host(), [])

    then.trusts_the_fixture_authority_through_ssl_cert_file(server_args)


def test_the_front_mounts_the_leaf_and_key_of_httpbin_org_read_only():
    then.mounts_the_leaf_and_key_of_httpbin_org(given.the_front().run_args())


def test_every_part_runs_hardened_with_no_capability_on_the_bridge():
    for part in HTTPBIN_PARTS:
        then.carries_the_hardening_with_no_capability(part.run_args())
        then.sits_on_the_bridge_at_its_address(part.run_args(), part.ip)


def test_the_front_sits_at_the_address_httpbin_org_resolves_to():
    assert given.the_front().ip == "44.209.237.184"
