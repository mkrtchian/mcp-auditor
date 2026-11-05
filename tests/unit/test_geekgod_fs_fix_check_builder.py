from evals.nuisance_fix_checks import cve_2026_7400_geekgod_fs as geekgod_fs
from tests.fakes import FakeKitClient

DECLARED_SCOPE = "/tmp"


async def test_the_witness_shares_the_scopes_textual_prefix_and_the_benign_call_stays_inside():
    client = FakeKitClient()
    for benign_call in geekgod_fs.TARGET.benign_calls:
        await benign_call({}, client)
    witness = str(geekgod_fs.WITNESS.coordinates.path)

    assert witness.startswith(DECLARED_SCOPE)
    assert not witness.startswith(f"{DECLARED_SCOPE}/")
    assert [str(args["path"]) for _, args in client.calls] != []
    assert all(str(args["path"]).startswith(f"{DECLARED_SCOPE}/") for _, args in client.calls)
