# `contextforge_ssrf_env` builds its `docker run` argv from `*args.env, *args.network` alone,
# deliberately: the gateway must run as root (`--user 0:0`, so its entrypoint can rewrite
# /etc/hosts for the DNS rebinding) and mounts no /srv tree (the flaw is a network fetch, not a
# filesystem read). That shortcut silently drops `args.user`, `args.working_directory`,
# `args.mounts` and `args.hostname` that the planting layer would otherwise emit. This pins the
# CVE-2026-18905 planting spec to the shape that drop is safe for, so a future change to the
# fixture's planting shape (a file place, an account, a layout, a hostname) fails here instead of
# silently vanishing from the launch.
from evals.cve_places import HOLDOUT_PLACES, kept_records, load_places
from evals.cve_planting import SymbolicUser
from evals.holdout_fixtures.cve_2026_18905_contextforge import TARGET


def test_the_contextforge_spec_carries_nothing_the_builder_silently_drops():
    places = load_places(HOLDOUT_PLACES)
    spec = TARGET.planting_spec(kept_records(TARGET.kept_places, places))

    assert spec.files == ()  # no file mount for the builder to drop
    assert spec.account is None  # no /etc/passwd+group mounts, and no --user the builder overrides
    assert spec.layout == ()  # no /srv layout the builder would have to mount
    assert spec.hostname is None  # no --hostname for the builder to drop
    # the only user/cwd the builder drops, overriding them with root 0:0 and no -w
    assert spec.host.user is SymbolicUser.UNPRIVILEGED
    assert spec.host.working_directory == "/tmp"
