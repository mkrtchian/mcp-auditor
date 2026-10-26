# Holdout backend-image provenance and fingerprint

## Context

A holdout target whose server needs a separate backend to boot and answer its benign calls provisions that backend inside its builder: the drawn Doris target (`CVE-2025-66335`, `evals/holdout_fixtures/cve_2025_66335_doris.py`) runs under `builder=doris_db_env`, which stands up a persistent Apache Doris FE+BE cluster through `ensure_doris` (`evals/doris_backend.py`). That backend pins two external images, `apache/doris:all-in-one-4.1.3` (serves the exploit's `http()` fetch) and `mysql:8.0.46` (the throwaway client that seeds the schema). Neither reaches the holdout run's provenance or its per-target fingerprint today. `HoldoutRunResult.image_ids` records only `target_services(targets)` (each target's compose `images` and its patched twin), looked up through `cve_baseline.image_ids`, which prepends the `mcp-auditor-cve-<name>:local` namespace. And `fixture_fingerprint` covers each target's Dockerfiles, builder name, server image, mechanism, aim, tools filter, reach, planting host and kept records, but no backend image, because the pin lives in `doris_backend.py`, which is absent from the fingerprinted `_ENVIRONMENT_PATHS`.

The nuisance suite already closed this exact gap on its own side. Commit `5b3373a` gave a backend server's provenance its pinned backend image id beside its patched service id, through a non-raising `backend_image_ids` (`evals/nuisance_images.py`) merged into the recorded `image_ids`, with the image carried on `AdmittedServer.backend` (`BackendFixture.image`). The holdout has no equivalent, so the first holdout run would freeze a `uv.lock` and tag a commit while recording nothing about the backend image its Doris target served. If the backend image is later bumped (or a second backend target is added after that run), the ADR 032 paired reading across two points would compare Doris on two silently different backends, with nothing in the record or the fingerprint to catch it. This plan gives `CVETarget` the same backend-image notion the nuisance fixture has, so the first run pins and records the Doris backend the way it already pins the server image.

This plan is a prerequisite for the first holdout run. It is deliberately a faithful mirror of `5b3373a`, not a redesign: the holdout does not need a provisioner registry (the builder already provisions), only to record and fingerprint which backend images a target pins.

## Approach

Add a per-target field `CVETarget.backend_images: tuple[str, ...] = ()` naming the raw external image tags a target's builder provisions (empty for every target whose server needs no separate backend). The Doris target is the only one today: the two other database-backed holdout targets (`mysql_db_env` for CVE-2026-85788, `arcadedb_mcp_env` for CVE-2026-65831) bake their engine into the compose-built server image (`FROM mysql:8.0`, `FROM arcadedata/arcadedb:...` in their Dockerfiles), so those pins already reach the fingerprint through `dockerfile_instructions` and the provenance through `target_services`. Only a builder that pulls an image outside the compose build sets the field. Feed it into the two places the server image already reaches: the per-target fingerprint (so a moved backend pin moves only that target's fingerprint) and the holdout run provenance (so the recorded `image_ids` carries the backend image id beside the server services). The Doris fixture sets the field to its two pinned tags. Every other target keeps the default empty tuple, so its fingerprint and the whole acceptance baseline stay byte-for-byte unchanged.

The fingerprint append is conditional on a non-empty tuple, matching the two conditional appends already in `fixture_fingerprint` (the fallback scope under the fallback launch mode, the sentinel Dockerfile when a kept record is an http endpoint): an empty tuple appends nothing, so the serialized `parts` list of every backend-less target is identical to today's and hashes to the same value. The provenance lookup is a non-raising `docker image inspect` by exact tag (the identity tag function, not the `mcp-auditor-cve-` namespace), mirroring `nuisance_images.backend_image_ids`, merged into `HoldoutRunResult.image_ids` the way `5b3373a` merges into the nuisance recording.

## Files to modify

`evals/cve_targets.py`: add `backend_images: tuple[str, ...] = ()` to the `CVETarget` dataclass, placed with the other maintainer-set-from-calibration-or-fixture fields (after `fallback_scope`, the last defaulted field, so the new default needs no reordering), with a comment above the field that it names the raw external image tags the builder provisions, empty when the server needs no separate backend. No behaviour change: the field is pure data read by the fingerprint and the provenance. `tests/unit/test_holdout_kit_isolation.py::test_kit_target_mirrors_the_drawn_cve_target_fields` keeps passing as is: it asserts `KitTarget`'s fields are a subset of `CVETarget`'s, and the new field is left off the kit like `tools_filter`, `severity` and `note` (maintainer-set at transplant, not authored by the calibration agent).

`evals/holdout_kit/kit_target.py`: unchanged. `backend_images` stays off the kit, maintainer-set at transplant like `tools_filter` (settled, see the implementation step).

`evals/cve_baseline.py`: add `backend_image_ids(tags: Sequence[str]) -> dict[str, str]`, placed right below its sibling `image_ids` (newspaper rule: the two provenance lookups read together), that inspects each tag with `check=False` and keeps only the tags that resolve, so a provenance read never raises on a backend image that is not yet pulled (a twin of `nuisance_images.backend_image_ids`, differing only in that it is the holdout core's copy). Extend `fixture_fingerprint` to append `sorted(target.backend_images)` to `parts` only when the tuple is non-empty, after the existing fallback-scope append and before the sentinel append; extend the function's docstring to name the backend images among what the fingerprint covers. Do not touch `_ENVIRONMENT_PATHS` or the existing `image_ids`.

`evals/holdout_run.py`: add `backend_image_ids: Callable[[Sequence[str]], dict[str, str]]` to `HoldoutDeps`, right after `image_ids` and before `read_tree` (the dataclass is built positionally in `default_deps` and in `deps_reaching_nothing`, so the position is part of the contract: `HoldoutDeps(audit, check, layout, rebuild, image_ids, backend_image_ids, read_tree)`); import and wire `backend_image_ids` from `cve_baseline` in `default_deps`; in `_assemble_run`, merge the backend image ids into the recorded `image_ids` dict, `{**deps.image_ids(target_services(targets)), **deps.backend_image_ids(_backend_images(targets))}`; add `_backend_images(targets) -> list[str]` that deduplicates every target's `backend_images` (preserving order with `dict.fromkeys`), the twin of `nuisance_run._backend_images`, placed at the end of the module right below `target_services` (newspaper rule: the two helpers of `_assemble_run`'s provenance read together, under their caller, as in `nuisance_run`).

`evals/holdout_fixtures/cve_2025_66335_doris.py`: set `backend_images=(DORIS_IMAGE, MYSQL_CLIENT_IMAGE)` on `TARGET`, importing the two tags from `evals.doris_backend`. This requires making the MySQL client tag public (see below).

`evals/doris_backend.py`: rename the private `_MYSQL_CLIENT_IMAGE` to a public `MYSQL_CLIENT_IMAGE` (one constant, one reference in `_doris_sql`), so the fixture can name it as a pinned backend image. `DORIS_IMAGE` is already public.

`tests/unit/support/test_holdout_run_given.py`: add `backend_image_ids` to both `HoldoutDeps` fakes (`deps_auditing` returns `{tag: f"sha256:{tag}" for tag in tags}`, `deps_reaching_nothing` raises `AssertionError("the backend image ids were read")`), matching the shape `5b3373a` used for the nuisance given helpers.

`tests/unit/test_holdout_run.py`: add a test that a target carrying `backend_images` records them beside its services in `result.image_ids` (twin of `test_nuisance_run.test_a_backend_server_records_its_backend_image_beside_its_service`).

`tests/unit/support/test_cve_baseline_given.py`: add a `FINGERPRINTED_CHANGES` entry, `"backend images": _replacing(backend_images=("apache/doris:all-in-one-4.1.3",))`, so the parametrized test in `tests/unit/test_cve_baseline.py` asserts the fingerprint moves (no new test function). The no-drift invariant of the empty tuple is not a unit test but a one-off check in Verification: the committed acceptance baselines cannot anchor it, because their `fixture_fingerprint` values were recorded at `b036714` and the environment modules (`doris_backend` extraction, MySQL client pin) have moved every live fingerprint since, so a test comparing a live fingerprint to a committed baseline fails today, before this change.

`CHANGELOG.md`: the backend-image provenance and fingerprint on holdout targets go into the existing `python -m evals.run_holdout run` bullet under `[Unreleased]` / `Added` (the feature is itself unreleased, so there is no earlier behaviour to list under `Changed`), the way the nuisance `run` and `gate` bullets were amended in place for the backend fixture.

## Code details

`CVETarget` new field (after `fallback_scope`):

```python
# The raw external image tags the builder pulls outside the compose build, empty when the server
# needs no separate backend (a backend baked into the server image is covered by its Dockerfile).
backend_images: tuple[str, ...] = ()
```

(Ruff's line length is 100, so the comment goes above the field, not beside it.)

`cve_baseline.backend_image_ids`:

```python
def backend_image_ids(tags: Sequence[str]) -> dict[str, str]:
    # check=False, keeping the tags that resolve: a provenance lookup never raises. A target
    # dropped before launch never reaches assembly, so its backend image is never looked up.
    ids: dict[str, str] = {}
    for tag in tags:
        inspected = subprocess.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", tag],
            check=False, capture_output=True, text=True,
        )
        if inspected.returncode == 0:
            ids[tag] = inspected.stdout.strip()
    return ids
```

`fixture_fingerprint` conditional append (after the fallback-scope block):

```python
if target.backend_images:
    parts.append(sorted(target.backend_images))
```

`holdout_run._assemble_run` provenance:

```python
image_ids={
    **deps.image_ids(target_services(targets)),
    **deps.backend_image_ids(_backend_images(targets)),
},
```

`holdout_run._backend_images`:

```python
def _backend_images(targets: Sequence[CVETarget]) -> list[str]:
    return list(dict.fromkeys(tag for target in targets for tag in target.backend_images))
```

Doris fixture:

```python
from evals.doris_backend import DORIS_IMAGE, MYSQL_CLIENT_IMAGE
...
TARGET = CVETarget(
    ...,
    backend_images=(DORIS_IMAGE, MYSQL_CLIENT_IMAGE),
)
```

## What stays unchanged

`_ENVIRONMENT_PATHS` is not touched: moving it would move every target's fingerprint and reset the acceptance baseline. The backend pin is carried on the target and appended per target instead. The acceptance baseline files under `evals/baselines/cve/` are not re-recorded and not touched: every acceptance target keeps `backend_images=()`, so its `parts` list and its fingerprint are identical to today's. The acceptance CVE benchmark provenance path (`cve_session_recording`, `cve_session_model.image_ids`, `run_cve_benchmark`) is not wired for backend images: no acceptance target has a backend, so the wiring would be inert; it is left out of scope and noted here as the place to extend if an acceptance target ever gains a backend. `cve_baseline.image_ids` (the raising, namespaced lookup) is unchanged. `evals/holdout_conditions.json`, the grammar, the holdout report markdown (`holdout_markdown.py`, which does not render `image_ids`) and the holdout report model (`holdout_report.py`, which stores `image_ids` as an opaque dict) are unchanged. The nuisance `backend_image_ids` in `evals/nuisance_images.py` is left as it is; this plan does not touch the unpushed nuisance stack (the two copies are ten near-identical lines, an accepted duplication under the project's "three similar lines beat a premature abstraction" rule; a later de-duplication, if wanted, is its own change).

## Edge cases

A holdout run with no backend target: `_backend_images` returns `[]`, `backend_image_ids([])` returns `{}`, and the merged `image_ids` is exactly today's. A backend image not yet pulled at assembly time: `backend_image_ids` omits it rather than raising, so provenance degrades to naming only what resolved (in practice the Doris image is pulled by `ensure_doris` during the pre-run vet, well before `_assemble_run`, so it resolves). Two targets sharing one backend image: `_backend_images` deduplicates, so the tag appears once in `image_ids`. A target carrying `backend_images` but whose builder does not actually provision them: out of this plan's concern, the field is maintainer-set data like `kept_places`; the fingerprint and provenance simply reflect what the field says.

## Test scenarios

`fixture_fingerprint` moves with `backend_images`: a new `FINGERPRINTED_CHANGES` entry replaces the target's `backend_images` with a non-empty tuple and the parametrized test asserts the fingerprint differs from the untouched target. Expected: different hash.

An empty `backend_images` leaves the fingerprint unchanged: checked once by hand, not by a test (see Verification). Before touching `cve_baseline.py`, print `fixture_fingerprint(target, load_places(HOLDOUT_PLACES))` for every target of `CVE_TARGETS` (`evals.cve_targets`) and `HOLDOUT_TARGETS` (`evals.holdout_targets`, not `cve_targets`); after the change, print them again and diff: every target but CVE-2025-66335 must hash identically, and only CVE-2025-66335 moves. The committed acceptance baselines are not the reference for this check (they already differ from the live fingerprints, recorded at `b036714`).

The holdout run records the backend image beside the target's services: a target built from `a_target(...)` (the filesystem target by default, services `filesystem` and `filesystem-patched`) with `backend_images=("apache/doris:all-in-one-4.1.3",)` (or two tags), audited through `deps_auditing`, yields a `HoldoutRunResult` whose `image_ids` equals `{"filesystem": "sha256:filesystem", "filesystem-patched": "sha256:filesystem-patched", "apache/doris:all-in-one-4.1.3": "sha256:apache/doris:all-in-one-4.1.3"}` (both fakes key by the raw name they are given and prefix `sha256:`, neither namespaces). Expected: the backend tag key is present with its faked id. A backend-less target's `image_ids` is unchanged (no existing test in `tests/unit/test_holdout_run.py` asserts `image_ids`, so the merge's empty case is covered only by the existing run tests still passing through `deps_auditing`, whose `image_ids` fake they exercise; confirm they still pass).

`deps_reaching_nothing` proves the backend lookup is not reached when the run refuses up front (a tools filter, tracing, a target absent from the census, a dirty tree, an unknown kept place): its `backend_image_ids` raises, and the existing "refuses before any dep" tests must still pass. The case where no target survives the pre-run check (`test_every_target_dropped_refuses_with_the_reasons`) runs on `deps_auditing` and refuses before `_assemble_run`, so the lookup is not reached there either, by control flow rather than by a raising fake.

## Verification

Test-first: the `FINGERPRINTED_CHANGES` entry and the holdout run test are written and seen red (the entry fails on `dataclasses.replace` with an unknown field, and the run test, with it every test of `tests/unit/test_holdout_run.py` that builds a `HoldoutDeps` through the given helpers, errors on the `backend_image_ids` field `HoldoutDeps` does not have yet, the expected red of a positional dataclass gaining a field) before `CVETarget`, `cve_baseline` and `holdout_run` change. Short loop while implementing: `uv run pytest tests/unit -n auto --maxprocesses 4`, `uv run pyright` on the changed files from the repo root, `uv run ruff check .`. Closing check: `uv run pytest -n auto`, `uv run ruff check .`, `uv run pyright` with no file argument. The unit tests added here are Docker-free. The live Doris provenance (the real `docker image inspect` on `apache/doris:all-in-one-4.1.3`) is exercised only under a holdout calibration or run with Docker; a manual `uv run python -m evals.run_holdout calibrate --cve CVE-2025-66335` confirms the Doris target still calibrates with the field set, and is where the recorded backend image id would first be observed (calibration does not record provenance, but it exercises the launch path the provenance reads from). No eval baseline is recorded by this change, and no acceptance fingerprint moves: before the change, print `fixture_fingerprint(target, load_places(HOLDOUT_PLACES))` for every target of `CVE_TARGETS` and `HOLDOUT_TARGETS` (a short `uv run python -` snippet, Docker-free), print them again after, and confirm only CVE-2025-66335 moved. Note that the acceptance gate is already not comparable on fixture at HEAD (the committed baselines were recorded at `b036714`, before the `doris_backend` extraction and the MySQL client pin moved `cve_environments.py`), a pre-existing state this change neither causes nor repairs: the invariant to hold is that this change moves no acceptance fingerprint, not that the gate reads comparable.

## Decisions settled

Both backend images, not the serving one only: this plan records `(DORIS_IMAGE, MYSQL_CLIENT_IMAGE)`, treating both pinned external images as provenance (Doris serves the fetch, the MySQL client seeds the schema, both float if unpinned). Recording only `DORIS_IMAGE` (the backend that serves at audit time, closer to the nuisance single-image `BackendFixture.image`) was rejected: completeness is cheap and the MySQL client's float would otherwise go unrecorded.

Tuple, not a single field: `backend_images: tuple[str, ...]` is chosen over a single `backend_image: str | None` because Doris genuinely pins two external images and a future backend target may pin more; the tuple also keeps the fingerprint append a clean sorted list. The single-field shape would be a tighter nuisance mirror but cannot hold the two Doris tags.

Field off the kit, no holdout-log entry: `backend_images` stays maintainer-set at transplant (left off `KitTarget` and `_DRAWN_TARGET_FIELDS`, like `tools_filter`/`severity`/`note`), and this change adds no `docs/holdout-log.md` entry, consistent with the recent Doris holdout commits that carry none.

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites, written for the passes that run after the plan is broken into steps (the implementation-phase fact check reads it). No pass may treat a line here as a reason to skip a verification: the record says what was concluded once, on 2026-10-26, not what is true now. A human who edits the corresponding fact by hand deletes its line rather than updating it, so this section never asserts something nobody checked.

- SETTLED: `apache/doris:all-in-one-4.1.3` (verified against the Docker Hub tag record of `apache/doris`, tag active, last updated 2026-09-11; the newest `all-in-one` tag apart from its `-full` variant; present locally under `docker image inspect`)
- SETTLED: `mysql:8.0.46` (verified against the Docker Hub tag record of `library/mysql`, tag active, last updated 2026-05-05; the newest `8.0.NN` patch tag on that date; present locally under `docker image inspect`)
- SETTLED: `docker image inspect --format {{.Id}} <tag>` with `check=False` (verified against the in-repo twin `evals/nuisance_images.backend_image_ids`, commit `5b3373a`, and the raising sibling `evals/cve_baseline.image_ids`, both already in use)
- SETTLED: the committed acceptance baselines' `fixture_fingerprint` values differ from the live ones at HEAD for all four acceptance targets (verified by computing `fixture_fingerprint` for every target of `CVE_TARGETS` and `HOLDOUT_TARGETS` against `evals/baselines/cve/`, recorded at `b036714`), so the plan's choice of a before/after diff rather than a baseline comparison for the no-drift check stands

## Implementation steps

### Step 1: Carry, fingerprint and record the backend images a holdout target pins

A single atomic commit that mirrors `5b3373a` on the holdout side: add the per-target field, feed it into the fingerprint and the run provenance, set it on the Doris fixture, and pin all of it with tests. Follow the project's test-first workflow: write the two red tests first, confirm they fail, then make them pass.

**Files**

Tests and fixtures (write first):
- `tests/unit/support/test_cve_baseline_given.py` (modify): add the `FINGERPRINTED_CHANGES` entry.
- `tests/unit/test_holdout_run.py` (modify): add the backend-image recording test.
- `tests/unit/support/test_holdout_run_given.py` (modify): add `backend_image_ids` to both `HoldoutDeps` fakes.

Production code:
- `evals/cve_targets.py` (modify): add the `backend_images` field to `CVETarget`.
- `evals/doris_backend.py` (modify): make the MySQL client tag public.
- `evals/cve_baseline.py` (modify): add `backend_image_ids`, extend `fixture_fingerprint`.
- `evals/holdout_run.py` (modify): add the dep, wire it, add `_backend_images`.
- `evals/holdout_fixtures/cve_2025_66335_doris.py` (modify): set `backend_images` on `TARGET`.
- `CHANGELOG.md` (modify): amend the `run_holdout run` bullet under `[Unreleased]` / `Added`.

**Do** (in this order)

1. Read the twins first so the mirror is exact: `evals/nuisance_images.py` (`backend_image_ids`), `evals/nuisance_run.py` (`_backend_images`, the provenance merge), and the nuisance given helper and run test that `5b3373a` added, to copy their shape.

2. Red tests first:
   - In `tests/unit/support/test_cve_baseline_given.py`, add a `FINGERPRINTED_CHANGES` entry `"backend images": _replacing(backend_images=("apache/doris:all-in-one-4.1.3",))`. It fails on `dataclasses.replace` with an unknown field until `CVETarget` gains the field.
   - In `tests/unit/test_holdout_run.py`, add a test: a target from `a_target(...)` (filesystem default, services `filesystem` / `filesystem-patched`) carrying `backend_images=("apache/doris:all-in-one-4.1.3",)`, audited through `deps_auditing`, yields a `HoldoutRunResult` whose `image_ids` equals `{"filesystem": "sha256:filesystem", "filesystem-patched": "sha256:filesystem-patched", "apache/doris:all-in-one-4.1.3": "sha256:apache/doris:all-in-one-4.1.3"}`. Twin of `test_nuisance_run.test_a_backend_server_records_its_backend_image_beside_its_service`. Fails on the missing `backend_image_ids` dep.
   - In `tests/unit/support/test_holdout_run_given.py`, add `backend_image_ids` to both fakes: `deps_auditing` returns `{tag: f"sha256:{tag}" for tag in tags}`; `deps_reaching_nothing` raises `AssertionError("the backend image ids were read")`. `HoldoutDeps` is built positionally, so insert the arg in position: `HoldoutDeps(audit, check, layout, rebuild, image_ids, backend_image_ids, read_tree)`.
   - Run `uv run pytest tests/unit/test_cve_baseline.py tests/unit/test_holdout_run.py -n auto --maxprocesses 4` and confirm the red: the new `FINGERPRINTED_CHANGES` case fails on the unknown field, and the whole of `test_holdout_run.py` errors on the `HoldoutDeps` field the given helpers now pass (positional dataclass, so every test that builds deps goes red until the field exists).

3. Production code:
   - `evals/cve_targets.py`: add after `fallback_scope`, comment above the field (ruff line length 100):
     ```python
     # The raw external image tags the builder pulls outside the compose build, empty when the server
     # needs no separate backend (a backend baked into the server image is covered by its Dockerfile).
     backend_images: tuple[str, ...] = ()
     ```
   - `evals/doris_backend.py`: rename `_MYSQL_CLIENT_IMAGE` to public `MYSQL_CLIENT_IMAGE` (one constant, one reference in `_doris_sql`). `DORIS_IMAGE` is already public.
   - `evals/cve_baseline.py`: add `backend_image_ids(tags: Sequence[str]) -> dict[str, str]` directly below `image_ids` (newspaper rule), `docker image inspect --format {{.Id}}` per tag with `check=False`, keeping only tags whose `returncode == 0` (see the plan's Code details snippet). In `fixture_fingerprint`, append `sorted(target.backend_images)` to `parts` only when the tuple is non-empty, after the fallback-scope append and before the sentinel append; extend the docstring to name the backend images. Do not touch `_ENVIRONMENT_PATHS` or the existing `image_ids`.
   - `evals/holdout_run.py`: add `backend_image_ids: Callable[[Sequence[str]], dict[str, str]]` to `HoldoutDeps` right after `image_ids` and before `read_tree`; wire it from `cve_baseline` in `default_deps` (and keep `deps_reaching_nothing` positional); in `_assemble_run` merge `{**deps.image_ids(target_services(targets)), **deps.backend_image_ids(_backend_images(targets))}`; add `_backend_images(targets) -> list[str]` using `dict.fromkeys`, placed at the end of the module right below `target_services`.
   - `evals/holdout_fixtures/cve_2025_66335_doris.py`: `from evals.doris_backend import DORIS_IMAGE, MYSQL_CLIENT_IMAGE` and set `backend_images=(DORIS_IMAGE, MYSQL_CLIENT_IMAGE)` on `TARGET`.
   - `CHANGELOG.md`: amend the existing `python -m evals.run_holdout run` bullet under `[Unreleased]` / `Added` to mention the backend-image provenance and fingerprint (in place, like the nuisance `run`/`gate` bullets were amended).

4. Decisions already settled by the plan (do not reopen): `KitTarget` and `_DRAWN_TARGET_FIELDS` stay as they are (`backend_images` is maintainer-set at transplant, left off the kit like `tools_filter`/`severity`/`note`); no `docs/holdout-log.md` entry is added. Record nothing in `docs/adr/` or `plans/`.

**Test**

- `FINGERPRINTED_CHANGES` entry: the parametrized test in `tests/unit/test_cve_baseline.py` asserts the fingerprint of the target with a non-empty `backend_images` differs from the untouched target. Expected: different hash.
- Holdout run recording: `image_ids` carries the backend tag key `"apache/doris:all-in-one-4.1.3"` with its faked id `"sha256:apache/doris:all-in-one-4.1.3"` beside the two service keys. Expected: key present.
- Backend-less path unchanged: the existing run tests (which exercise `deps_auditing` with no `backend_images`) still pass, covering the empty-merge case; `_backend_images([])` -> `[]`, `backend_image_ids([])` -> `{}`.
- `deps_reaching_nothing`: its `backend_image_ids` raising proves the lookup is not reached when the run refuses up front; the existing "refuses before any dep" tests must still pass. The "no target survived" test runs on `deps_auditing` and refuses before `_assemble_run`.

**Verify**

- No-drift hand check (not a unit test): before changing `cve_baseline.py`, run a short Docker-free `uv run python -` snippet printing `fixture_fingerprint(target, load_places(HOLDOUT_PLACES))` for every target of `CVE_TARGETS` and `HOLDOUT_TARGETS`; after the change, print again and diff. Expected: only `CVE-2025-66335` moves; every other target hashes identically. The committed acceptance baselines are not the reference (they already differ from live, recorded at `b036714`).
- Short loop while implementing: `uv run pytest tests/unit -n auto --maxprocesses 4`, `uv run pyright <changed files>` from the repo root, `uv run ruff check .`.
- Closing check (run with no file argument): `uv run pytest -n auto`, `uv run ruff check .`, `uv run pyright`. Expected: all green. The added unit tests are Docker-free.
- Optional live confirmation (Docker, not part of the commit gate): `uv run python -m evals.run_holdout calibrate --cve CVE-2025-66335` still calibrates with the field set.
