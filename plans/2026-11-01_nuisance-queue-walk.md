# Nuisance queue walk

## Context

The nuisance rule (`docs/nuisance-rule.md`, Eligibility, "The walk") lets servers enter the figure only through flaws of the salted draw order, and the log entry of 2026-10-29 records an addition that resumes the walk past the holdout walk and runs to the end of the order, sized at 43 servers. Batches 6 and 7 admitted 25 servers first reached at draw positions 87 to 186 on that addition. The code does not know about it: `nuisance_walk.nuisance_population` follows `census.draw.walk` only, the 86 frozen steps of the holdout draw. Three consequences:

1. `run_nuisance walk` lists none of the 25 queue servers, and nothing checks that an admitted server was reached by the walk. `nuisance_population.run_population` audits every admitted server that carries no mark, so a server admitted by mistake (a misspelled package, a duplicate) would enter N silently.
2. Server identity. `server_of` reads the first classifier only and normalizes PyPI names only. In the queue, one server appears under two labels (`Go:github.com/googleapis/mcp-toolbox` at position 107 and `https://github.com/googleapis/mcp-toolbox` at 119), `PyPI:kubectl-mcp-tool` (position 106) is the same project as `PyPI:kubectl-mcp-server` (reached earlier, logged a duplicate on 2026-10-31), and the two classifiers name different packages for three queue flaws (CVE-2026-19337 npm against https, CVE-2025-66689 zen against pal, CVE-2026-34884 Go against https).
3. Criterion settlements. The rule requires that a flaw the holdout walk has not reached have its classifier disagreements settled before the walk takes it, and skipped if it then fails the draw-order criteria. 28 flaws of positions 87 to 186 carry a disagreement on a criterion (mostly `effect_in_tool_response` and `pinnable`, three on `grammar_class`, two on `stdio_tools_call`), and none is settled. The code reads a disagreement as met when either classifier says so.

The holdout draw record inside `evals/holdout_census.json` is a pre-registered artifact and stays frozen. The queue settlements must still bind the holdout: a future holdout addition that walks past position 86 meets these same flaws, and must not settle them the other way.

## Decisions (taken with the maintainer)

- The queue record lives in its own file, `evals/nuisance_walk_record.json`. `evals/holdout_census.json` does not change.
- The 31 criterion settlements (on 28 flaws: 17 `effect_in_tool_response`, 9 `pinnable`, 3 `grammar_class`, 2 `stdio_tools_call`) and the identity settlements are written in this plan, as a maintainer step done by hand, and committed on their own after review.
- An admitted server the walk does not reach, other than an acceptance server, makes `admission_problems` fail, so `load_admission` and every command that loads the admission refuse.
- The batch-7 log entry that says "positions 79 to 102" (the batch folder numbers, the positions are 131 to 182) is corrected by a new dated log entry. The same slip in `CHANGELOG.md` `[Unreleased]` is corrected in place, the CHANGELOG being a living doc.

## Approach

A new record, read beside the census, carries three things: the addition (its size and the date it was logged), the criterion settlements of the flaws past the holdout walk, and the identity settlements (flaw to server package). A value object pairs the census and the record, and the walk functions take it in place of the bare census. The walk follows the holdout walk as today, then continues in draw order over every draw-order flaw the holdout walk has not reached, skipping a flaw that fails the draw-order criteria once its settlements apply. The admission check then compares the admitted servers with the walk's population and enforces the addition's size.

No rule version opens: the rule already says all of this, the code catches up with it.

## Files

### New: `evals/nuisance_walk_record.py`

Schema, loading and validation of the record. Pure functions apart from `load_walk_record`.

```python
class Addition(BaseModel):
    logged_on: date
    size: int


class IdentitySettlement(BaseModel):
    flaw: str
    server_package: str
    reason: str


class NuisanceWalkRecord(BaseModel):
    rule_commit: str
    addition: Addition
    settlements: list[Settlement]  # evals.census_draw.Settlement, reused
    identities: list[IdentitySettlement]


@dataclass(frozen=True)
class NuisanceCensus:
    census: HoldoutCensus
    record: NuisanceWalkRecord


def load_walk_record(path: Path, census: HoldoutCensus) -> NuisanceCensus: ...
def walk_record_problems(nuisance_census: NuisanceCensus) -> list[str]: ...
```

The module imports nothing from `nuisance_walk`, which imports `NuisanceCensus` from it: an import the other way is a cycle that fails at import time. `walk_record_problems` needs `reached_identifiers` (holdout-walked flaws) and `normalized_package` (identity disagreements), so these two functions move here unchanged in signature, and `nuisance_walk`, `nuisance_dossier` and `tests/unit/test_nuisance_walk.py` import them from here. The queue flaws the completeness check reads are `holdout_draw.draw_order(census)` minus `reached_identifiers(census)`, computed here, with no call into `nuisance_walk`.

One `addition`, not a list: a later addition needs a census extension first (log entry of 2026-10-29, reading of the stopping clause) and will change the schema then.

`walk_record_problems` refuses:

- a settlement or identity on a flaw that is not a draw-order candidate of the census (identities: not a census flaw).
- two settlements on one (flaw, criterion), two identities on one flaw.
- a settlement that contradicts a draw settlement on the same flaw and criterion. This check alone is what binds the holdout: if a later holdout addition writes a draw settlement on a queue flaw with the other verdict, loading the record fails, and the real-data test below fails in CI. A record settlement on a flaw the holdout walk has reached is allowed as long as it agrees (decided by the maintainer at diligence): when the holdout resumes past position 86, it copies the record's verdicts into its draw record, and nothing in the record has to move or be pruned. Today no record settlement sits on a holdout-reached flaw, since the record only settles queue flaws.
- completeness, the rule's "settled first": every flaw the queue walk reaches whose classifiers disagree on a `Criterion` (compared through `criteria_met`) needs a settlement for that criterion, and every one whose classifiers name different normalized packages needs an identity. A flaw the walk skips is still reached, so it needs its settlements too (the skip is decided from them).
- `addition.size` below 1.

`load_walk_record` raises `FileNotFoundError` when the file is absent and `ValueError` listing the problems, mirroring `load_admission`.

### New: `evals/nuisance_walk_record.json`

Written in the maintainer step (see Steps). Shape:

```json
{
  "rule_commit": "<commit of the current rule version in the log>",
  "addition": {"logged_on": "2026-10-29", "size": 43},
  "settlements": [{"flaw": "...", "criterion": "pinnable", "verdict": true, "reason": "..."}],
  "identities": [{"flaw": "CVE-2026-14538", "server_package": "Go:github.com/googleapis/mcp-toolbox", "reason": "..."}]
}
```

### `evals/nuisance_walk.py`

Every public function that takes `census: HoldoutCensus` and depends on the walk or on server identity takes `NuisanceCensus` instead: `server_of`, `census_flaws_of`, `version_setting_flaws`, `acceptance_servers`, `current_acceptance_servers`, `nuisance_population`. `reached_identifiers` and `normalized_package` keep their signatures and move to `nuisance_walk_record.py` (see above).

- `server_of(identifier, nuisance_census)`: an identity settlement on the flaw wins, otherwise the first classifier's normalized package, as today.
- `_settlement(flaw, nuisance_census, criterion)`: looks in the draw settlements, then in the record's settlements. `_sets_version` and `_tools_reached` are unchanged otherwise.
- `nuisance_population(nuisance_census) -> list[NuisanceServer]`: first the holdout walk's identifiers as today (every reached identifier, whatever its outcome), then the queue: the draw order (`holdout_draw.draw_order`) filtered to the identifiers the holdout walk has not reached, in order, keeping a flaw only when it meets the draw-order criteria with settlements applied (`DRAW_ORDER_CRITERIA` of `census_grouping`, each read with `_met`, the classifier side being `any(criteria_met(c)[criterion] for c in seen)`). `census_grouping._DRAW_ORDER_CRITERIA` is renamed `DRAW_ORDER_CRITERIA` (its one use in `in_draw_order` follows): pyright strict reports an import of a private name from another module (`reportPrivateUsage`), and copying the tuple would let the two lists drift. The holdout walk is not a prefix of the draw order in sequence (calibration reordered it), only as a set (positions 1-86), so the queue is filtered by set membership, never sliced at 86. A server first reached in the queue carries `in_addition=True`.
- `NuisanceServer` gains `reaching_position: int` (1-based position of the reaching flaw in the draw order) and `in_addition: bool`. The position lets the admission check order the addition's entries and lets the walk command print it.

The draw-order criteria are re-read per flaw with `_met` rather than by calling `census_grouping.in_draw_order`, because that function reads classifiers only. If the module passes 300 lines, the queue part (`_queue_identifiers` and its helpers) moves to `evals/nuisance_queue.py`.

### `evals/nuisance_admission.py`

- `load_admission(path, nuisance_census)` and `admission_problems(admission, nuisance_census, grammar_fingerprint, backends)` take `NuisanceCensus`.
- `_foreign_flaws` uses the new `census_flaws_of`. Its `server_package` settlements path (`_settled_to_server`) stays: it is what the admission records, and the googleapis entries keep passing either way.
- New `_walk_problems(admission, nuisance_census) -> list[str]`:
  - every admitted server that is not an acceptance server (`acceptance_servers`) is in `nuisance_population` (by `server_package`), else `"<package>: not reached by the walk"`.
  - its `reaching_flaw` equals the population's reaching flaw for that server, else a problem naming both. This catches an admission that recorded the wrong reaching flaw after the identity merges.
  - the addition's size: the admitted servers that entered through the addition (`in_addition`, no mark, `standing_exit` is `None`), sorted by `reaching_position`. Past `addition.size` of them, each further one is a problem: the walk had stopped before reaching it. Today 25 entered, under 43, so this never fires on the real data.

`standing_exit` lives in `nuisance_population.py`, which imports `nuisance_admission`. To avoid the cycle, move `standing_exit` into `nuisance_admission.py` (it reads `AdmittedServer` only) and import it from there in `nuisance_population.py` and `nuisance_gate_session.py`.

`nuisance_admission.py` is at 259 lines today, and `_walk_problems` plus `standing_exit` bring it near 300. If it passes 300 lines, `_walk_problems` and its helpers move to `evals/nuisance_admission_walk.py` (it imports `standing_exit` and `AdmittedServer` from `nuisance_admission`, and `admission_problems` calls it).

### `evals/nuisance_population.py`

`run_population(walked, admission, acceptance)` is unchanged in signature and behavior. Its caller passes the extended population.

### `evals/nuisance_commands.py`

- `WALK_RECORD_PATH = REPO_ROOT / "evals" / "nuisance_walk_record.json"`.
- New `committed_nuisance_census(census_path, record_path) -> NuisanceCensus`, loading the census and the record. Every subcommand that takes `--census` (walk, nuisance-dossier, run, calibrate, gate) gains `--walk-record` (default `WALK_RECORD_PATH`): the unit tests run the commands on fixture censuses, and once the committed record holds settlements (implementation step 5) it fails `walk_record_problems` against any fixture census (settlements on flaws it does not have), so every CLI test passes a fixture record. An absent record is a `Refused` ("the nuisance walk record is not committed"), not a crash: every nuisance command needs it. `malformed_input_refused` message becomes "the census, the walk record or the admission is malformed."
- `committed_admission(path, nuisance_census)`.

### `evals/run_nuisance.py`, `evals/nuisance_gate_command.py`, `evals/nuisance_calibrate_command.py`, `evals/nuisance_dossier.py`

Each loads through `committed_nuisance_census` and passes `NuisanceCensus` on.
Provenance (decided by the maintainer at the final review, in this plan, step 4b): the run result records `census_commit = last_commit(args.census)` only, and once the record decides the population (identities, settlements, the queue), a record edit changes which servers a run audits without moving that commit. `run_nuisance run` therefore also records `walk_record_commit = last_commit(args.walk_record)`, a provenance field beside `census_commit`, not a condition: it flows through `nuisance_run.run_nuisance` (`_RunContext`), `nuisance_results` (the run result model), `nuisance_report` (the report model and `build_report`) and the markdown line that prints the census commit. The gate records no census commit today and is left as it is.
 `write_dossier` passes it to `census_flaws_of`, so a googleapis dossier would carry the https-labelled flaws too.

`_walk` prints, per server, the draw position of its reaching flaw, `(addition)` for a queue server, and the holdout outcome for a holdout-walk one, then a closing line: `"<k> of <size> servers of the addition admitted and in the figure"`. The admission is optional for this line: when none is committed, the line is left out. `walk` takes no `--admission` today, so it gains one (default `ADMISSION_PATH`) and loads it through `committed_admission` inside `malformed_input_refused`. The existing walk tests then pass a missing admission path: with the default, the committed admission would be checked against the fixture census and refused. `walk` still needs no LLM and no network.

### `tests/`

- `tests/unit/test_nuisance_walk_record.py` (+ `_given.py`, `_then.py` where they abstract something): the refusals listed above, one test each, on a small fixture census.
- `tests/unit/test_nuisance_walk.py`: existing tests take a `NuisanceCensus` built by a given helper (record with no settlement or identity). New cases below.
- `tests/unit/test_nuisance_admission.py`: the walk cases below (scenario 7), driven through the public `admission_problems`, never by calling `_walk_problems` directly.
- `tests/unit/test_nuisance_walk_record_loads.py`: loads the committed record against the committed census (mirrors `test_nuisance_admission_loads.py`), added with the data. This is the binding test.
- `tests/unit/test_nuisance_admission_loads.py` and `test_nuisance_fix_checks.py`: load through `NuisanceCensus`.
- Every other test that calls a changed signature is updated (`test_run_nuisance.py`, its given, `test_nuisance_population.py` and `support/test_nuisance_run_given.py` which build `NuisanceServer` and gain its two fields, `test_nuisance_images.py` which calls `admission_problems`, `test_nuisance_dossier.py`, gate tests). `support/test_run_nuisance_run_given.a_run_reaching_nothing` monkeypatches `run_nuisance.load_census`: once `run_nuisance` loads through `committed_nuisance_census`, that name may no longer be imported there and `setattr` raises, so the patched name follows the new loader. Every CLI test passes `--walk-record` with a fixture record.

## What stays unchanged

- `evals/holdout_census.json`, its draw record, `census_draw.py`, `holdout_draw.py`: not edited. `census_grouping.py`: only the rename of `_DRAW_ORDER_CRITERIA` to `DRAW_ORDER_CRITERIA`, no behavior change.
- `docs/nuisance-rule.md`: no new version, no text change. The three dfie points waiting for the next rule contact are out of scope.
- `run_population`, the counter, the statistic, the report, the gate's logic, the fix-check modules, every Dockerfile and compose service.
- `evals/nuisance_admission.json` content: no server added or removed. If the new checks find a real defect in it, stop and report to the maintainer rather than editing it on the fly.
- The holdout run and its commands.

## Edge cases

- A queue flaw whose settlement turns a draw-order criterion false: skipped, its server is not reached through it. If no later flaw reaches the server and the server is admitted, `_walk_problems` fires.
- A queue flaw whose server the holdout walk already reached (e.g. flyto-core at 89): adds nothing, as today with repeated servers.
- An identity merging a queue label into a server reached at 1-86 (kubectl-mcp-tool into kubectl-mcp-server): the server keeps its earlier reaching flaw, no new server.
- The ContextForge sandbox (`https://github.com/IBM/mcp-context-forge`, CVE-2026-53710) is its own server, reached at 1-86. No identity merges it into the gateway.
- Identity settlements also apply to flaws at positions 1-86 if any names one. None does today, and the real-data test pins that the 1-86 part of the population is unchanged (52 servers, same packages).
- Flaws outside the draw order (no draw identifier, or failing the criteria before settlement) are never reached, as today. A settlement on one is refused.
- An admitted acceptance server outside the walk: allowed, as today.

## Test scenarios

On fixture censuses (no real data), Given/When/Then:

1. Population continues past the holdout walk: census whose draw order has 4 flaws, holdout walk on the first 2; population lists the servers of all 4 in order, the last two `in_addition=True` with positions 3 and 4.
2. A queue flaw failing a draw-order criterion after its settlement (classifier A `effect_in_tool_response` true, B false, settlement false) is skipped; its server is absent if nothing else reaches it.
3. Same disagreement settled true: the flaw reaches its server.
4. Identity settlement merges two labels into one server; the merged flaws appear in its `flaws` and `version_setting`.
5. A queue settlement on `grammar_class` false removes the flaw from `version_setting` (via `_sets_version`).
6. Record refusals: settlement on a non-candidate; duplicate; contradiction with a draw settlement (fixture where the draw settles a flaw the holdout walked and the record settles it the other way). Record acceptance: the same fixture with the record's verdict agreeing with the draw's loads without problem (the holdout-resume case). Further refusals: missing settlement for a reached queue flaw with a disagreement; missing identity for a package disagreement; size 0.
7. Admission: an admitted non-acceptance server absent from the population is refused; an admitted acceptance server outside the walk passes; a wrong `reaching_flaw` is refused; with `size=1` and two admitted queue servers entering, the second by position is refused; a queue server with a standing exit (not over stdio) does not count toward the size.
8. `run_nuisance walk` on a fixture census prints the addition marker and the count line (existing CLI test pattern in `test_run_nuisance.py`).

On the committed data (added with the maintainer step):

9. `load_walk_record` on the committed files passes, `load_admission` passes.
10. Population sanity: the 1-86 part is the 52 servers of today; the googleapis https label is not a separate server; `PyPI:kubectl-mcp-tool` is not a separate server; the 25 queue servers of batches 6 and 7 are reached with `in_addition=True`.

## Steps outline (refined by the breakdown pass)

This outline predates `## Implementation steps` below, which supersede it: its step 2 is implementation steps 2 to 4, its step 3 is implementation step 5, its step 4 is implementation step 6.

1. Record module, schema and refusals (tests first), and the `NuisanceCensus` value object.
2. Walk, admission and command changes (tests first), signature migration across callers and tests, `standing_exit` move. This step commits a minimal `evals/nuisance_walk_record.json` (the addition, no settlement, no identity), so the real-data tests that load the admission stay green. The completeness refusal is not in this step: with it, the minimal record would fail to load.
3. Maintainer step, done by hand by the assistant, not dispatched to an implementer: fill `evals/nuisance_walk_record.json` with the identity settlements and the 31 criterion settlements (28 flaws), each with its reason, read from the advisory records of the census sources and the pages they link, and for an admitted server from its admission record (fix-check and patched version show the effect in a tool response and the version pinned). Then add the completeness refusal with its tests (scenario 6, last two cases) and the real-data tests 9 and 10. Run the full checks. Present the settlements to the maintainer for review before any commit. If the model's classifier cuts the advisory reading, switch to Opus 4.8.
4. Docs: `docs/nuisance-log.md` entries (the queue record committed with its counts of settlements and identities, the kubectl-mcp-tool and googleapis merges as identity settlements, the correction of "positions 79 to 102" to 131 to 182); a `docs/holdout-log.md` entry stating that the criterion settlements of `evals/nuisance_walk_record.json` bind a later holdout walk past position 86: the holdout copies those verdicts into its draw record when it reaches the flaws, and loading refuses a contradicting draw settlement; `CHANGELOG.md` `[Unreleased]` (walk command prints the queue; the "79 to 102" slip fixed in place); `CLAUDE.md` Commands line for `run_nuisance walk`; `CONTRIBUTING.md` walk paragraph (the queue, the new `--walk-record` and walk `--admission` flags, the record as a prerequisite of every nuisance command, "the census or the admission is malformed" becoming "the census, the walk record or the admission"); `README.md` only if it describes the walk's extent.

Commits: the code in one or more `feat(evals)` commits, the record data in its own commit, the docs and log in their own, each after the maintainer's go on the diff.

## Verification

```bash
uv run pytest tests/unit -n auto --maxprocesses 4
uv run pytest -n auto
uv run ruff check .
uv run ruff format .
uv run pyright
uv run python -m evals.run_nuisance walk     # lists the queue servers, "(addition)", count line "25 of 43"
uv run python -m evals.run_nuisance calibrate --cve CVE-2026-61462   # still loads the admission (Docker)
```

## Due diligence record

What the plan-diligence pass concluded about the external facts this plan cites or defers, kept so that the implementation-phase fact check can read it after `/clear`. No pass may treat a line here as a reason to skip a verification: the record says what was concluded once, not what is true now. A human who edits the corresponding fact by hand deletes its line rather than updating it, so this section never asserts something nobody checked.

- No cited external fact to verify: every package label, position and count the plan names is census or admission data of the repository (checked locally: draw order 186 flaws, holdout walk 86, population 52 servers, 59 admitted of which 25 lie outside today's population).
- OPEN (deferred): the 31 criterion settlements on 28 queue flaws (`effect_in_tool_response`, `pinnable`, `grammar_class`, `stdio_tools_call`) and their reasons, left to step 3 to read from the advisory records and the pages they link, so none is settled by this pass.
- OPEN (deferred): the identity settlements beyond the two the plan names (googleapis/mcp-toolbox Go module and repository, kubectl-mcp-tool into kubectl-mcp-server), including the three package disagreements (CVE-2026-19337, CVE-2025-66689, CVE-2026-34884), whose `server_package` values step 3 decides from the sources.

## Implementation steps

Each step closes with `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format .` and `uv run pyright` (no file argument), all green. In the loop: `uv run pytest tests/unit -n auto --maxprocesses 4` and `uv run pyright <changed files>`.

### Step 1: Walk record module and `NuisanceCensus`

- **Files**:
  - create `tests/unit/test_nuisance_walk_record.py`, `tests/unit/support/test_nuisance_walk_record_given.py` (and a `_then.py` only if an assertion abstracts something)
  - create `evals/nuisance_walk_record.py`
  - modify `evals/nuisance_walk.py`, `evals/nuisance_dossier.py`, `tests/unit/test_nuisance_walk.py` (imports only)
- **Do**:
  - Tests first, on a small fixture census built with the helpers of `tests/unit/support/test_nuisance_walk_given.py` (`a_census_walking`, `with_a_settlement`), reused from the new given rather than copied.
  - In `evals/nuisance_walk_record.py`: `Addition`, `IdentitySettlement`, `NuisanceWalkRecord` (Pydantic, `settlements: list[Settlement]` reusing `evals.census_draw.Settlement`), the frozen dataclass `NuisanceCensus(census, record)`, `load_walk_record(path, census) -> NuisanceCensus` (`FileNotFoundError` when absent, `ValueError` joining the problems, mirroring `load_admission`), `walk_record_problems(nuisance_census) -> list[str]`.
  - Move `reached_identifiers` and `normalized_package` unchanged from `nuisance_walk.py` into this module. `nuisance_walk`, `nuisance_dossier` and `tests/unit/test_nuisance_walk.py` import them from here. This module imports nothing from `nuisance_walk` (cycle).
  - `walk_record_problems` refuses, in this step: a settlement on a flaw that is not a draw-order candidate (`holdout_draw.draw_order(census)` identifiers), an identity on a flaw that is not a census flaw, two settlements on one (flaw, criterion), two identities on one flaw, a settlement contradicting a draw settlement on the same flaw and criterion (an agreeing one on a holdout-reached flaw is accepted; a census whose `draw` is `None` has no draw settlement to contradict, so this check finds nothing there rather than raising: the CLI tests of step 2 load records against draw-less fixture censuses), `addition.size` below 1. The completeness refusal is NOT in this step (step 5).
- **Test** (scenario 6 minus the two completeness cases):
  - record with a settlement on a non-candidate flaw: one problem naming it.
  - identity on a non-census flaw: one problem.
  - duplicate settlement (same flaw and criterion): problem. Duplicate identity: problem.
  - draw settles a holdout-walked flaw `pinnable=True`, record settles it `False`: problem. Same with `True`: no problem.
  - `size=0`: problem.
  - empty record (no settlement, no identity, size 1) on the fixture census: no problem.
  - `load_walk_record` on a missing path raises `FileNotFoundError`, on a file with a problem raises `ValueError` carrying it (written to `tmp_path`).
- **Verify**: new tests red first, then green. Full checks green (no behavior change elsewhere).

### Step 2: Thread `NuisanceCensus` through every nuisance caller

Mechanical migration, no new behavior: the walk still reads the holdout walk only.

- **Files**:
  - modify tests: `tests/unit/support/test_nuisance_walk_given.py` (a `NuisanceCensus` builder with an empty record), `tests/unit/test_nuisance_walk.py`, `tests/unit/support/test_nuisance_admission_given.py`, `tests/unit/test_nuisance_admission.py`, `tests/unit/test_nuisance_admission_loads.py`, `tests/unit/test_nuisance_fix_checks.py`, `tests/unit/test_nuisance_images.py`, `tests/unit/test_nuisance_dossier.py`, `tests/unit/support/test_run_nuisance_given.py`, `tests/unit/test_run_nuisance.py`, `tests/unit/support/test_run_nuisance_run_given.py`
  - create `evals/nuisance_walk_record.json`
  - modify `evals/nuisance_walk.py`, `evals/nuisance_admission.py`, `evals/nuisance_commands.py`, `evals/run_nuisance.py`, `evals/nuisance_gate_command.py`, `evals/nuisance_calibrate_command.py`, `evals/nuisance_dossier.py`
- **Do**:
  - `evals/nuisance_walk_record.json`: the minimal record, `{"rule_commit": <commit of the current rule version, read from docs/nuisance-log.md>, "addition": {"logged_on": "2026-10-29", "size": 43}, "settlements": [], "identities": []}`.
  - `nuisance_walk.py`: `server_of`, `census_flaws_of`, `version_setting_flaws`, `acceptance_servers`, `current_acceptance_servers`, `nuisance_population` take `nuisance_census: NuisanceCensus` and read `nuisance_census.census`. The private helpers follow. Behavior unchanged.
  - `nuisance_admission.py`: `load_admission(path, nuisance_census)`, `admission_problems(admission, nuisance_census, grammar_fingerprint, backends)`, `_foreign_flaws` through the new `census_flaws_of` (`_settled_to_server` stays).
  - `nuisance_commands.py`: `WALK_RECORD_PATH`, `committed_nuisance_census(census_path, record_path) -> NuisanceCensus` (absent record raises `Refused("Refused: the nuisance walk record is not committed.", ...)`), `committed_admission(path, nuisance_census)`, the `malformed_input_refused` message becomes "the census, the walk record or the admission is malformed."
  - `run_nuisance.py` (walk, nuisance-dossier, run), `nuisance_gate_command.py`, `nuisance_calibrate_command.py`: each subcommand with `--census` gains `--walk-record` (default `WALK_RECORD_PATH`), loads through `committed_nuisance_census` inside `malformed_input_refused`, and passes `NuisanceCensus` on (`draw_order` and `last_commit` keep reading the bare census and its path). `nuisance_dossier.write_dossier` takes `NuisanceCensus`.
  - Tests: every CLI test passes `--walk-record` pointing at a fixture record written to `tmp_path` (the committed record will not load against fixture censuses once step 5 fills it). `a_run_reaching_nothing` monkeypatches the loader name `run_nuisance` now imports (`committed_nuisance_census`), not `load_census`. Real-data tests (`test_nuisance_admission_loads.py`, `test_nuisance_fix_checks.py`) load through `load_walk_record(WALK_RECORD_PATH, load_census(CENSUS_PATH))`.
  - Add one CLI test: a subcommand run with a missing `--walk-record` path exits `REFUSED_EXIT` with the "not committed" message.
- **Test**: the existing suite unchanged in assertions, except `test_run_nuisance.py`'s malformed-admission test, which asserts the old "the census or the admission is malformed" text and follows the new message; plus the missing-record refusal.
- **Verify**: full checks green. `uv run python -m evals.run_nuisance walk` prints the same list as before the step.

### Step 3: The queue walk, identity and record settlements

- **Files**:
  - modify tests: `tests/unit/support/test_nuisance_walk_given.py`, `tests/unit/test_nuisance_walk.py`, `tests/unit/test_nuisance_population.py` (its `_walked` helper is the one place a test builds `NuisanceServer`; `support/test_nuisance_run_given.py` builds none)
  - modify `evals/census_grouping.py`, `evals/nuisance_walk.py` (and create `evals/nuisance_queue.py` if `nuisance_walk.py` passes 300 lines)
- **Do**:
  - Tests first (scenarios 1 to 5). The given gains a census whose draw order has more flaws than its holdout walk, and helpers to add a record settlement and an identity.
  - `census_grouping._DRAW_ORDER_CRITERIA` renamed `DRAW_ORDER_CRITERIA` (its use in `in_draw_order` follows).
  - `NuisanceServer` gains `reaching_position: int` (1-based position of the reaching flaw in `holdout_draw.draw_order`) and `in_addition: bool`. The builder in `test_nuisance_population.py` gains them. A holdout-walk identifier outside the draw order raises `ValueError`: a loaded census never has one (`census_draw._walk_problems` refuses a walk step that is not a draw-order candidate), but three existing tests of `test_nuisance_walk.py` walk such a flaw on an unvalidated fixture (`test_a_benchmark_flaw_marks_its_server_acceptance` walks CVE-2025-53109, a benchmark flaw; `test_an_excluded_server_is_marked_excluded` and `test_acceptance_wins_over_excluded` walk a flaw whose only label is an excluded server). Re-give them so the walk reaches the server through a draw-order flaw (the benchmark flaw carried as a non-walk override of the same server; the excluded server's flaw given a second-classifier label outside `EXCLUDED_SERVERS` with `with_the_second_classifier_overriding`, the one way an excluded server enters the real draw order), assertions unchanged.
  - Fixture draw order is the salted SHA order (`holdout_draw.draw_digest`), not the order identifiers are written in. Scenario 1's given sorts its four identifiers by `draw_digest` and walks the first two, so the queue positions are 3 and 4 by construction.
  - `server_of`: an identity settlement on the flaw wins (its `server_package` passed through `normalized_package`), else the first classifier's normalized package.
  - `_settlement(flaw, nuisance_census, criterion)`: the draw settlements first, then the record's.
  - `nuisance_population`: the holdout walk's identifiers as today, then the draw order filtered by set membership to the identifiers the holdout walk has not reached (never sliced at 86), in order, keeping a flaw only when every `DRAW_ORDER_CRITERIA` criterion holds under `_met`, the classifier side being `any(criteria_met(c)[criterion] for c in seen)`. A server first reached by a queue flaw carries `in_addition=True`. A repeated server (including one merged by identity into a holdout-reached server) adds nothing.
- **Test**:
  1. draw order of 4 flaws, holdout walk on the first 2: population lists the 4 servers in order, the last two `in_addition=True` with positions 3 and 4, the first two `False`.
  2. queue flaw with `effect_in_tool_response` A true, B false, record settlement false: skipped, its server absent.
  3. same settled true: the server is reached.
  4. identity merging two labels: one server, both flaws in `flaws` and `version_setting`.
  5. record settlement `grammar_class` false removes the flaw from `version_setting_flaws`.
- **Verify**: new tests red first, then green. Full checks green. `run_nuisance walk` still runs (it prints the holdout walk only until step 4).

### Step 4: Admission walk checks and the walk command's queue output

- **Files**:
  - modify tests: `tests/unit/support/test_nuisance_admission_given.py`, `tests/unit/test_nuisance_admission.py`, `tests/unit/support/test_run_nuisance_given.py`, `tests/unit/test_run_nuisance.py`
  - modify `evals/nuisance_admission.py` (or create `evals/nuisance_admission_walk.py` if it passes 300 lines), `evals/nuisance_population.py`, `evals/nuisance_gate_session.py`, `evals/run_nuisance.py`
- **Do**:
  - Tests first (scenarios 7 and 8), scenario 7 through the public `admission_problems` only.
  - Move `standing_exit` from `nuisance_population.py` into `nuisance_admission.py`, imported from there by `nuisance_population.py` and `nuisance_gate_session.py`.
  - `_walk_problems(admission, nuisance_census)`, called from `admission_problems`: every admitted server not in `acceptance_servers` is in `nuisance_population` by `server_package` (else `"<package>: not reached by the walk"`), its `reaching_flaw` equals the population's (else a problem naming both), and among the admitted servers with `in_addition`, no mark and `standing_exit(server) is None`, sorted by `reaching_position`, each one past `addition.size` is a problem.
  - `run_nuisance walk`: gains `--admission` (default `ADMISSION_PATH`), loaded through `committed_admission` inside `malformed_input_refused`. Prints per server the draw position of its reaching flaw, `(addition)` for a queue server, the holdout outcome for a holdout-walk one, then `"<k> of <size> servers of the addition admitted and in the figure"` (k counted as in the size check), the line left out when no admission is committed. Existing walk tests pass a missing admission path.
  - Fixture censuses. `_walk_problems` calls `nuisance_population`, which raises `ValueError` ("the census has no draw walk to follow", from `reached_identifiers`) on a census whose `draw` is `None`, and runs whatever the admitted servers are (an acceptance-only admission included). `census_given.a_census()`, the census of `test_nuisance_admission_given.a_census`, of `test_nuisance_images.py`, of the run and gate CLI tests of `test_run_nuisance.py` and of `support/test_run_nuisance_given.a_gate_set_of_one_server`, has no draw, so every one of those tests would raise or exit `REFUSED_EXIT`. Each census that reaches `admission_problems` or `load_admission` gains a draw whose walk reaches each admitted non-acceptance server through its recorded `reaching_flaw` (for the admission given: one `skipped` step on `FIRST_FLAW`, which `load_census`'s draw validation accepts without card or agent; the census's other flaws of `npm:@acme/files` then add nothing to the queue). `support/test_run_nuisance_run_given` already uses `draw_given.a_census_with_draw`: check that its admitted server is reached with the recorded reaching flaw, and that the fixture record's `addition.size` covers the fixture's queue servers.
    Decided by the maintainer at the final review: keep the raise and migrate the fixtures. A census without a draw is not read as an empty holdout walk, and `test_reached_identifiers_raises_without_a_draw` stays as it is.
  - If `test_nuisance_admission_loads.py` fails on the real admission (an admitted server unreached, or a reaching flaw that differs), stop and report to the maintainer: do not edit `evals/nuisance_admission.json`. (Checked at review on the committed data with no identity and no record settlement: all 59 admitted servers are reached with their recorded reaching flaw, none is an acceptance server, and 25 enter through the addition, all over stdio and under Docker, so this should not fire.)
- **Test**:
  - admitted non-acceptance server absent from the population: refused. Admitted acceptance server outside the walk: passes.
  - wrong `reaching_flaw`: refused, the problem names both flaws.
  - `size=1`, two admitted queue servers: the second by position refused. A queue server with a standing exit does not count toward the size.
  - `run_nuisance walk` on a fixture census with a fixture admission prints `(addition)` and the count line. Without an admission, no count line.
- **Verify**: new tests red first, then green. Full checks green. `uv run python -m evals.run_nuisance walk` lists the queue servers with `(addition)` and ends `25 of 43 ...`.

### Step 4b: Walk record provenance in the run result

- **Files**:
  - modify `evals/nuisance_results.py`, `evals/nuisance_report.py`, `evals/nuisance_run.py`, `evals/nuisance_markdown.py`, `evals/run_nuisance.py`
  - modify tests: `tests/unit/support/test_nuisance_run_given.py`, `tests/unit/support/test_nuisance_report_given.py`, `tests/unit/support/test_run_nuisance_run_given.py`, and the report or markdown test that asserts the census commit line
- **Do**:
  - Tests first: a run result and its report carry `walk_record_commit` beside `census_commit`, and the markdown prints it on the provenance line next to the census commit.
  - `run_nuisance run` computes `last_commit(args.walk_record)` the way it computes the census commit and passes it on through `run_nuisance` (`_RunContext`) to the result. `support/test_run_nuisance_run_given` already monkeypatches `run_nuisance.last_commit` for the census, which lives out of git: the same patch covers the record.
  - Provenance, not a condition: no baseline, gate or comparison reads it.
- **Test**: the result JSON, the report and the markdown carry the record's commit; a run whose record and census sit at different commits records both.
- **Verify**: new tests red first, then green. Full checks green.

### Step 5: Maintainer step, the record's settlements and the completeness check (done by hand by the assistant, not dispatched)

- **Files**:
  - modify `evals/nuisance_walk_record.json`
  - create `tests/unit/test_nuisance_walk_record_loads.py`
  - modify `tests/unit/test_nuisance_walk_record.py` (and its given), `evals/nuisance_walk_record.py`
- **Do**:
  - Fill `identities` (googleapis Go module and repository labels: every census flaw either classifier labels `https://github.com/googleapis/mcp-toolbox`, i.e. CVE-2026-14538 at position 119 and also CVE-2026-14537, CVE-2026-14539 and CVE-2026-14541 outside the draw order, so that `census_flaws_of` and the dossier carry them under the Go module; completeness requires none of these, since both classifiers label CVE-2026-14538 https and CVE-2026-14537 is outside the draw order; `PyPI:kubectl-mcp-tool` (CVE-2025-69902) into `PyPI:kubectl-mcp-server`, the three package disagreements CVE-2026-19337, CVE-2025-66689, CVE-2026-34884, any other the completeness check finds) and the 31 criterion `settlements` on the 28 queue flaws, each with its reason read from the census advisory sources and the pages they link, and for an admitted server from its admission record. If the classifier cuts the advisory reading, switch to Opus 4.8.
  - Tests first: completeness in `walk_record_problems`. Every flaw the queue walk reaches (draw order minus `reached_identifiers`, skipped ones included) whose classifiers disagree on a `Criterion` (through `criteria_met`) needs a settlement for that criterion, and every one whose classifiers name different normalized packages needs an identity. Computed in `nuisance_walk_record.py` with no call into `nuisance_walk`. It calls `reached_identifiers`, which raises on a census without a draw: every fixture census still loaded through `committed_nuisance_census` without a draw after step 4 (the `nuisance-dossier` CLI tests of `test_run_nuisance.py` on `census_given.a_census()`, and any other) gains a draw in this step, or those tests exit `REFUSED_EXIT` (the raise is kept, decided at the final review).
  - Real-data tests: `load_walk_record` on the committed files passes and `load_admission` passes (scenario 9). Population sanity (scenario 10): the holdout part is the 52 servers of today with the same packages, the googleapis https label and `PyPI:kubectl-mcp-tool` are not separate servers, the 25 admitted queue servers of batches 6 and 7 are reached with `in_addition=True`.
  - If a settlement unreaches an admitted server or changes its reaching flaw, stop and report rather than editing the admission.
  - Present the settlements to the maintainer before any commit.
- **Test**: missing settlement for a reached queue flaw with a disagreement: refused. Missing identity for a package disagreement: refused. The two real-data tests above.
- **Reference counts** (checked at review on the committed census): draw order 186, holdout walk 86 (a set equal to positions 1-86, not a prefix in sequence), queue 100 flaws, 31 criterion disagreements on 28 queue flaws, 3 package disagreements (CVE-2026-19337 at 124, CVE-2025-66689 at 149, CVE-2026-34884 at 161), no draw settlement on a queue flaw. With no identity and no settlement the queue first reaches 44 servers with a version-setting flaw; the googleapis merge brings that to the logged 43 and the kubectl merge to 42, before any criterion settlement skips a flaw. Settlements that sit on the reaching flaw of an admitted queue server, where a false verdict could unreach it: CVE-2026-0758 (pinnable, siri-shortcuts), CVE-2025-59834 (effect, adb-mcp), CVE-2026-7810 (pinnable, python-notebook-mcp), CVE-2026-4198 (pinnable, mcp-server-auto-commit).
- **Verify**: full checks green. `uv run python -m evals.run_nuisance walk` ends `25 of 43 ...`. `uv run python -m evals.run_nuisance calibrate --cve CVE-2026-61462` still loads the admission (Docker).

### Step 6: Living docs and logs

- **Files**: `docs/nuisance-log.md`, `docs/holdout-log.md`, `CHANGELOG.md`, `CLAUDE.md`, `CONTRIBUTING.md`, `README.md` (only if it describes the walk's extent)
- **Do**: as listed in the outline's step 4: nuisance-log entries (record committed with its settlement and identity counts, the kubectl-mcp-tool and googleapis merges, the "positions 79 to 102" correction to 131 to 182), the holdout-log entry on the record binding a later holdout walk past position 86, `CHANGELOG.md` `[Unreleased]` (walk prints the queue, the run result records the walk record's commit, the "79 to 102" slip fixed in place), the `CLAUDE.md` Commands line for `run_nuisance walk` (queue, `--walk-record`, `--admission`) and the "malformed" wording wherever quoted, the `CONTRIBUTING.md` walk paragraph (queue, `--walk-record` and walk `--admission`, the record as a prerequisite of every nuisance command, the new "malformed" message). English, no em dash.
- **Test**: none.
- **Verify**: `uv run ruff check .` and `uv run pytest -n auto` green (nothing should change).
