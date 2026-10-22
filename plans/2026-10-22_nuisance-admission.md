# Nuisance suite: admission, fix check and patched images

## Context

The nuisance suite is pre-registered but nothing of it is built. ADR 033 and `docs/nuisance-rule.md` (version 1, `docs/nuisance-log.md`) fix what it counts: on the patched version of a server, a case or a chain that calls a tool which carried a fixed flaw and is judged FAIL in a category valid for that flaw's class. The unit is the server, built at the first pinnable release that fixes every one of its census flaws the suite counts. The census is built and loads (`evals/holdout_census.json`), and the holdout walk has reached position 86 (30 drawn, the rest given up, excluded or skipped), so the servers the nuisance walk takes already exist as census flaws with their draw order and classifier settlements.

What stands between the rule and a first run is code the rule prescribes but that does not exist. It splits in two along the same seam the holdout did (prerequisites of the draw in `plans/2026-10-16_holdout-draw-prerequisites.md`, then the run mode in `plans/2026-10-16_holdout-run-mode.md`): an input side, which turns census flaws into admitted servers with a patched image and a verified fix, and a measurement side, which audits those servers, counts alarms and gates the acceptance servers. This plan is the input side. The measurement side (the counter out of `cve_grammar.py` with its own fingerprint, the run orchestrator, the server statistic and side split, the exits and raw-count tables, and the acceptance gate in a run of its own) is a separate later plan, built on the admission file and the images this plan leaves behind.

This plan delivers the scaffolding only. It admits no server, runs no agent, builds no image and verifies no real fix: the admission itself (running the two blind agents over the walk, settling their disagreements, reading each record, planting each witness) is the maintainer's deferred admission session, the analog of the holdout draw, and is out of scope for `/implement-plan`. Every module here is testable with fakes and crafted records, exactly as the holdout run mode was testable with `HOLDOUT_TARGETS` empty before the draw ran.

No change here edits `docs/nuisance-rule.md`, `docs/holdout-rule.md` or `evals/cve_grammar.py`: every artifact is an implementation the rule already prescribes, so no rule version opens and no grammar fingerprint moves. Each artifact gets a dated `docs/nuisance-log.md` line naming its commit and stating that no server is admitted, so no figure is produced, on the model of the version 1 entry.

## Approach

Five parts, each a prerequisite the admission needs, ordered so each stands alone and keeps `pytest`, `ruff` and `pyright` green:

1. **The nuisance walk** (pure code, no LLM): the population the admission covers, drawn from the holdout walk of `evals/holdout_census.json` and the census, with its own eligibility (a graded class, stdio, effect visible in a tool response, pinnable, runnable), and a command that prints the servers to admit with the flaws that set each one's version.
2. **The admission file**: the schema (one file distinct from `holdout_census.json`, admitted servers only), its per-server and per-flaw records, the two agents' agreement and the maintainer's settlements, validated on load when present, empty now.
3. **The isolated admission workshop**: a `nuisance-dossier` command that assembles, outside the repository, a self-contained kit (advisories, fixture format, grammar, an MCP client and a Docker launch that import nothing from `mcp_auditor`) the admission agents run, and a fix-check driver that reproduces each flaw on both versions, plus an import-closure test that pins the isolation.
4. **The patched images, wired**: the namespace, the compose services and the fixture fingerprint of a patched server, disjoint from the acceptance and the kit namespaces, built on the `cve_images` identity machinery (`d915502`, `ae8235a`, `45980a4`).
5. **Living docs and the nuisance log**.

Parts 1 and 2 reuse what the holdout laid down: `evals/holdout_draw.draw_order` (the salted order), `evals/holdout_exclusions.py` (`EXCLUDED_SERVERS`, `BENCHMARK_FLAWS`), `evals/census_grouping` (the draw-order predicate and the settlements) and `evals/holdout_census.load_census` (the walk the holdout already recorded). Part 3 mirrors `evals/holdout_kit/` and `evals/calibration_dossier.py`. Part 4 mirrors the kit namespace of `d915502` and the `cve_images` label.

## Part 1: the nuisance walk

New module `evals/nuisance_walk.py` and a new entry point `evals/run_nuisance.py` (nuisance-specific commands, kept out of `run_holdout.py`, `run_census.py` and `run_cve_benchmark.py`).

The walk reaches every flaw the holdout walk reached. The holdout walk is the `walk` of `evals/holdout_census.json`'s `DrawRecord` (every `DrawWalkStep`, whatever its outcome: `drawn`, `skipped`, `given_up`, `excluded`). The nuisance population is the servers of those flaws, since the rule says a server enters through a flaw of the draw order and then counts all its census flaws. A nuisance walk past the holdout walk (an addition) is out of scope here: the holdout walk is the current frontier, and additions are logged, sized in servers and deferred.

`evals/nuisance_walk.py` exposes:

- `reached_identifiers(census: HoldoutCensus) -> list[str]`: the identifiers of `census.draw.walk`, in walk order. Raises when `census.draw` is None (no walk to follow).
- `server_of(identifier, census) -> str`: the `server_package` the first classifier recorded for the flaw, read from `census.classifications[CLASSIFIERS[0]]` as `calibration_dossier._server_packages` does (`census_grouping` has no server reader). A `PyPI:` name is normalized per PEP 503 (casefold, runs of `.`, `-`, `_` collapsed to `-`) and other prefixes are read verbatim, so a case-only difference between the classifiers names one package with no settlement: the committed walk holds one such case, CVE-2026-47394 recorded `PyPI:PraisonAI` by one classifier and `PyPI:praisonai` by the other, and the rule's unit being the package, the two are one server. Any other classifier disagreement on server identity is the maintainer's settlement at admission, not here.
- `nuisance_population(census) -> list[NuisanceServer]`: one `NuisanceServer` per distinct server the walk reached, in the order of its first reaching flaw, carrying every census flaw of that server (not only the reaching one) and the identifier of the reaching flaw.
- `version_setting_flaws(server, census) -> list[str]`: the server's census flaws that are in a graded class (`census_classification.in_grammar` on `effect_class`), reached through `tools/call` (`classification.primitive == Primitive.TOOLS`, not `Criterion.STDIO_TOOLS_CALL`, which also requires stdio: the rule counts a flaw whatever transport the census records), whose effect shows in a tool response (`effect_in_tool_response`) and whose vulnerable version is pinnable (`pinnable`), read from the classifications and the settlements already in `census.draw.settlements`. A criterion is met when either classifier finds it met, as `census_grouping.in_draw_order` reads the census, and a `Settlement` on the flaw and criterion overrides both. This is the eligibility the rule's Eligibility section defines, as far as the census can decide it before the agents read the sources. A server with none leaves the population here; the agents refine the rest.

`NuisanceServer` (a frozen dataclass): `server_package: str`, `reaching_flaw: str`, `flaws: tuple[str, ...]`, `version_setting: tuple[str, ...]`.

Excluded servers and acceptance servers stay in the population at this stage, marked, because the rule routes them (acceptance servers go through admission outside the walk and are gated; excluded servers leave the figure). The marking reuses `EXCLUDED_SERVERS` and the acceptance servers are the `server_package` the census records for each flaw of `holdout_exclusions.BENCHMARK_FLAWS` (current and dropped targets alike, all eight are census members): a `CVETarget` carries a `cve_id` and no package name, so `CVE_TARGETS` cannot be read for it directly. A later part of the measurement plan reads the mark; here it is only recorded. Note that `census_grouping.in_draw_order` already keeps excluded servers and benchmark flaws out of the draw order, so in the committed walk no step reaches an excluded or acceptance server; the mark exists for a server that enters through another of its census flaws (the dropped `npm:gemini-mcp-tool` is not excluded, for instance).

`evals/run_nuisance.py` gets a `walk` subcommand that prints, per server in walk order, the `server_package`, the reaching flaw, the version-setting flaws and the exclusion or acceptance mark, for the maintainer to admit. No LLM, no network.

## Part 2: the admission file

New module `evals/nuisance_admission.py`: the schema the admission session fills and its load validation, on the model of `evals/census_draw.py` (the draw record) but in a file of its own, `evals/nuisance_admission.json`, admitted servers only.

Schema (pydantic `BaseModel`, every list empty until the admission session):

- `ToolRecord`: `vulnerable_name: str | None`, `patched_name: str | None`, `status: Literal["unchanged", "renamed", "removed"]`.
- `FlawRecord`: `flaw: str`, `tools: list[ToolRecord]`, `effect_class: MechanismClass | None` (`cve_grammar.MechanismClass`, so pydantic refuses a non-grammar class on load and no separate check is needed), `patched_version: str | None`, `patched_source: Literal["advisory", "fix_commit", "none"]`, `launch_option: LaunchOption | None` (reusing `census_draw.LaunchOption`), `benign_calls: list[BenignCall]` (one per tool, in the patched version), `needs_backend: bool`, `declared_function_is_effect: bool`, `fix_check: FixCheckRecord`.
- `BenignCall`: `tool: str`, `arguments: dict[str, Any]` (written from the tool description, not aimed at the flaw).
- `FixCheckRecord`: `source: Literal["fix_check", "holdout_calibration"]` (the rule exempts a holdout server whose patched version is the one its holdout calibration checks, for the drawn flaw and its siblings: such a record carries the card's result and no witness of its own), `witness: str`, `exploit_calls: list[str]` (described, not the auditor's), `vulnerable_surfaces: bool`, `patched_surfaces: bool` (on the flaw's own patched version), `server_patched_surfaces: bool | None` (on the server's patched version when it differs from the flaw's, None when they are the same: the rule and ADR 033 require the witness to surface on neither), `patched_benign_errored: bool`. The record of the reproduction the fix check runs, filled by the driver of Part 3.
- `AdmittedServer`: `server_package: str`, `reaching_flaw: str`, `flaws: list[FlawRecord]`, `runs_over_stdio: bool`, `runs_in_container: bool`, `launch: list[str]`, `service: str` (the compose service name of the patched image, in the nuisance namespace), `agents: list[AgentRecord]` (the two models, reusing `census_work.AgentRecord`, which needs a new `AgentRole.ADMITTER` member: the enum has no admission role today, and the addition is inert for the census), `agreement: list[FieldAgreement]`, `settlements: list[AdmissionSettlement]`.
- `FieldAgreement`: `flaw: str | None` (None for the two server-level fields), `field: str`, `agreed: bool` (per the rule's list: tools and status, class, patched version, backend, declared function per flaw, stdio and container per server).
- `AdmissionSettlement`: `server_package: str`, `flaw: str | None`, `field: str`, `value: str`, `reason: str` (the maintainer's, on the advisory and the pages it links).
- `NuisanceAdmission`: `rule_commit: str`, `grammar_fingerprint: str`, `servers: list[AdmittedServer]`.

`load_admission(path: Path) -> NuisanceAdmission` validates, on the model of `load_census`: the `grammar_fingerprint` matches the current grammar (`cve_baseline.grammar_fingerprint()`), every `FieldAgreement` with `agreed=False` has an `AdmissionSettlement` on the same server, flaw and field, every flaw of a server is a census flaw of that `server_package`, and the counted tools (`counted_tools` below) are non-empty for an admitted server. `admission_problems(admission, census, grammar_fingerprint) -> list[str]` holds the checks, raised joined by `load_admission`, so a crafted admission can be checked in a unit test without a file. The file is absent until the admission session, and `load_admission` on a missing file raises a clear error, as the run will need it.

The derived reads the measurement plan will consume are defined and tested once here, in `evals/nuisance_counting.py` rather than beside the schema: eight models plus the load checks already fill a module the size of `census_draw.py`, and a file past 300 lines is split (CLAUDE.md, coding standards).

- `counted_flaws(server) -> list[FlawRecord]`: the flaws that set the version (graded class, a tool reached, effect visible, pinnable) and are fixed on the patched version (`fix_check.vulnerable_surfaces and not fix_check.patched_surfaces and not fix_check.server_patched_surfaces and not fix_check.patched_benign_errored`, a None `server_patched_surfaces` reading as not surfaced).
- `counted_tools(server) -> dict[str, frozenset[str]]`: per counted tool that exists in the patched version, does not need an absent backend and whose declared function is not the effect of its class, the union of the grammar's valid categories over the classes of the counted flaws that reach it. This is the map the Part-B counter consumes; its valid categories come from `cve_grammar.VALID_CATEGORIES`, read, not redefined.
The first release that fixes every counted flaw is not computed here: no version-ordering library is a dependency (`packaging` is not in `pyproject.toml`, and npm semver and PEP 440 order pre-releases, post-releases and epochs differently, so one library would not cover both registries). It is a settled admission field, `AdmittedServer.patched_version`, written by the agents and settled by the maintainer. It has to exist before the admission loads anyway, since the Part 3 fix check plays the exploits on the server's patched version when it differs from a flaw's, so the driver reads it from the fixture. `load_admission` checks it is one of the counted flaws' patched versions, and that each counted flaw's `server_patched_surfaces` is `None` exactly when the flaw's patched version equals the server's.

## Part 3: the isolated admission workshop

The admission agents are blind to the auditor, as the rule and ADR 033 require. The workshop mirrors `evals/holdout_kit/` and `evals/calibration_dossier.py`: a tree exported outside the repository that imports nothing from `mcp_auditor`, with the clean modules copied in, an MCP client and a Docker launch of its own, and a no-LLM fix-check driver the agent runs until a fix reproduces.

New command in `evals/run_nuisance.py`, `nuisance-dossier --server <package> --out <dir>`, mirroring `calibration-dossier`. It assembles, from the census flaws of one server (`CensusFlaw` fields alone, never the raw exports), the advisories, the fixture format, the grammar classes, and the kit source. It reuses `evals/holdout_kit/kit_client.py` and `evals/holdout_kit/kit_launch.py` unchanged (the MCP client and the Docker launch are the same), and the same clean modules `calibration_dossier._CLEAN_MODULES` copies (`cve_grammar`, `cve_proofs`, `cve_units`, `cve_places`, `cve_layout`, the `cve_planting*` modules, `cve_endpoint_address`): none can be left out, since `kit_launch` imports `cve_layout`, `cve_places` and `cve_planting`, and `kit_target` imports `cve_places`. What the nuisance dossier leaves out is `holdout_places.json` and `layout.md`, the holdout's list and layout. The kit module list is the nuisance dossier's own (`_KIT_MODULES` plus `fix_check`), so the holdout dossier's export does not change.

New module `evals/holdout_kit/fix_check.py` (in the kit tree, so the exported dossier carries it), the nuisance twin of `evals/cve_calibration.check_target`. It reuses the grammar's proof and aim evaluation (`cve_grammar`, `cve_proofs`, `cve_units`) unchanged, but its place is the flaw's own coordinate, not a catalogue place, so the witness sits where the flaw reaches and a server the holdout dropped for reaching no catalogue place can still be verified. The check:

- plants the `witness` at the flaw's coordinate, with the kit's planting, free of the holdout's `holdout_places.json` list: the agent builds a `cve_places.Place` value in the fixture (an id of its own, a `PlantKind` and `Coordinates`), and `cve_planting.planting_spec` plants it as it plants a catalogue place, so no `kept_records` lookup and no loaded mapping is involved.
- plays the exploits on the vulnerable version: the check passes its positive control when the witness surfaces in a tool response (`proofs_in` non-empty for the witness) and the exploits read as aimed.
- plays the exploits and the benign call on the flaw's patched version and, when the server's patched version differs, on that one too: the witness surfaces on neither and the benign call returns no error.
- returns a `FixCheckRecord` the agent writes into the admission.

The verdict is a pure function of the exchanges recorded on each version (the witness, the exploit and benign exchanges per version) to a `FixCheckRecord`, kept apart from the launches, as `dead_conditions` sits beside `check_target`; the launches are what the test replaces by the fake kit client. The record-building logic then needs no Docker in the unit tests (CLAUDE.md: prefer pure functions, inject the side effect).

The driver stays synchronous and single-target, like `kit_driver` (one server at a time, no event loop, no `evals/concurrency`). The isolation test (`tests/unit/test_nuisance_dossier_isolation.py` or an extension of the kit isolation test) scans the exported tree and pins that it imports nothing from `mcp_auditor`.

A `FixCheckTarget` (a flat field-for-field mirror of the admission fields the fix check needs, typed against `KitClient` and `kit_launch.Launch`, plus the witness `Place`, the exploits and the benign calls as callables, the vulnerable and the patched services), the analog of `KitTarget`, is what the agent writes and the driver consumes. A parity test pins the mirror against the admission schema fields the driver reads, so it cannot drift, as `test_holdout_kit_isolation.py` pins `KitTarget` against `CVETarget`. The rule commits the vulnerable Dockerfile and the exploits beside the admission: they are `FixCheckTarget` fixtures, typed against the kit and run only through the kit driver (the fix check runs outside any run and the auditor never sees them), so unlike a `KitTarget` they are never transplanted into an in-repo twin. The module that holds them (`evals/nuisance_fixtures.py`, an empty tuple now, the analog of `holdout_targets.HOLDOUT_TARGETS`) imports from `evals.holdout_kit` only, which keeps it inside the kit's import closure.

The import-closure test already scans `evals/holdout_kit/` whole (`test_no_kit_file_imports_mcp_auditor`), so `fix_check.py` is covered there as soon as it exists; the new test covers the nuisance dossier's written tree.

## Part 4: the patched images, wired

The patched images build from `evals/docker/` like the acceptance and kit images, with a namespace of their own so a nuisance build never overwrites an acceptance or a kit image.

- `evals/nuisance_images.py` exposes `image_tag(service)` returning `mcp-auditor-nuisance-<service>:local`, by the model of `kit_launch.image_tag`. A unit test pins the three prefixes apart (`cve_targets.image_tag`, `kit_launch.image_tag`, the nuisance one) and, over a crafted admission, that no admitted `service` is an acceptance service (`CVE_TARGETS` images and patched images plus `SENTINEL_SERVICE`, the set `calibration_dossier._readme` already computes). The kit services are the agents' own and are not enumerated in the repository, so the prefix is the only disjointness the test can pin against them.
- Each patched image pins the server's patched version and the digest of its base image, as the CVE Dockerfiles do, with the transitive dependencies floating (ADR 024, ADR 033). It carries the `cve_images.FINGERPRINT_LABEL` of its Dockerfile, so the identity machinery of `d915502`, `ae8235a` and `45980a4` rebuilds it when the Dockerfile changes. One change to `cve_images` is needed for that: `stale_services` calls `cve_targets.image_tag` directly and `ensure_images` reaches it through `stale_services`, so both gain a `tag: Callable[[str], str]` parameter defaulting to it (`ensure_images` forwarding its own), and the nuisance passes its own (`dockerfile_fingerprint` already takes a `docker_directory`, and `ComposeImageStore.build` goes through the one `compose.yml`, where the nuisance services sit beside the acceptance ones with their own `image:` name). The acceptance call sites are unchanged.
- The fixture fingerprint of an admitted server covers its patched Dockerfile, its launch, its counted tools with the class of each, and their benign calls, as the rule's Run conditions section lists. New function `nuisance_fixture_fingerprint(server: AdmittedServer, docker_directory: Path = DOCKER_DIRECTORY) -> str`, by the model of `cve_baseline.fixture_fingerprint`, computed over `cve_images.dockerfile_instructions` of `Dockerfile.<service>` and those fields. The measurement plan reads it into each run; here it is defined and tested over crafted servers with a Dockerfile written under `tmp_path`.

No Dockerfile is added in this plan (no server is admitted), so no fingerprint is produced and no baseline exists yet. The compose services the admission session adds, one patched service per admitted server, are the maintainer's, written beside the admission file.

## Part 5: living docs and the nuisance log

- `docs/nuisance-log.md`: one dated line per committed part, naming its commit and stating that no server is admitted, so no figure is produced.
- `CLAUDE.md` Commands: the new `run_nuisance walk` and `nuisance-dossier` commands, with their prerequisites (no LLM, no network for `walk`; Docker for the fix-check driver), on the model of the holdout command lines.
- `CONTRIBUTING.md`: the same two commands, in a paragraph after the one on the holdout draw commands in the CVE benchmark section, stating that no server is admitted yet.
- `README.md`: no change. The suite publishes no figure yet, and the "What is not measured" paragraph already names the nuisance suite as not yet run.
- `CHANGELOG.md` `[Unreleased]`: the admission scaffolding, as a tooling entry.

## What this plan does not do

- It admits no server, runs no admission agent, and settles no disagreement. The admission session is the maintainer's, deferred, out of scope for `/implement-plan`.
- It builds no patched image and writes no compose service, since no server is admitted.
- It does not count alarms, run an audit, compute the figure or the side split, or gate the acceptance servers. That is the measurement plan.
- It does not touch `evals/cve_grammar.py`, `docs/nuisance-rule.md` or `docs/holdout-rule.md`.
- It does not resume or extend the holdout walk, and takes no addition past the walk's current frontier.

## What stays unchanged

`evals/cve_grammar.py` and its fingerprint, `evals/cve_targets.py` and the acceptance baseline, `evals/holdout_census.json`, `evals/holdout_targets.py`, `docs/holdout-rule.md`, `docs/nuisance-rule.md` and the grammar golden master. The nuisance modules import `cve_grammar.VALID_CATEGORIES`, the holdout draw order and the census readers, and add nothing to them. The two additive touches outside the new modules are `census_work.AgentRole.ADMITTER` (Part 2) and the injected `tag` of `cve_images.stale_services` and `ensure_images` (Part 4), both inert for the census and the acceptance preflight. The acceptance fixture fingerprint (`cve_baseline._ENVIRONMENT_PATHS`) covers neither module, so no acceptance fingerprint moves.

## Edge cases

- A server the holdout walk reached whose every flaw leaves the population at Part 1 (no graded class, no stdio, no visible effect, not pinnable): absent from the `walk` output, so the maintainer does not admit it. Logged by the measurement plan's exits, not here.
- A server reached by several flaws: one `NuisanceServer`, the reaching flaw is the first in walk order, all its census flaws carried.
- An acceptance server the walk reaches: kept in the population with the acceptance mark, since the rule admits it outside the walk and gates it. The `walk` output marks it; this plan does not gate.
- A flaw the census records under two server identities for two candidates (the ContextForge case the holdout handled): `server_of` reads the classification, and the maintainer settles identity at admission, recorded as an `AdmissionSettlement` on `server_package`.
- `load_admission` on a grammar fingerprint that does not match the current grammar: a problem, raised, since a grammar change reapplies eligibility and resets the gate baseline (the rule's Versioning section).
- A `FlawRecord` with `effect_class` None (the agents found no grammar class): not a counted flaw, does not set the version; a server with no counted flaw left is a load problem (the measurement plan drops it from the figure, but an admitted server must have one).

## Test scenarios

- `nuisance_population` over a crafted census with a `draw.walk` of mixed outcomes: one server per distinct `server_package`, in first-reaching order, every census flaw carried, excluded and acceptance servers marked.
- `version_setting_flaws` over flaws with and without a graded class, stdio, visible effect and pinnability: only the eligible ones returned.
- `reached_identifiers` on a census with no `draw`: raises.
- `load_admission` / `admission_problems` over a crafted admission: a mismatched grammar fingerprint, an unsettled disagreement, a flaw not of its server, and a server with no counted tool each produce a named problem; a non-grammar `effect_class` is refused by the schema itself (`MechanismClass`); a clean admission loads.
- `counted_flaws`, `counted_tools`, `patched_version` over crafted servers: a flaw fixed only on a later release sets the version to that release; a renamed tool is counted under its patched name; a backend-needing or effect-is-function tool is not a counted tool; a tool carrying flaws of two classes takes the union of their valid categories.
- `fix_check` over a fake kit client that surfaces the witness on the vulnerable version and not on the patched one: a passing record; one that still surfaces on the patched version: `patched_surfaces` True, not a counted flaw; one whose server patched version differs from the flaw's: both patched images exercised, `server_patched_surfaces` filled; one where they are the same: one patched launch, `server_patched_surfaces` None.
- `cve_images.stale_services` with the nuisance `image_tag` injected: reads the label of the nuisance tag, not the acceptance one, over a fake `ImageStore`.
- `version_setting_flaws` with a `draw.settlements` entry: the settlement overrides the classifiers on its criterion.
- the import-closure test: the exported nuisance dossier imports nothing from `mcp_auditor`.
- the parity test: `FixCheckTarget` mirrors the admission fields the driver reads.
- the namespace test: nuisance services are disjoint from acceptance and kit services.
- `nuisance_fixture_fingerprint`: stable over the same server, moves when a counted tool's class, a benign call or the patched Dockerfile changes.

## Verification

`uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check`, `uv run pyright` (no file argument), all green. The dossier's import-closure and the namespace-disjointness tests pass. `uv run python -m evals.run_nuisance walk` prints the population from the committed census with no LLM and no network. No eval fixture fingerprint, grammar fingerprint or baseline moves (a test or the gate would catch it), since no server is admitted and no Dockerfile is added.

## Governance note

Every artifact is an implementation the nuisance rule (version 1) and ADR 033 already prescribe, so no rule version opens and no ADR is written. No change reaches the system under test (`src/`, the prompts), the grammar or any baseline, so no eval number is affected and ADR 016 does not apply. Each committed part is a `docs/nuisance-log.md` line stating that no server is admitted.

## Due diligence record

What the diligence pass concluded on 2026-10-22, written for the later passes (step breakdown, implementation fact check) that read it. No pass may treat a line here as a reason to skip a verification: the record says what was concluded once, not what is true now. A human who edits one of these facts by hand deletes its line rather than updating it, so the section never asserts something nobody checked.

- SETTLED: `census.draw.walk` holds 86 `DrawWalkStep` entries with the four outcomes `drawn`, `skipped`, `given_up`, `excluded` (verified against `evals/holdout_census.json` at HEAD `b99395e`).
- SETTLED: `holdout_exclusions.BENCHMARK_FLAWS` has eight identifiers, all census members (verified against `evals/holdout_exclusions.py` and `evals/holdout_census.json`).
- SETTLED: `CVETarget` carries `cve_id`, `images`, `server_image`, `patched_image` and no package name (verified against `evals/cve_targets.py`).
- SETTLED: `cve_targets.image_tag` → `mcp-auditor-cve-<name>:local`, `kit_launch.image_tag` → `mcp-auditor-kit-<name>:local` (verified against both modules).
- SETTLED: `cve_images.stale_services` calls `image_tag` directly, `ensure_images` only through `stale_services` (verified against `evals/cve_images.py`, plan corrected).
- SETTLED: `calibration_dossier._CLEAN_MODULES` is the ten modules the plan lists and `_KIT_MODULES` is `("__init__", "kit_client", "kit_launch", "kit_target", "kit_driver")` (verified against `evals/calibration_dossier.py`).
- SETTLED: `census_work.AgentRole` has no admission member; its only readers are `census_draw.draw_problems` (CALIBRATOR, CARD_CHECKER) and `holdout_census._reader_problems` (READER), so a new member is inert for the census (verified against `evals/`).
- SETTLED: commits `d915502`, `ae8235a`, `45980a4`, `137fca4` exist with the subjects the plan implies (verified against `git log`).
- SETTLED: `packaging` is not a declared dependency in `pyproject.toml`, but `packaging==26.0` is present in `uv.lock` as a transitive one (verified locally; latest on PyPI is 26.3, 2026-08-04).
- SETTLED: PyPI names normalize by lowercasing and collapsing `.`/`-`/`_` runs to `-`, so `PyPI:PraisonAI` and `PyPI:praisonai` name one package (verified against PEP 503, peps.python.org).
- SETTLED: npm semver and PEP 440 order pre-releases differently (`1.0.0-alpha` is a semver pre-release and is not a canonical PEP 440 form, which writes `1.0.0a0`, and PEP 440 adds post-releases and epochs semver lacks), so one library cannot order both registries (verified against semver.org v2.0.0 item 11 and packaging.python.org version specifiers).
- SETTLED (Roman, 2026-10-22): version ordering is not computed in code; the server's patched version is a settled admission field `AdmittedServer.patched_version`, checked against the counted flaws' versions on load (Part 2).
- SETTLED (Roman, 2026-10-22): `server_of` normalizes a `PyPI:` name per PEP 503, so a case-only difference names one package with no settlement; other identity disagreements are settled at admission (Part 1).
- SETTLED (Roman, 2026-10-22): the `FixCheckTarget` fixtures live in `evals/nuisance_fixtures.py`, inside the kit's import closure (Part 3).

## Implementation steps

The three decisions the REVIEW markers raised, settled by Roman on 2026-10-22, each recorded in the step that implements it:

- **Server identity (Part 1).** `server_of` normalizes a `PyPI:` package name per PEP 503 (casefold, runs of `.`, `-`, `_` collapsed to `-`), other prefixes verbatim. The diligence record settled that `PyPI:PraisonAI` and `PyPI:praisonai` name one package, and the rule's unit is the package, so grouping them is the rule, not a guess. `EXCLUDED_SERVERS` and the benchmark flaws' packages are compared after the same normalization.
- **Version ordering (Part 2).** No ordering in code. The server's patched version is a settled admission field, `AdmittedServer.patched_version`, written by the agents and settled by the maintainer like any other field. It has to exist before the admission loads anyway: the fix check of Part 3 plays the exploits on the server's patched version when it differs from the flaw's, so the driver reads it from the fixture. `load_admission` checks it is one of the counted flaws' patched versions and that each counted flaw's `server_patched_surfaces` is `None` exactly when the flaw's patched version equals the server's. `nuisance_counting.patched_version` is not written. No dependency is added.
- **Fixture placement (Part 3).** As the plan's text says: `evals/nuisance_fixtures.py`, an empty tuple of `FixCheckTarget`, importing from `evals.holdout_kit` only.

One consequence of the kit isolation: `evals/nuisance_admission.py` imports `cve_baseline` (for the grammar fingerprint), which reaches `mcp_auditor`, so the kit's `fix_check.py` cannot import `FixCheckRecord` from it. The driver returns a kit-local frozen dataclass `FixCheckResult` with the same fields, and the parity test of step 3 pins the two field sets equal, as `LaunchMode` is a kit-local copy pinned by the existing parity test.

Verification commands (CLAUDE.md): the short loop is `uv run pytest tests/unit -n auto --maxprocesses 4`, `uv run pyright <changed files>` and `uv run ruff check .` plus `uv run ruff format .`. Every step closes with `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .` and `uv run pyright` with no file argument, all green.

### Step 1: the nuisance walk and the `walk` command

**Files**

- Create `tests/unit/support/test_nuisance_walk_given.py`
- Create `tests/unit/test_nuisance_walk.py`
- Create `tests/unit/test_run_nuisance.py`
- Create `evals/nuisance_walk.py`
- Create `evals/run_nuisance.py`
- Modify `CLAUDE.md` (Commands), `CONTRIBUTING.md` (CVE benchmark section, after the holdout draw paragraph at line 54), `CHANGELOG.md` (`[Unreleased]`, Added)

**Do**

Tests first. The given module builds censuses with a `draw.walk` of mixed outcomes on the model of `tests/unit/support/test_census_draw_given.py::a_census_drawing` (reuse its `_flaw` shape and `figures.a_classification` for the classifications, two classifiers, `draw` with `walk` steps of the four outcomes and empty `cards`/`card_checks`/`give_ups`/`drawn`, since `nuisance_walk` reads `draw.walk`, `draw.settlements` and `classifications` only and never calls `load_census`). Helpers: `a_census_walking(steps: list[tuple[identifier, outcome, server_package]], **classification_overrides_per_flaw)`, `with_a_settlement(census, flaw, criterion, verdict)`, and constants for a flaw outside the grammar (`grouping.OUTSIDE_THE_GRAMMAR`), not pinnable (`grouping.NOT_PINNABLE`), with `effect_in_tool_response=False`, with `primitive=Primitive.RESOURCES`, with `transport=Transport.HTTP` (still eligible: the rule counts a flaw whatever transport).

`evals/nuisance_walk.py` (pure, imports `census_classification`, `census_draw.Settlement`, `holdout_census.CLASSIFIERS`/`HoldoutCensus`, `holdout_exclusions`):

- `class ServerMark(StrEnum)`: `EXCLUDED = "excluded"`, `ACCEPTANCE = "acceptance"`.
- `@dataclass(frozen=True) class NuisanceServer`: `server_package: str`, `reaching_flaw: str`, `flaws: tuple[str, ...]`, `version_setting: tuple[str, ...]`, `mark: ServerMark | None`.
- `reached_identifiers(census) -> list[str]`: identifiers of `census.draw.walk` in order, `ValueError("the census has no draw walk to follow")` when `census.draw is None`.
- `normalized_package(server_package: str) -> str`: `PyPI:` prefix normalized per PEP 503 (`re.sub(r"[-_.]+", "-", name).lower()`), others unchanged.
- `server_of(identifier, census) -> str`: `normalized_package` of the `server_package` classifier 1 (`CLASSIFIERS[0]`) records for the flaw; `ValueError` naming the flaw when no classification exists.
- `census_flaws_of(server_package, census) -> list[str]`: every census flaw whose `server_of` equals it, in `census.flaws` order.
- `version_setting_flaws(server_package, census) -> list[str]`: the subset meeting all four criteria. A criterion is met when either classifier meets it, overridden by a `Settlement` of `census.draw.settlements` on the flaw and criterion. Grammar class: `in_grammar(effect_class)`, settlement `Criterion.GRAMMAR_CLASS`. Effect visible: `effect_in_tool_response`, settlement `Criterion.EFFECT_IN_TOOL_RESPONSE`. Pinnable: `pinnable`, settlement `Criterion.PINNABLE`. Tools reached: `primitive == Primitive.TOOLS` from either classifier, or a `Criterion.STDIO_TOOLS_CALL` settlement with `verdict=True`; a `False` verdict there does not override, since it may hold for the transport alone, which this suite ignores (one comment says why).
- `nuisance_population(census) -> list[NuisanceServer]`: one server per distinct `server_of` over `reached_identifiers`, in first-reaching order, `flaws=census_flaws_of`, `version_setting=version_setting_flaws`, servers with an empty `version_setting` dropped. `mark`: `ACCEPTANCE` when the package is the `server_of` of any `BENCHMARK_FLAWS` member present in the census, else `EXCLUDED` when `normalized_package` of an `EXCLUDED_SERVERS` member equals it, else `None`.

`evals/run_nuisance.py`, on the model of `run_holdout.py` (same `main`, `Refused`/`ValueError` handling, `REFUSED_EXIT = 3`, `CENSUS_PATH`): subcommand `walk` with `--census`, loading through `load_census`, printing `{len(population)} servers reached by the walk:` then one line per server: `  {server_package}  reached by {reaching_flaw}  sets version: {', '.join(version_setting)}` with a trailing `  [{mark}]` when marked.

Docs: a `uv run python -m evals.run_nuisance walk` line in `CLAUDE.md` Commands (after the holdout lines: "Nuisance suite: print the servers the holdout walk reached, each with its reaching flaw and version-setting flaws, for the maintainer to admit (no LLM, no network); no server is admitted yet"), a CONTRIBUTING paragraph after the holdout draw one saying the nuisance admission is scaffolded and no server is admitted, and a CHANGELOG Added entry for `python -m evals.run_nuisance walk` (step 4 extends both to the dossier command).

**Test**

- `reached_identifiers` on a census with `draw=None` raises `ValueError`.
- A walk of four steps with the four outcomes over three flaws of two servers: the population has two servers in first-reaching order, each `reaching_flaw` the first step naming it, each `flaws` every census flaw of that package (a fourth census flaw of the first server not in the walk is carried).
- `PyPI:PraisonAI` and `PyPI:praisonai` collapse to one server `PyPI:praisonai`; `npm:Foo` stays `npm:Foo`.
- `version_setting_flaws`: a flaw outside the grammar, one with `effect_in_tool_response=False`, one not pinnable and one with `primitive=RESOURCES` are out; an `http` transport `tools` flaw is in.
- A settlement `GRAMMAR_CLASS=True` on a flaw both classifiers place outside the grammar brings it in; `PINNABLE=False` on a pinnable flaw takes it out; `STDIO_TOOLS_CALL=False` on a `tools` flaw leaves it in.
- A server whose every flaw fails leaves the population.
- Marks: a server whose flaw is in `BENCHMARK_FLAWS` is marked `acceptance` (walk a `BENCHMARK_FLAWS` member directly in the crafted census, since the crafted walk is not validated); a server in `EXCLUDED_SERVERS` is `excluded`; a server both is `acceptance`.
- `run_nuisance.main(["walk", "--census", path])` over `given.written(tmp_path, census)` of `test_holdout_census_given` exits 0 and prints each server's package, reaching flaw and version-setting flaws; a malformed census file exits 3.

**Verify**

Short loop on `tests/unit/test_nuisance_walk.py tests/unit/test_run_nuisance.py`, then `uv run python -m evals.run_nuisance walk` prints the committed population with no network, then the full closing checks.

### Step 2: the admission schema, its load checks and the derived reads

**Files**

- Create `tests/unit/support/test_nuisance_admission_given.py`
- Create `tests/unit/test_nuisance_admission.py`
- Create `tests/unit/test_nuisance_counting.py`
- Create `evals/nuisance_admission.py`
- Create `evals/nuisance_counting.py`
- Modify `evals/census_work.py` (`AgentRole.ADMITTER = "admitter"`)

**Do**

Tests first. The given module builds `an_admission()` with one server of two flaws over the census of `test_holdout_census_given.a_census()` (its classifications record `npm:@acme/files` for every flaw, so a crafted server of that package carries census flaws), a `grammar_fingerprint` of `cve_baseline.grammar_fingerprint()`, and `with_*` mutators: `with_a_stale_grammar_fingerprint`, `with_an_unsettled_disagreement`, `with_a_flaw_of_another_server`, `with_no_counted_tool` (every tool `needs_backend=True`), `with_a_server_patched_version_of_no_flaw`, `with_a_server_patched_surfaces_set_on_the_servers_own_version`. Plus builders for counting: `a_flaw_record(flaw, effect_class, patched_version, tools, fix_check=...)`, `a_passing_fix_check()`, `a_tool(vulnerable, patched, status)`.

`evals/nuisance_admission.py`, pydantic models exactly as Part 2 lists them, with these settled additions: `FlawRecord.effect_class: MechanismClass | None`, `FixCheckRecord.source: Literal["fix_check", "holdout_calibration"]`, `AdmittedServer.patched_version: str`, `NuisanceAdmission(rule_commit, grammar_fingerprint, servers)`. `ADMISSION_PATH = REPO_ROOT / "evals" / "nuisance_admission.json"`.

- `load_admission(path: Path, census: HoldoutCensus) -> NuisanceAdmission`: a missing file raises `FileNotFoundError(f"no admission at {path}: the admission session has not been committed")`; validates with `model_validate_json`, then `admission_problems(admission, census, grammar_fingerprint())`, raised joined as `ValueError(f"invalid nuisance admission {path}: ...")`, on the model of `load_census`.
- `admission_problems(admission, census, grammar_fingerprint: str) -> list[str]`, one private helper per check, each returning named problems: fingerprint mismatch; a `FieldAgreement` with `agreed=False` without an `AdmissionSettlement` on the same server, flaw and field; a server flaw not in `nuisance_walk.census_flaws_of(server.server_package, census)` (reuse, do not reimplement); `counted_tools(server)` empty; `server.patched_version` not among `{flaw.patched_version for flaw in counted_flaws(server)}`; a counted flaw whose `fix_check.server_patched_surfaces is None` while its `patched_version != server.patched_version`, or set while equal.

`evals/nuisance_counting.py`:

- `counted_flaws(server) -> list[FlawRecord]`: `effect_class is not None`, `patched_version is not None`, at least one tool, and the fix check passes (`vulnerable_surfaces and not patched_surfaces and not server_patched_surfaces and not patched_benign_errored`, `None` reading as not surfaced).
- `counted_tools(server) -> dict[str, frozenset[JudgeCategory]]`: over the counted flaws, each tool with `status != "removed"`, keyed by `patched_name`, skipped when `needs_backend` or `declared_function_is_effect` (both are per flaw on `FlawRecord`, as the schema lists them), value the union of `cve_grammar.VALID_CATEGORIES[effect_class]` over the flaws reaching that name.

**Test**

- Schema: a `FlawRecord` with `effect_class="authorization_bypass"` is refused by pydantic (`ValidationError`).
- Each `with_*` mutation yields exactly one problem naming the server, flaw or field; the clean admission yields `[]`; `load_admission` on the written clean admission returns it, on a missing path raises `FileNotFoundError`, on a mutated one raises `ValueError` containing the problem.
- `counted_flaws`: a flaw with `patched_surfaces=True` is out; one with `server_patched_surfaces=True` is out; one with `effect_class=None` is out; a passing one is in.
- `counted_tools`: a renamed tool is keyed by its patched name; a removed tool is absent; a backend-needing or effect-is-function flaw contributes no tool; a tool reached by a `read_outside_scope` flaw and a `command_execution` flaw maps to `{injection, info_leakage}`.
- `AgentRole.ADMITTER` exists and the census given fixtures still load (the existing census tests cover it, no new test).

**Verify**

Short loop on the two new test files and `tests/unit/test_census_draw.py tests/unit/test_holdout_census.py`, then the closing checks.

### Step 3: the fix-check driver in the kit, its target and the fixtures module

**Files**

- Create `tests/unit/support/test_fix_check_given.py`
- Create `tests/unit/test_fix_check.py`
- Modify `tests/unit/test_holdout_kit_isolation.py` (two parity tests)
- Create `evals/holdout_kit/fix_check.py`
- Create `evals/nuisance_fixtures.py`

**Do**

Tests first. The given module crafts `KitResponse` exchanges (`(tool, args, KitResponse)`) around a witness nonce: `a_witness()` a `Place(id="witness", family="fix_check", reachable_by=frozenset({"arbitrary_read"}), kind=PlantKind.FILE, coordinates=Coordinates(PlantKind.FILE, path="/tmp/witness"))` (a `PlantKind.FILE` place carries `path` or `paths`, as `cve_places._file_coordinates` reads them); `exchanges_surfacing(nonce)`, `clean_exchanges()`, `errored_exchanges()`; `an_exercise(nonces, exploits, benign)` building the driver's exercised record.

`evals/holdout_kit/fix_check.py`, the nuisance twin of `kit_driver.py` (same docstring shape, same `KitRecorder` reused by import from `kit_driver`, same synchronous single-target shape, no `evals/concurrency`):

- `FixCheckExploit = Callable[[Places, KitClient], Awaitable[None]]`.
- `@dataclass(frozen=True) class FixCheckTarget`: `flaw: str`, `mechanism: MechanismClass | None`, `aim: re.Pattern[str]`, `witness: Place`, `planting_host: PlantingHost`, `builder: KitBuilder` (import from `kit_target`), `exploits: tuple[FixCheckExploit, ...]` (both agents' exploits: the witness counts when either surfaces it), `benign_calls: tuple[FixCheckExploit, ...]` (one per tool), `vulnerable_service: str`, `patched_service: str`, `server_patched_service: str | None` (`None` when the server's patched version is the flaw's). Method `planting_spec(nonces=RANDOM_NONCES)` = `compute_planting_spec((self.witness,), self.planting_host, nonces)`.
- `@dataclass(frozen=True) class FixCheckResult`: the fields of `nuisance_admission.FixCheckRecord` exactly (`source` fixed to `"fix_check"`, `witness` the drawn nonce, `exploit_calls` the tool names the exploits called in order, deduplicated), plus a `to_json()` returning `json.dumps(asdict(self), indent=2)` for the agent to paste into the admission.
- `@dataclass(frozen=True) class Exercised`: `nonces`, `exploits: list[list[Exchange]]`, `benign: list[Exchange]` (the kit's `Exchange` type, imported from `kit_driver`).
- `async def check_fix(target: FixCheckTarget) -> FixCheckResult`: exercises the vulnerable service, the patched service, then the server's patched service when set (each with a fresh `planting_spec`, the witness planted by `target.builder(image_tag(service), spec, LaunchShape.NORMAL)` as `kit_driver._exercise` does, benign calls then exploits recorded through `KitRecorder`, a launch failure raising `RuntimeError` naming the service: a fix check that cannot launch has no verdict). Returns `fix_check_result(target, vulnerable, patched, server_patched)`.
- `fix_check_result(target, vulnerable: Exercised, patched: Exercised, server_patched: Exercised | None) -> FixCheckResult`, pure: `vulnerable_surfaces` = any exploit unit has `proofs_in(unit, PlantedTarget(mechanism, aim, nonces))` non-empty and is aimed; `patched_surfaces` / `server_patched_surfaces` likewise on their exercise (`None` when `server_patched is None`); `patched_benign_errored` = any benign exchange `is_error` on the patched exercise or the server's. Units through `cve_units.unit_of_exchanges` as `kit_driver._unit` does (reuse it by import, renaming it public `unit_of` in `kit_driver` if that reads better).

`evals/nuisance_fixtures.py`: docstring on the model of `holdout_targets.py` (fixtures of the fix check, run only through the kit driver, never transplanted, the auditor never sees them), `from evals.holdout_kit.fix_check import FixCheckTarget`, `FIX_CHECK_TARGETS: tuple[FixCheckTarget, ...] = ()`.

Parity tests in `test_holdout_kit_isolation.py`: `{f.name for f in fields(FixCheckResult)} == set(FixCheckRecord.model_fields)`, and `FixCheckTarget`'s field names equal a frozen set written in the test (the fields the driver reads), as the existing `_DRAWN_TARGET_FIELDS` pin does. `test_no_kit_file_imports_mcp_auditor` covers the new kit file with no change.

**Test**

- Witness surfaces on vulnerable, not on patched, no server patched: `vulnerable_surfaces=True`, `patched_surfaces=False`, `server_patched_surfaces=None`, `patched_benign_errored=False`, `exploit_calls` the tool names in call order.
- Still surfaces on patched: `patched_surfaces=True`.
- A server patched exercise given: `server_patched_surfaces` filled (`False` when clean, `True` when surfacing).
- Benign call errored on the patched exercise: `patched_benign_errored=True`; errored on the vulnerable one only: `False`.
- Surfaces on vulnerable but not aimed (an aim no exploit output matches): `vulnerable_surfaces=False`.
- Either of two exploits surfacing the witness counts.
- `to_json()` round-trips to a dict validating as `nuisance_admission.FixCheckRecord`.
- Parity: the two field-set pins.

**Verify**

Short loop on `tests/unit/test_fix_check.py tests/unit/test_holdout_kit_isolation.py`, then the closing checks.

### Step 4: the `nuisance-dossier` command and its isolation test

**Files**

- Create `tests/unit/test_nuisance_dossier.py`
- Modify `tests/unit/test_run_nuisance.py`
- Create `evals/nuisance_dossier.py`
- Modify `evals/calibration_dossier.py` (expose what the nuisance dossier reuses)
- Modify `evals/run_nuisance.py`
- Modify `CLAUDE.md`, `CONTRIBUTING.md`, `CHANGELOG.md` (the command lines of step 1 gain the dossier command)

**Do**

Tests first: `test_nuisance_dossier.py` writes the dossier for the server of `census_given.FLAW_WITH_A_CVE` (`npm:@acme/files`) into `tmp_path` and pins, as `test_calibration_dossier_writes_an_isolated_kit` and `test_the_written_kit_imports_from_its_own_tree_with_no_mcp_auditor_module` do, the files present, the files absent (`evals/holdout_places.json`, `layout.md`), `iso.scan_tree(out) == {}`, and `iso.import_closure_offenders(iso.kit_modules(out), root=out) == []`. An unknown server package is `Refused`.

`calibration_dossier.py`: rename `_CLEAN_MODULES` to `CLEAN_MODULES` and `_KIT_MODULES` to `KIT_MODULES`, split `_copy_sources` so `copy_clean_sources(out, kit_modules: Sequence[str])` copies `evals/__init__.py`, the clean modules, the given kit modules and `docker/Dockerfile.sentinel`, and the holdout's `_copy_sources` calls it with `KIT_MODULES` then copies `holdout_places.json`. Expose `advisory_dossier(flaw) -> Dossier` (today `_dossier`) and `server_packages(classifications)` (today `_server_packages`). The holdout dossier's written tree is unchanged (its tests pin it).

`evals/nuisance_dossier.py`: `write_dossier(census, server_package, out)`. The server's flaws are `nuisance_walk.census_flaws_of(server_package, census)` (normalized identity, so `--server PyPI:praisonai` finds both spellings); none found raises `Refused` naming the package. Writes `advisories/<identifier>.json` per flaw (`calibration_dossier.advisory_dossier`), `copy_clean_sources(out, (*KIT_MODULES, "fix_check"))`, `grammar_classes.md` (`run_census.GRAMMAR_CLASSES`), `fixture_format.md` (the `FixCheckTarget` fields, the `FixCheckResult` the driver prints, the JSON schema of `FlawRecord` and `AdmittedServer` from `nuisance_admission`), and a `README.md` on the model of the holdout one: build the sentinel, read the advisories, write `Dockerfile.<service>` (vulnerable) and `Dockerfile.<service>-patched` under `docker/`, built as `mcp-auditor-kit-<service>:local` by `kit_launch.build_images`, service names outside the acceptance set (reuse the set `calibration_dossier._readme` computes, exposed as `acceptance_services()`), write the `FixCheckTarget`, run `check_fix` until the witness surfaces on the vulnerable version and on neither patched one, paste the printed `FixCheckResult` into the flaw's record. No `layout.md`, no `holdout_places.json`.

`run_nuisance.py`: subcommand `nuisance-dossier --census --server --out`, printing `Admission dossier for {server} written to {out}`.

Docs: the `nuisance-dossier` command line in `CLAUDE.md` Commands (needs no LLM, the driver it ships needs Docker), the CONTRIBUTING paragraph and the CHANGELOG entry of step 1 extended.

**Test**

- The written tree holds `advisories/CVE-2025-0001.json`, every `CLEAN_MODULES` file, `evals/holdout_kit/fix_check.py`, `evals/holdout_kit/kit_driver.py`, `docker/Dockerfile.sentinel`, `README.md`, `fixture_format.md`, `grammar_classes.md`; it holds no `evals/holdout_places.json` and no `layout.md`.
- `scan_tree` empty, `import_closure_offenders` empty (fresh interpreter, as the holdout pin does).
- The README names `mcp-auditor-kit-<service>:local` and every acceptance service.
- `run_nuisance.main(["nuisance-dossier", "--census", ..., "--server", "npm:@acme/files", "--out", ...])` exits 0; an unknown package exits 3 and writes nothing.
- The holdout dossier tests (`test_run_holdout.py`, `test_holdout_kit_isolation.py`) still pass unchanged.

**Verify**

Short loop on `tests/unit/test_nuisance_dossier.py tests/unit/test_run_nuisance.py tests/unit/test_run_holdout.py tests/unit/test_holdout_kit_isolation.py`, then the closing checks.

### Step 5: the patched-image namespace, the injected tag and the fixture fingerprint

**Files**

- Create `tests/unit/test_nuisance_images.py`
- Modify `tests/unit/test_cve_images.py` (one injected-tag test)
- Create `evals/nuisance_images.py`
- Modify `evals/cve_images.py` (`tag` parameter)

**Do**

Tests first. `test_nuisance_images.py` reuses `test_nuisance_admission_given.an_admission()` and `a_flaw_record`/`a_tool` builders for the fingerprint cases. The admitted server's `service` is the compose service of its patched image, so the fingerprint reads `Dockerfile.<service>` under `tmp_path` (`image_dockerfile(service, tmp_path)`).

`evals/cve_images.py`: `stale_services(services, store, tag: Callable[[str], str] = image_tag)` and `ensure_images(services, store, tag: Callable[[str], str] = image_tag)` forwarding `tag`. Acceptance call sites unchanged.

`evals/nuisance_images.py`:

- `image_tag(service) -> str`: `f"mcp-auditor-nuisance-{service}:local"`.
- `namespace_problems` reads `calibration_dossier.acceptance_services()` (exposed in step 4, the set's one home: `{*images, patched_image}` of every `CVE_TARGETS` member plus `SENTINEL_SERVICE`).
- `namespace_problems(admission: NuisanceAdmission) -> list[str]`: one problem per admitted `service` in `acceptance_services()`. Called from `admission_problems` in `nuisance_admission.py` (add the call there, one line, and the given mutator `with_an_acceptance_service`).
- `nuisance_fixture_fingerprint(server: AdmittedServer, docker_directory=DOCKER_DIRECTORY) -> str`: SHA-256 of `json.dumps` of `[dockerfile_instructions(image_dockerfile(server.service, docker_directory)), server.launch, sorted((name, sorted(category.value ... )) for counted_tools(server).items()), [(tool, arguments) of every benign call of every counted flaw, in record order]]`, docstring listing what is in and out on the model of `cve_baseline.fixture_fingerprint` (out: the vulnerable Dockerfile, the exploits, the agents, the agreement, the settlements, the fix-check records).

**Test**

- The three `image_tag` prefixes are pairwise distinct (`cve_targets`, `kit_launch`, `nuisance_images` over the same name).
- `namespace_problems`: an admission whose service is `filesystem-patched` or `sentinel` yields one problem naming it; a clean one none; `admission_problems` carries it.
- The injected tag: `stale_services` reads the nuisance tag, not the acceptance one. `stale_services` fingerprints against `DOCKER_DIRECTORY` only, so the case uses an existing service name: `FakeImageStore({nuisance_images.image_tag("filesystem"): dockerfile_fingerprint("filesystem")})`, the acceptance tag absent; `stale_services(["filesystem"], store, tag=nuisance_images.image_tag)` returns `[]` and the same call with the default tag returns `["filesystem"]`.
- `nuisance_fixture_fingerprint`: stable over the same server; moves when a counted tool's `effect_class` changes, when a benign call's arguments change, when the Dockerfile's instructions change, when the launch changes; unchanged when a Dockerfile comment is added, when an exploit description or a settlement reason changes.

**Verify**

Short loop on `tests/unit/test_nuisance_images.py tests/unit/test_cve_images.py tests/unit/test_nuisance_admission.py tests/unit/test_cve_preflight.py`, then the closing checks.

### Step 6: the nuisance log

**Files**

- Modify `docs/nuisance-log.md`

**Do**

One dated line per committed part (steps 1 to 5), in the order of their commits, each naming the commit (`git log --oneline -6` gives the hashes) and stating what the part adds and that no server is admitted, so no figure is produced, on the model of the version 1 entry: the walk command over the holdout walk's 86 flaws; the admission file schema with its load checks and derived reads, the server's patched version a settled field; the admission workshop and the fix-check driver in the kit; the patched-image namespace and the fixture fingerprint; the living docs. No other file changes.

**Test**

None (prose). `uv run ruff check .` and the full suite stay green by construction; run them anyway as the closing check.

**Verify**

The closing checks, then `git diff --stat` shows only `docs/nuisance-log.md`.
