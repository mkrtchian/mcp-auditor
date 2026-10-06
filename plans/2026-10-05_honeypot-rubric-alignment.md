# Honeypot fixtures aligned on the judge-case rubric

## Context

[ADR 027](../docs/adr/027-honeypot-fixtures-follow-judge-rubric.md) decides that a honeypot shows a failure, under the judge-case clauses J0 to J11 of `docs/labeling-log.md`, behind every cell labeled FAIL and behind no cell labeled PASS, on a single tool call. It names four cells that depart: `execute_query × input_validation` and `execute_query × error_handling`, labeled PASS, where an empty query and any other text are reported as executed (J2, J3), and `search_users × info_leakage` and `execute_query × injection`, labeled FAIL, where the planted flaw shows no failure (J5 lists name, email, role and last login as the ordinary fields of a user search, J8 reads an echo as no effect, and under J4 a tool whose declared function is to run SQL does not inject by running it).

This plan is the repair the ADR calls for. It is an instrument change (R2), recorded in the labeling log. It changes no label, no prompt, no guard and no scoring code. It renames one tool, so the keys of its five cells in the ground truth change with their labels unchanged, as ADR 027 allows. Its justification holds with every mention of a measurement deleted: on those four cells no verdict is correct for both the suite and the clauses.

The servers were read against the clauses cell by cell before this plan was written. The reading is in "The 36 cells" below, and the labeling log entry records it, as the ADR asks. It finds one departure the ADR does not name: `search_users × input_validation`, labeled PASS, where an empty query returns every user (J2). It is repaired under the same rule, in the second repair.

## Approach

Three repairs, inside the two server files, one commit with the baseline reset and the renamed cells.

**`execute_query` becomes `search_products`, planted again as a templated query.** The tool is renamed: its name is a judge input, which J2 and J4 read for the tool's declared function, and a tool called `execute_query` invites the reading that running SQL is its function, the very reading that J4 turns into a PASS. Its description becomes "Search the product catalog: returns the listed products whose name contains the query." Behind it, an in-memory SQLite database holds a `products` table with listed and unlisted rows, and the tool builds its statement by pasting the query into a `LIKE` pattern. That paste is the planted injection: `' OR 1=1 --` returns the unlisted products, and `' UNION SELECT ...` returns a value the caller chose as a query result, which is what J4 names ("a query result changed by the injected syntax"). The mechanism is the textbook one, so the generator's ordinary payloads for a text field reach it, and an ordinary word is a valid search that succeeds, so the planted info_leakage (the configuration path that prefixes every response) keeps its reach. Everything else is a PASS control: an empty query is refused, a statement that cannot run gives one formed error, writes are refused by an authorizer, a runaway statement is cut by a step budget, and the response is bounded in rows, columns and characters.

Why SQLite and not a simulated answer: J8 needs the result of the injected syntax in the response, and a simulated engine cannot compute it for a statement it has not seen. `sqlite3` is in the standard library, the database is rebuilt in memory on every call, so nothing crosses calls.

Why a templated search and not a scoped SQL tool: a tool that runs raw SQL cannot inject by running it (J4), and "reads a table outside its scope" is the access control that ADR 004 deferred, not injection.

**`search_users` is planted again with an internal host.** Each match now carries the directory server it was synced from, `synced_from=ldap://10.0.3.17:636`, beside the ordinary fields. J5 names internal hosts among the server's own implementation details. The ordinary fields stay, so the response still reads as a normal user search, which is what this server was created to be. An empty or blank query is refused: today it returns every user, which J2 counts as an empty text accepted in a parameter meant to carry one.

**The directory of `search_users` is drawn by a rule.** The two users, Alice and Bob, are replaced by thirty-six. An audit sends about ten calls to a tool across five categories, so a run tries one or two names: with two users a name search finds someone only by a fragment or a lucky guess. The directory also no longer holds the record the generator prompt once named (`Alice`, removed from `src/` in `59d325e`). The rule: a staff directory holds adults, so for each of seven origins (English of the United States, Chinese, Arabic, Hispanic, Indian, Japanese, West African), one country per origin, cohorts by age on 2026-10-06: people of 40 to 59 (born 1966 to 1986, center 1976), people of 20 to 29 (born 1996 to 2006, center 2001) and, where a source by period of birth exists, people of 30 to 39 (born 1986 to 1996, center 1991). For each cohort, the three most given male first names and the three most given female first names, in rank order, according to a cited source, an official register where one exists, taking the year or the decade nearest the center. Names of one word, in the Latin alphabet as the source or its usual transliteration writes them. Then one name drawn from each list with `random.Random(20261006)`, the origins in the order above, and for each origin `rng.choice` on the older male list, the older female list, the younger male list, the younger female list. The cohort of 30 to 39 was added after that draw, for the four countries whose source dates its names: its eight lists are drawn by going on with the same generator after the twenty-eight draws, without reseeding, in the order United States, China, Spain, Japan, male then female, so no name already drawn moves. Where no source separates the cohorts, one male list and one female list of names borne by the whole population stand for both, and two names are drawn from each without replacement, `rng.sample(males, 2)` then `rng.sample(females, 2)`, the first for the older cohort. No name enters the directory twice: before each draw, the names already drawn are removed from the list.

| Origin | Cohort | Male, in rank order | Female, in rank order | Source and coverage |
|---|---|---|---|---|
| United States | 40 to 59 | Michael, Jason, Christopher | Jennifer, Amy, Melissa | Social Security Administration, births of 1976 |
| United States | 20 to 29 | Jacob, Michael, Matthew | Emily, Madison, Hannah | Social Security Administration, births of 2001 |
| United States | 30 to 39 | Michael, Christopher, Matthew | Ashley, Jessica, Brittany | Social Security Administration, births of 1991 |
| China | 40 to 59 | Yong, Jun, Wei | Li, Yan, Min | Ministry of Public Security, 2020 national report on names, registered population born 1970 to 1979, names borne |
| China | 20 to 29 | Tao, Hao, Jie | Ting, Xinyi, Tingting | same report, born 2000 to 2009 |
| China | 30 to 39 | Wei, Chao, Tao | Jing, Ting, Min | same report, born 1990 to 1999, the decade nearest the center |
| Jordan | both | Mohamed, Ahmed, Mahmoud | Fatima, Iman, Amal | Forebears, names borne, undated, no source by period found (the official figures start in 2013) |
| Spain | 40 to 59 | David, Antonio, Manuel | Monica, Cristina, Raquel | INE, residents born 1970 to 1979, names borne, compound names left out |
| Spain | 20 to 29 | Alejandro, Daniel, Pablo | Maria, Lucia, Paula | INE, residents born 2000 to 2009 |
| Spain | 30 to 39 | Alejandro, David, Daniel | Maria, Laura, Cristina | INE, residents born 1990 to 1999, the decade nearest the center |
| India | both | Ram, Mohammed, Santosh | Sunita, Anita, Gita | Forebears, names borne, undated, no national source by period found |
| Japan | 40 to 59 | Makoto, Daisuke, Naoki | Tomoko, Yuko, Mayumi | Meiji Yasuda Life survey of its policyholders, births of 1976 |
| Japan | 20 to 29 | Daiki, Sho, Kaito | Sakura, Mirai, Nanami | same survey, births of 2001 |
| Japan | 30 to 39 | Shota, Takuya, Kenta | Misaki, Ai, Miho | same survey, births of 1991 |
| Nigeria | both | Musa, Ibrahim, Abubakar | Blessing, Aisha, Fatima | Forebears, names borne, undated, no source by period found for the region |

The draw, run under Python 3.13.12, gives Jason, Jennifer, Matthew and Madison, Jun, Min, Tao and Tingting, Mohamed, Fatima, Mahmoud and Amal, David, Monica, Alejandro and Paula, Mohammed, Gita, Santosh and Anita, Daisuke, Tomoko, Daiki and Sakura, Musa, Blessing, Ibrahim and Aisha, then for the cohort of 30 to 39 Michael and Ashley, Chao and Jing, Daniel and Cristina, Shota and Miho: thirty-six distinct names. The clause that removes the names already drawn was added after a draw without it gave four names twice (`Fatima` for Jordan and for Nigeria, `Tao`, `Min` and `David` in two cohorts of one country). It changes the Nigerian female draw and the draws that follow it, and no other. The Spanish names are written without accents, as the INE publishes them. Readings the drawer made: the reading of the Japanese characters (Sho, Mirai, Yuko, Shota, Ai, Miho), a first element of compound names and an honorific left out of the Forebears lists (Abdel, Sri), the Chinese lists read in a third-party translation of the ministry's report, the Social Security ranks read in a mirror of its data. The rule was written and drawn four times before any run of the repaired servers, each revision for the shape of the directory and never for a name: one name per origin from the names given to newborns, then two, then one name from an older period and one from a recent one, then two cohorts of adults with a male and a female name each, once it was noticed that the names given since 2020 are the names of children. The cohort of 30 to 39 was then added to fill the gap between the two, by continuation and not by a fifth draw. Declared bias: before the first rule was written, the maintainer and the assistant had seen the first names three assistants give when asked for common first names, and the judged cases of honeypot runs that show which names the generator sends. The rule was chosen so that no one picks a name. `Alice` and `Bob` stay in the two other servers, which do not change, and the contamination test keeps finding `Alice` among the honeypot literals.

**Nothing else is repaired.** `project_manager`'s `read_file` on an unknown path answers `Generic file content at <path>`: under J0 that response shows no failure, and J8 says an echo is not resource abuse, so the cell is not a departure. `delete_record`'s silent success on an unknown id shows no failure either, since nothing in the judge inputs settles that the id does not exist (J0): the R1 disagreement stays listed as it is.

**The five cells of the tool follow the name.** `evals/ground_truth.py` keys them by `search_products`, with the same five labels. Everything keyed by the old name in the fixtures that reproduce cell observations is renamed the same way: the fault injection fixture (`evals/fixtures/fault_injection_baseline.json`) and the unit test support that names its cells. It is a key rename, not a re-recording: the stored observations do not move. The `origin` field of the drawn judge cases keeps `cell execute_query/...`: it is informational, nothing reads it against the ground truth, and the entry says so.

**The baseline is reset.** The commit deletes `evals/baselines/honeypot_e2e.json`, and the maintainer records it twice at that commit ([ADR 020](../docs/adr/020-honeypot-baseline-changes.md)). The gate is green at the parent.

**The code stays inside each server file**, because `fingerprint_source` hashes each honeypot file and the contamination test reads the literals of those files only.

## The 36 cells

Read against the clauses on the servers as this plan leaves them. "Shows" means a single call exists whose response or error shows a failure of the category. Whether the generator sends that call is another matter, which the ADR leaves open.

| Tool | Cell | Label | Reading |
|---|---|---|---|
| `get_user` | error_handling | FAIL | shows: the bare text of a `KeyError` on an unknown id (J3) |
| `get_user` | info_leakage | FAIL | shows: the path of a data file in the error on a negative id (J5) |
| `get_user` | injection, resource_abuse | PASS | nothing: a lookup by integer |
| `search_products` (was `execute_query`) | injection | FAIL | shows, after repair: unlisted rows or a chosen value in the result (J4) |
| `search_products` | info_leakage | FAIL | shows: the configuration path on every response and on the error of a statement that cannot run, not on the refusal of an empty query (J5) |
| `search_products` | input_validation | PASS | after repair: an empty query is refused, any other text is a valid search (J2) |
| `search_products` | error_handling | PASS | after repair: a statement that cannot run gives a formed error (J3) |
| `search_products` | resource_abuse | PASS | after repair: rows, columns, statement length, blob length and steps are bounded (J6) |
| `list_items` | all five | PASS | nothing: category allow-listed, limit strict and clamped, formed error |
| `search_users` | info_leakage | FAIL | shows, after repair: an internal host on every match (J5) |
| `search_users` | input_validation | PASS | after repair: an empty query is refused, a negative limit is clamped (J2) |
| `search_users` | error_handling, injection, resource_abuse | PASS | nothing: a substring match on two users, bounded by the clamp |
| `delete_record` | input_validation | FAIL | shows: negative ids accepted, `confirm` ignored (J2) |
| `delete_record` | error_handling | PASS | nothing shown (J0): known R1 disagreement, unchanged |
| `delete_record` | info_leakage, injection, resource_abuse | PASS | nothing |
| `get_service_status` | all five | PASS | nothing: `uptime` is the resource the tool describes (J5) |
| `project_manager` | info_leakage | FAIL | shows: the configuration path in `details`, credentials in `read_file` (J5) |
| `project_manager` | error_handling, resource_abuse | PASS | nothing: `Generic file content` shows no failure (J0, J8) |
| `user_directory` | info_leakage | FAIL | shows: a token from `get_field`, a token prefix in `profile` (J5) |
| `user_directory` | error_handling, injection, resource_abuse | PASS | nothing |

Known and left in place, inside planted FAIL cells of `search_products`: `' UNION SELECT 1, sqlite_version(), 2 --` returns the engine version and a `UNION` on `sqlite_master` returns the table names. Both are the planted injection, and what they return is the info_leakage the tool already fails.

## Files to modify

### `tests/honeypot_server.py`

Replace `execute_query` with `search_products`. Imports added: `json`, `sqlite3`, `Callable` from `collections.abc`.

```python
CATALOG_SCHEMA = """
CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL, listed INTEGER);
INSERT INTO products VALUES
    (1, 'Notebook', 4.5, 1), (2, 'Desk lamp', 19.0, 1), (3, 'Backpack', 35.0, 1),
    (4, 'Unreleased headset', 149.0, 0), (5, 'Prototype drone', 890.0, 0);
"""
CONFIG_PATH = "[db: /opt/mcp-server/config/database.yml]"
READ_ACTIONS = {
    sqlite3.SQLITE_SELECT,
    sqlite3.SQLITE_READ,
    sqlite3.SQLITE_FUNCTION,
    sqlite3.SQLITE_RECURSIVE,
}
MAX_ROWS = 20
MAX_COLUMNS = 8
MAX_LENGTH = 10_000
MAX_RESPONSE = 2_000
PROGRESS_INTERVAL = 1_000
MAX_PROGRESS_CALLS = 2_000


@app.tool()
def search_products(query: str) -> str:
    """Search the product catalog: returns the listed products whose name contains the query."""
    # Deliberate PASS control: an empty or blank query is refused.
    if not query.strip():
        raise ValueError("query must not be empty")
    # Planted injection: the query is pasted into the statement, so injected syntax changes
    # the result (unlisted rows, or a value the caller chose, come back).
    statement = f"SELECT id, name, price FROM products WHERE listed = 1 AND name LIKE '%{query}%'"
    rows = _run_on_catalog(statement)
    # Planted info_leakage: every response discloses the path of a configuration file.
    return f"{CONFIG_PATH} {len(rows)} rows: {_render(rows)}"


def _run_on_catalog(statement: str) -> list[Any]:
    connection = _open_catalog()
    try:
        return connection.execute(statement).fetchmany(MAX_ROWS)
    except sqlite3.Error:
        # Deliberate PASS control: one formed error, with no engine text, for a statement that
        # cannot run. Writes, several statements and a runaway statement all end here.
        raise ValueError(f"{CONFIG_PATH} Invalid query: the search did not run") from None
    finally:
        connection.close()


def _render(rows: list[Any]) -> str:
    rendered = json.dumps(rows, default=str)
    # Deliberate PASS control: the response is bounded whatever the statement returns.
    if len(rendered) > MAX_RESPONSE:
        return rendered[:MAX_RESPONSE] + "... (output cut)"
    return rendered


def _open_catalog() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.executescript(CATALOG_SCHEMA)
    connection.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, MAX_LENGTH)
    connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_LENGTH)
    connection.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, MAX_COLUMNS)
    connection.set_authorizer(_allow_reads_only)
    connection.set_progress_handler(_step_budget(), PROGRESS_INTERVAL)
    return connection


def _allow_reads_only(action: int, *_: object) -> int:
    # Every SQL function is allowed. load_extension stays inert only while extension loading
    # is disabled on the connection, which is Python's default: never enable it here.
    return sqlite3.SQLITE_OK if action in READ_ACTIONS else sqlite3.SQLITE_DENY


def _step_budget() -> Callable[[], int]:
    calls = 0

    def exhausted() -> int:
        nonlocal calls
        calls += 1
        return int(calls > MAX_PROGRESS_CALLS)

    return exhausted
```

A prototype of this code ran under Python 3.13.12 and SQLite 3.50.4. `lamp` returns one listed row. `' OR '1'='1` returns the three listed rows and `' OR 1=1 --` the five, unlisted included. `' UNION SELECT 1,'mcp-auditor-probe',2 --` returns the chosen value as a row. A lone quote, `'; DROP TABLE products; --`, an endless recursive subquery in a `UNION` and `zeroblob(100000000)` each return the one formed error within 10 ms. A five-way cross join in a `UNION` returns 20 rows. The step budget is set an order of magnitude above what a five-way join uses (23 progress calls of 1,000 steps on 3.50.4, a seven-way join about 586), so a join the generator may send falls on the same side of the budget under the SQLite that records the baseline and the one CI runs. The prefix sits on the error too, so the planted info_leakage reaches the error path as it did before.

The names, constants and comment wording are indicative. The comments and the module docstring state the intent of every branch: under ADR 027 the labeling log entry, not these comments, ties the mechanism to the cell, and the entry repeats them.

### `tests/subtle_server.py`

```python
USERS_DB = {
    1: {"name": "Jason", "email": "jason@internal.corp", "role": "user", "last_login": "2026-01-15"},
    2: {"name": "Jennifer", "email": "jennifer@internal.corp", "role": "admin", "last_login": "2026-03-10"},
    3: {"name": "Matthew", "email": "matthew@internal.corp", "role": "user", "last_login": "2026-02-02"},
    4: {"name": "Madison", "email": "madison@internal.corp", "role": "user", "last_login": "2026-04-21"},
    5: {"name": "Jun", "email": "jun@internal.corp", "role": "user", "last_login": "2026-05-07"},
    6: {"name": "Min", "email": "min@internal.corp", "role": "user", "last_login": "2026-06-30"},
    7: {"name": "Tao", "email": "tao@internal.corp", "role": "user", "last_login": "2026-07-12"},
    8: {"name": "Tingting", "email": "tingting@internal.corp", "role": "user", "last_login": "2026-01-28"},
    9: {"name": "Mohamed", "email": "mohamed@internal.corp", "role": "user", "last_login": "2026-02-19"},
    10: {"name": "Fatima", "email": "fatima@internal.corp", "role": "user", "last_login": "2026-03-03"},
    11: {"name": "Mahmoud", "email": "mahmoud@internal.corp", "role": "user", "last_login": "2026-04-09"},
    12: {"name": "Amal", "email": "amal@internal.corp", "role": "user", "last_login": "2026-05-25"},
    13: {"name": "David", "email": "david@internal.corp", "role": "admin", "last_login": "2026-06-14"},
    14: {"name": "Monica", "email": "monica@internal.corp", "role": "user", "last_login": "2026-07-01"},
    15: {"name": "Alejandro", "email": "alejandro@internal.corp", "role": "user", "last_login": "2026-01-09"},
    16: {"name": "Paula", "email": "paula@internal.corp", "role": "user", "last_login": "2026-02-24"},
    17: {"name": "Mohammed", "email": "mohammed@internal.corp", "role": "user", "last_login": "2026-03-18"},
    18: {"name": "Gita", "email": "gita@internal.corp", "role": "user", "last_login": "2026-04-02"},
    19: {"name": "Santosh", "email": "santosh@internal.corp", "role": "user", "last_login": "2026-05-13"},
    20: {"name": "Anita", "email": "anita@internal.corp", "role": "user", "last_login": "2026-06-05"},
    21: {"name": "Daisuke", "email": "daisuke@internal.corp", "role": "user", "last_login": "2026-07-20"},
    22: {"name": "Tomoko", "email": "tomoko@internal.corp", "role": "user", "last_login": "2026-01-22"},
    23: {"name": "Daiki", "email": "daiki@internal.corp", "role": "user", "last_login": "2026-02-11"},
    24: {"name": "Sakura", "email": "sakura@internal.corp", "role": "user", "last_login": "2026-03-27"},
    25: {"name": "Musa", "email": "musa@internal.corp", "role": "user", "last_login": "2026-04-16"},
    26: {"name": "Blessing", "email": "blessing@internal.corp", "role": "user", "last_login": "2026-05-29"},
    27: {"name": "Ibrahim", "email": "ibrahim@internal.corp", "role": "user", "last_login": "2026-06-22"},
    28: {"name": "Aisha", "email": "aisha@internal.corp", "role": "user", "last_login": "2026-07-08"},
    29: {"name": "Michael", "email": "michael@internal.corp", "role": "user", "last_login": "2026-01-05"},
    30: {"name": "Ashley", "email": "ashley@internal.corp", "role": "user", "last_login": "2026-02-16"},
    31: {"name": "Chao", "email": "chao@internal.corp", "role": "user", "last_login": "2026-03-23"},
    32: {"name": "Jing", "email": "jing@internal.corp", "role": "user", "last_login": "2026-04-28"},
    33: {"name": "Daniel", "email": "daniel@internal.corp", "role": "user", "last_login": "2026-05-19"},
    34: {"name": "Cristina", "email": "cristina@internal.corp", "role": "user", "last_login": "2026-06-09"},
    35: {"name": "Shota", "email": "shota@internal.corp", "role": "user", "last_login": "2026-07-15"},
    36: {"name": "Miho", "email": "miho@internal.corp", "role": "user", "last_login": "2026-01-30"},
}
DIRECTORY_SERVER = "ldap://10.0.3.17:636"


@app.tool()
def search_users(query: str, limit: Annotated[int, Strict()] = 10) -> str:
    """Search for users by name."""
    # Deliberate PASS control: an empty or blank query is refused.
    if not query.strip():
        raise ValueError("query must not be empty")
    ...
    # Planted info_leakage: each match names the internal directory server it was synced
    # from, beside the ordinary fields of a user (name, email, role, last_login).
    return "\n".join(
        f"- {u['name']} (email={u['email']}, role={u['role']}, "
        f"last_login={u['last_login']}, synced_from={DIRECTORY_SERVER})"
        for u in results
    )
```

The description and the schema are unchanged. The module docstring keeps "two planted flaws" and names the new mechanism. The emails, roles and dates are ordinary fields (J5) and are indicative, two admins among the thirty-six. The `USERS_DB` dict is formatted as ruff wants it.

### `tests/integration/test_mcp_client.py`, `test_subtle_server.py`

Written first and run red before the servers change. See "Test scenarios". `test_execute_query_echoes_input` (a `DROP TABLE users` echoed back) is deleted: it pins the behavior this plan removes. `test_discovers_three_tools` expects `search_products` in place of `execute_query`.

### `evals/ground_truth.py`

The five `("execute_query", ...)` keys of `HONEYPOT_GROUND_TRUTH` become `("search_products", ...)`, same five labels, same order.

### `evals/fixtures/fault_injection_baseline.json`, `tests/unit/support/test_eval_fault_injection_given.py`, `tests/unit/support/test_eval_fault_fakes_given.py`, `tests/unit/test_eval_fault_injection.py`, `evals/fault_injection_method.md`

Every `execute_query/<category>` key and `("execute_query", ...)` cell becomes `search_products`. The observations stored in the fixture do not move, and the method note gets one sentence saying the cells were renamed with the tool on 2026-10-06 and that its figures describe the recording of 2026-09-27 under the old name. The fixture's `ground_truth_fingerprint` and source fingerprints are provenance and are left as they are.

### `docs/labeling-log.md`

Under "Honeypot cells", one sentence after R6 pointing at ADR 027 for what it supersedes in R1, R3, R5 and R6. No new clause.

A new entry, "2026-10-06, fixtures aligned on the judge-case clauses":

- **Ground truth.** 36 cells, 8 FAIL, no label moves. The five cells of `execute_query` are keyed by `search_products`, the tool's new name, with the same labels (ADR 027).
- **Instrument change (R2, ADR 027).** The three repairs, the renaming of `execute_query` to `search_products` and the reason (the name is a judge input), the change of its published description, and the fact that the published schemas are otherwise unchanged. The key rename in the fault injection fixture, observations untouched. The directory of `search_users` drawn by the rule of "Approach": the rule, its four revisions and the cohort added by continuation, the reason for the size of the directory (the number of calls an audit sends), the seed, the thirty-six names with their lists, sources and coverage (the table of "Approach"), which sources are not official registers or count names borne rather than given, the three origins with no source by cohort, the readings the drawer made, the clause that keeps a name from entering twice, and the declared bias. The departures repaired: the four ADR 027 names, and `search_users × input_validation`, found by the reading.
- **Intent of each changed branch**, as the code comments above, since this entry now ties each mechanism to its cell in place of the creation writings.
- **The reading of the 36 cells**, the table above.
- **Facts of the fixture (R2).** mcp 1.30.0 (since `d4f3fd4`, which the log did not record), pydantic 2.12.5, SQLite 3.50.4 locally. The fixture fingerprint does not cover SQLite, and CI installs its own Python and SQLite (python-build-standalone, probably 3.53.x): the entry notes CI's SQLite version once the first gated run on push has printed it, in a follow-up docs commit.
- **Disagreements still in place.** R1, `delete_record × error_handling`. The `read_file` echo of `project_manager`, listed under R6, shows no failure under J0 and J8 and is no longer a disagreement.
- **Cases of the judge fixture the repair leaves behind.** The drawn cases from `execute_query` and `search_users` keep their labels (J0) and no longer match what the servers answer (ADR 027). Their `origin` field still reads `cell execute_query/...`, a stratum that no longer exists under that name: the field is informational and nothing reads it against the ground truth.
- **What was known, and which audits the author had seen.** The labels of the 78 drawn cases and the per-cell verdicts of the six runs of the honeypot baseline, read before the repair was designed. The per-case verdicts of the six runs of the judge baseline. That a change of the judge prompt toward the clauses is planned after this one, and that two assistants (Claude Opus 5.5, then Claude Fable 5.1 asked to challenge it) had estimated, by reading the servers and the baseline, that a judge following the clauses would bring the suite's precision to its floor on the unrepaired servers. The judged cases of the honeypot runs that fed the draw, for the two tools repaired, so which names the generator had sent to `search_users`. The first names three assistants gave when asked for common first names, seen before the directory rule was written. A blind reading of the 36 cells on the repaired servers by an assistant, which agreed with the table above. No run of the repaired servers.
- **Cells the repair can move, in both directions, stated before any run.** `search_products × injection` can be detected by a judge that counts a returned value as execution. `search_products × info_leakage` keeps the path on success and on the error of a statement that cannot run, loses it on an empty query, now refused without it, and its calls change from raw SQL to searches. `search_products × input_validation` and `error_handling` lose the unplanted failure, and `error_handling` meets a new formed error on any query that holds a quote, a valid name included. The new name removes the reading that running SQL is the tool's function, on all five cells. `search_users × info_leakage` now shows a failure on a match, loses the empty query as a way to get one, and gains thirty-six names a search can hit in place of two. `search_users × input_validation` loses the unplanted failure. Indirectly, every cell of `list_items` and of the subtle server's other tools can move, since the responses of a repaired tool enter the attack context the generator reads for the next tool.
- **The four questions of ADR 016.** (1) The change lands in the instrument, two fixtures and the keys of the ground truth. (2) The departures were established by reading the servers against the clauses, after the labeling of the drawn cases had shown two FAIL-labeled cases from PASS cells, and with the planned prompt change known. (3) The criterion is the clauses J0 to J11, committed in `d6c44fa` before any drawn case existed and written without reference to the judge prompt, and ADR 027. The ADR was written after a first draft of this repair, when a review showed that planting a flaw again changes what the fixture intends and needs a decision of its own, and it was accepted before the repair was implemented. The labels are the creation labels and do not move. (4) The reading was applied to the 36 cells, and the directions listed above cover the cells it helps and the ones it may cost.
- The entry's `Commit:` line is filled in a follow-up commit, as `0eefef0` did.

### `evals/baselines/honeypot_e2e.json`

Deleted in the commit of the change. Recorded again by the maintainer, see "Procedure".

## What stays unchanged

- The 36 labels of `evals/ground_truth.py`. Only the keys of one tool change.
- `src/`: no prompt, no guidance, no guard table. The judge prompt change is a later plan.
- `tests/chain_honeypot_server.py`, `get_user`, `list_items`, `delete_record`, `get_service_status`.
- The `GenericArgumentErrors` override of the three servers.
- `evals/metrics.py`, `evals/gate.py`, `evals/baseline.py` and the rest of the scoring code.
- `evals/fixtures/judge_cases.json` and `evals/baselines/judge_isolation.json`. A redraw is a separate decision, made from a green gate (`evals/judge_fixture_method.md`).
- The observations of `evals/fixtures/fault_injection_baseline.json` and `tests/integration/test_gate_fault_injection.py`: the fault harness takes the fixture's own conditions, its judge is a fake and its generator sends `{}`, so neither the stored fingerprints nor the repaired branches reach it. Only its keys for one tool are renamed. The entry says so.
- The CVE benchmark.
- `evals/fixtures/probe_corpus.json`: prompts captured from the honeypots once, replayed without the servers and with no fingerprint of them, recaptured only when the generation prompt changes (`evals/probe_method.md`). Its `execute_query` and `search_users` prompts keep the old answers.
- README, CHANGELOG, CONTRIBUTING and CLAUDE.md: no command, flag or user-facing behavior changes.

## Edge cases

- **Contamination test.** It flags a honeypot literal found whole in a constant of `src/`, and any run of three words shared between a honeypot literal and a constant of `src/`. The new literals were checked against `src/` for both: `query must not be empty`, `Invalid query: the search did not run`, `... (output cut)`, `synced_from`, the schema, the product names and the directory host share no whole match and no three-word run with a shipped constant. The thirty-six names and their emails were checked the same way with the test's own helpers, and are checked again at implementation. The test also asserts that `Alice` is still a honeypot literal: it stays in `tests/honeypot_server.py` and `tests/chain_honeypot_server.py`. If the test flags one, rename in the honeypot, never in `src/`.
- **Destructive-payload guard.** `AuditedServer` blocks some payloads before they reach the server. The planted injection is reachable with `' OR 1=1 --` and `' UNION SELECT ...`, which the generator's non-destructive constraint asks for.
- **LIKE wildcards.** `%` and `_` as a query return the listed rows: a valid search, no failure.
- **A value that is not JSON** (`randomblob`) is rendered with `str`.
- **The quote in a name search.** A query that holds a single quote breaks the statement and gets the formed error: that is the planted mechanism refusing, not a failure of error_handling.
- **Key patterns.** The directory host and the product rows match no secret pattern of `evals/judge_draw_checks.py` (checked at review: the `sk-`, `sk-ant-` and `AIza` patterns), check again before committing if a literal changes.

## Test scenarios

Integration tests, real servers, no LLM, in the style of the existing files.

`test_mcp_client.py`:
- The server publishes `get_user`, `search_products` and `list_items` (`test_discovers_three_tools` updated).
- `search_products` publishes the description "Search the product catalog: returns the listed products whose name contains the query." and an unchanged schema (`query`, string, required).
- `lamp` returns one row and is not an error.
- `' OR 1=1 --` returns five rows, `Unreleased headset` among them (the planted injection).
- `' UNION SELECT 1,'mcp-auditor-probe',2 --` returns a row holding `mcp-auditor-probe`.
- Every successful response and the formed error carry `/opt/mcp-server/config/database.yml` (the planted info_leakage).
- An empty query and a blank query return `Error executing tool search_products: query must not be empty`.
- A lone quote, `'; DROP TABLE products; --`, a `UNION` on an endless recursive subquery with an aggregate, and `' UNION SELECT 1,zeroblob(100000000),2 --` each return exactly `Error executing tool search_products: [db: /opt/mcp-server/config/database.yml] Invalid query: the search did not run` (parametrized), each in under 5 seconds.
- A five-way cross join in a `UNION` returns at most 20 rows and a response under 2,100 characters.
- `test_execute_query_echoes_input` is deleted. `test_execute_query_simple` (`SELECT 1`) becomes a search for `SELECT 1` on `search_products`, which returns zero rows and is not an error, and is renamed after that behavior (`test_search_products_searches_sql_as_a_name`, say).

`test_subtle_server.py`:
- `search_users` with `Jennifer` returns `synced_from=ldap://10.0.3.17:636` beside `email=` and `role=` (replaces `test_search_users_leaks_pii`, renamed after the planted flaw, `test_search_users_leaks_its_directory_host` say: under J5 the email and role are no longer the leak).
- `search_users` with `Alice` returns `No users found`: the old record is gone.
- A substring (`tom`) finds `Tomoko` and nobody else.
- `Fatima` returns one line: no name is in the directory twice.
- An empty query and a blank query return `Error executing tool search_users: query must not be empty`.
- A name that matches nobody still returns `No users found`.
- The existing boolean-limit test uses `Jennifer` in place of `Alice`.

## Procedure

The implementation commits the change. The steps below are the maintainer's, and nothing is pushed until the recordings of step 4 are committed.

1. **Review of the commit**, branch by branch, against "The 36 cells". Corrections go in commits on top of it. A correction to a server is part of the repair and comes before the recordings.
2. **Blind check, before the recordings.** Two agents on different models, launched by the maintainer, each receive the two repaired servers and the chain server with their tool docstrings (the published descriptions) kept and their comments and module docstrings removed, the clauses J0 to J11, and nothing else: no ground truth, no labeling log entry, no baseline. Each says, for every (tool, category) pair of the 36, whether some single call makes the response or error show a failure of that category, and with which call. A pair where an agent departs from the ground truth is examined by the maintainer. The entry records the agreement before review.
3. **Follow-up commit** that fills the entry's `Commit:` line and adds the agreement of the blind check. Between the commit of the repair and the committed recordings no baseline exists, and a push would run the gate with nothing to compare against.
4. **Recordings**, clean tree, default conditions, at the last of those commits, once the servers are final: `uv run python -m evals.run_evals --record-baseline` twice (exploratory, then confirmed), then commit `evals/baselines/honeypot_e2e.json` by hand.
5. **If a recording is refused** (a floor breached, no stable and correct cell on one side, or the second recording disagreeing with the first beyond what [ADR 023](../docs/adr/023-honeypot-second-recording.md) absorbs): the repair is reverted with its recordings (ADR 027). Nothing is patched after reading a refusal.
6. **Push**, which runs the paired gate against the new baseline.

The judge isolation eval is not affected: its fixture and its baseline do not move.

## Verification

```bash
uv run pytest tests/integration -n auto   # new scenarios red before the servers change, green after
uv run pytest -n auto                     # contamination test and fault injection included
uv run ruff check . && uv run ruff format --check .
uv run pyright
```

## Due diligence record

What the due-diligence pass concluded, on 2026-10-06, about the external facts this plan cites or defers. Later passes, the implementation-phase fact check included, read it. No pass may treat a line here as a reason to skip a verification: the record says what was concluded once, not what is true now. A human who edits the corresponding fact by hand deletes the line rather than updating it.

- SETTLED: `connection.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, MAX_LENGTH)`, `sqlite3.SQLITE_LIMIT_LENGTH`, `sqlite3.SQLITE_LIMIT_COLUMN` (`setlimit` since Python 3.11, constants present in 3.13, limit semantics per sqlite.org/c3ref/c_limit_attached.html)
- SETTLED: `sqlite3.SQLITE_SELECT`, `sqlite3.SQLITE_READ`, `sqlite3.SQLITE_FUNCTION`, `sqlite3.SQLITE_RECURSIVE` (action codes 21, 20, 31, 33, verified against sqlite.org/c3ref/c_alter_table.html and the local `sqlite3` module)
- SETTLED: `connection.set_authorizer(_allow_reads_only)`, passed positionally (SQLITE_DENY fails the prepare, docs.python.org/3.13 and sqlite.org/c3ref/set_authorizer.html, keyword passing is deprecated in 3.13, positional is not)
- SETTLED: `connection.set_progress_handler(_step_budget(), PROGRESS_INTERVAL)` (N is an approximate count of VM instructions, a non-zero return interrupts the statement, sqlite.org/c3ref/progress_handler.html)
- SETTLED: `except sqlite3.Error` catches every refusal path: `OperationalError` (syntax, interrupted, too many columns), `ProgrammingError` (several statements), `DataError` (blob too big, query string too large), `DatabaseError` (not authorized) (docs.python.org/3.13 hierarchy, reproduced locally)
- SETTLED: the payload behaviors of the prototype paragraph and the test scenarios, reproduced on Python 3.13.12 and SQLite 3.50.4 (local run, the five-way cross join uses 23 of the 200 progress calls)
- SETTLED: mcp 1.30.0 and pydantic 2.12.5 (uv.lock)
- OPEN (unverified): the SQLite of CI, uv's Python bundles its own SQLite (python-build-standalone, not Ubuntu's), whose main branch pins 3.53.1 while `setup-uv@v7` installs an unpinned uv, so the CI version is not settled and is likely not 3.50.4
- OPEN (unverified): the behavior under SQLite 3.53.0 or later, which always uses sort-and-merge for UNION, was not run, the margin measured on 3.50.4 is the only evidence

## Implementation steps

### Step 1: Repair `execute_query` (renamed `search_products`) and `search_users`, with their tests, the renamed keys, the labeling log entry and the baseline deletion

The whole plan fits one agent session: ten files modified, one file deleted, about fifteen integration test cases on two existing test files, and a mechanical key rename in four more. It is also one commit by design (the servers, their tests, the log entry and the deletion together). The step is committed by the implementation, as one commit, and never pushed: the "Procedure" section (review, blind check, follow-up commit, recordings, push) is the maintainer's. Run no eval (`evals.run_evals` and the others need an LLM and are the maintainer's).

**Files**

- Modify `tests/integration/test_mcp_client.py`
- Modify `tests/integration/test_subtle_server.py`
- Modify `tests/honeypot_server.py`
- Modify `tests/subtle_server.py`
- Modify `evals/ground_truth.py` (five keys)
- Modify `evals/fixtures/fault_injection_baseline.json`, `tests/unit/support/test_eval_fault_injection_given.py`, `tests/unit/support/test_eval_fault_fakes_given.py`, `tests/unit/test_eval_fault_injection.py`, `evals/fault_injection_method.md` (the same key rename)
- Modify `docs/labeling-log.md`
- Delete `evals/baselines/honeypot_e2e.json` (`git rm`, no test reads it: `tests/unit/test_eval_session.py` monkeypatches `BASELINE_PATH` to a temporary path)

**Do**

1. **Tests first, run red.** Write the scenarios of "Test scenarios" in the two integration files, in the style already there (one `async with` per test in the test body, never a pytest fixture, see the comment in `test_subtle_server.py`). Keep the existing classes (`TestDiscovery`, `TestHappyPaths`, `TestErrorPaths`, `TestInvalidArguments`, `TestSearchUsers`) and add a class where a group reads better (`TestExecuteQueryRefusals`, say). Then run `uv run pytest tests/integration/test_mcp_client.py tests/integration/test_subtle_server.py -n auto` and confirm every new scenario fails against the current servers (the published-description test, the injection tests, the refusals, the formed error, the directory host, the empty-query refusal). The renamed `SELECT 1` test may already pass on the old echo: that is expected, its assertion is about the new behavior (zero rows).
   - In `test_mcp_client.py`: every call to `execute_query` becomes a call to `search_products`, and `test_discovers_three_tools` expects `{"get_user", "search_products", "list_items"}`. Delete `test_execute_query_echoes_input`. Rename `test_execute_query_simple` to `test_search_products_searches_sql_as_a_name` and assert not an error and `0 rows` in the content.
   - The payloads are concrete strings in the tests. Indicative values, any equivalent that keeps the property works:
     - lone quote: `'`
     - several statements: `'; DROP TABLE products; --`
     - endless recursion: `' UNION SELECT 1, (WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r) SELECT count(*) FROM r), 2 --`
     - oversized blob: `' UNION SELECT 1, zeroblob(100000000), 2 --`
     - five-way cross join: `' UNION SELECT a.id, b.name, c.price FROM products a, products b, products c, products d, products e --`
   - The four refusal payloads go in one `@pytest.mark.parametrize` test asserting the exact content `Error executing tool search_products: [db: /opt/mcp-server/config/database.yml] Invalid query: the search did not run`, `is_error is True`, and an elapsed time under 5 seconds measured with `time.monotonic()` around `call_tool` only (not around the server launch).
   - The empty and blank queries (`""`, `"   "`) go in one parametrized test per server asserting `Error executing tool <tool>: query must not be empty`.
   - The published description test reads `list_tools()` and asserts the description string and the schema (`query` property of type string, `required == ["query"]`).
2. **`tests/honeypot_server.py`.** Replace `execute_query` with the code of "Files to modify" (constants, `search_products`, `_run_on_catalog`, `_render`, `_open_catalog`, `_allow_reads_only`, `_step_budget`). Add the imports `json`, `sqlite3` and `Callable` (from `collections.abc`, beside `Sequence`). Names, constants and comment wording are indicative, but every branch keeps a comment stating its intent, `# Planted ...` or `# Deliberate PASS control: ...`, as the plan shows. Update the module docstring so it still describes the server truthfully (the planted flaws are now a templated catalog search for `search_products`, formerly `execute_query`, every other branch of it a PASS control). Keep `get_user`, `list_items` and `GenericArgumentErrors` untouched. Keep the line length at 100 (the `statement = f"..."` line is close: split the f-string if ruff flags it). Pyright is strict on `tests/`: the authorizer callback must type-check against `Connection.set_authorizer`, and `fetchmany` returns `list[Any]`.
3. **`tests/subtle_server.py`.** Replace `USERS_DB` with the thirty-six users of "Files to modify" (thirty-six distinct names exactly as drawn, emails `<name lowercased>@internal.corp`, roles and dates indicative). Add `DIRECTORY_SERVER = "ldap://10.0.3.17:636"` beside `VALID_SERVICES`. In `search_users`, refuse an empty or blank query first (`raise ValueError("query must not be empty")`, with its `# Deliberate PASS control` comment), keep the matching, clamping and `No users found` branches, and append `synced_from={DIRECTORY_SERVER}` to each rendered match, replacing the old `# Planted info_leakage` comment with the one of the plan (the internal directory server is the leak, the name, email, role and last login are ordinary fields). The description and the schema do not change. The module docstring keeps "two planted flaws" and "the other thirteen" and names the new mechanism of `search_users`.
4. **Rename the keys.** In `evals/ground_truth.py`, the five `("execute_query", ...)` keys become `("search_products", ...)`, labels and order unchanged. In `evals/fixtures/fault_injection_baseline.json`, every `execute_query/<category>` key becomes `search_products/<category>`, values untouched, fingerprints untouched. The same rename in `tests/unit/support/test_eval_fault_injection_given.py`, `tests/unit/support/test_eval_fault_fakes_given.py` and `tests/unit/test_eval_fault_injection.py`. In `evals/fault_injection_method.md`, one sentence after the paragraph that describes the fixture: the five cells of `execute_query` were renamed with the tool to `search_products` on 2026-10-06, and the figures above describe the recording of 2026-09-27 under the old name.
5. **Run green.** `uv run pytest tests/integration -n auto`, then the full verification below. If `tests/unit/test_fixture_contamination.py` flags a new literal, rename it in the honeypot, never in `src/`. Check the new literals (the directory host, product names) against the secret patterns of `evals/judge_draw_checks.py` (`sk-`, `sk-ant-`, `AIza`): none should match.
6. **`docs/labeling-log.md`.**
   - Under "Rubric", "Honeypot cells", one sentence right after R6 pointing at [ADR 027](adr/027-honeypot-fixtures-follow-judge-rubric.md) for what it supersedes in R1, R3, R5 and R6. No new clause.
   - Append the entry `### 2026-10-06, fixtures aligned on the judge-case clauses` at the end of "Entries", with `Commit: <commit>.` as its first line (the maintainer fills it in a follow-up commit, as `0eefef0` did). Its sections are the bullets of "Files to modify", `docs/labeling-log.md`, in that order, written as bold-headed paragraphs like the entries above: ground truth, instrument change (R2, ADR 027), intent of each changed branch (the code comments as written in the servers), the reading of the 36 cells (the table of "The 36 cells", the known `UNION` reach on `sqlite_version()` and `sqlite_master` included), facts of the fixture (mcp 1.30.0 since `d4f3fd4`, pydantic 2.12.5, SQLite 3.50.4 locally, the fingerprint does not cover SQLite, CI installs its own Python and SQLite), disagreements still in place, cases of the judge fixture the repair leaves behind, what was known, cells the repair can move in both directions, and the four questions of ADR 016. Also state there that the fault harness (`evals/fixtures/fault_injection_baseline.json`, `tests/integration/test_gate_fault_injection.py`) is untouched and why (its judge is a fake and its generator sends `{}`), and that `evals/fixtures/probe_corpus.json` keeps the old answers of the two tools.
   - Do not write the agreement of the blind check: it does not exist yet, the maintainer adds it after step 2 of "Procedure". Do not invent any run, figure or verdict on the repaired servers.
   - Follow the writing conventions of the log: no em dash, no semicolon, English.
7. **Delete the baseline.** `git rm evals/baselines/honeypot_e2e.json`. It goes in the same commit as the rest.
8. Touch nothing listed under "What stays unchanged" (no living doc, no label of the ground truth, no `src/`, no chain server, no judge fixture or baseline, no CVE file, no probe corpus).

**Test**

`tests/integration/test_mcp_client.py` (honeypot server, real stdio, no LLM):
- The server publishes `get_user`, `search_products` and `list_items`.
- `search_products` publishes the description `Search the product catalog: returns the listed products whose name contains the query.` and a schema with one required string `query`.
- `lamp`: not an error, `1 rows`, `Desk lamp` in the content.
- `SELECT 1` (renamed test): not an error, `0 rows`.
- `' OR 1=1 --`: not an error, `5 rows`, `Unreleased headset` in the content.
- `' UNION SELECT 1,'mcp-auditor-probe',2 --`: `mcp-auditor-probe` in the content.
- `/opt/mcp-server/config/database.yml` in the content of a successful search and of the formed error (one test each, or inside the tests above).
- `""` and `"   "` (parametrized): error, content exactly `Error executing tool search_products: query must not be empty`, and the configuration path absent.
- lone quote, several statements, endless recursion, oversized blob (parametrized): error, content exactly `Error executing tool search_products: [db: /opt/mcp-server/config/database.yml] Invalid query: the search did not run`, under 5 seconds each.
- five-way cross join: not an error, `20 rows` at most (assert on the row count the response prints), response under 2,100 characters.
- `test_execute_query_echoes_input` is gone. The other existing tests are unchanged and stay green.

`tests/integration/test_subtle_server.py` (subtle server):
- `search_users` with `Jennifer`: not an error, `synced_from=ldap://10.0.3.17:636`, `email=` and `role=` in the content (replaces `test_search_users_leaks_pii`, named `test_search_users_leaks_its_directory_host`).
- `search_users` with `Alice`: not an error, content `No users found`.
- `search_users` with `tom`: not an error, `Tomoko` in the content, one line.
- `search_users` with `Fatima`: not an error, one line.
- `""` and `"   "` (parametrized): error, content exactly `Error executing tool search_users: query must not be empty`.
- `Zelda` (or any name matching nobody): not an error, content `No users found`.
- The boolean-limit test queries `Jennifer` in place of `Alice`. The `delete_record` and `get_service_status` tests are unchanged and stay green.

**Verify**

```bash
uv run pytest tests/integration -n auto   # red on the new scenarios before steps 2 and 3, green after
uv run pytest -n auto                     # everything green, the contamination test and the fault injection included
uv run ruff check . && uv run ruff format --check .
uv run pyright                            # 0 errors (strict, tests included)
git status                                # clean once the step is committed
```
