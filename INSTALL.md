# Installing rlsautotest

`rlsautotest` reads your Postgres / Supabase RLS policies and turns them into pgTAP tests — so you can check, in one command, that your policies actually enforce what you think they do.

Requires **Python 3.10 or newer** (`python --version`).

> ⚠️ **Run rlsautotest against a disposable copy of your database — never production.** It probes each policy by seeding rows and running real `SELECT`/`INSERT`/`UPDATE`/`DELETE` (every probe is rolled back, nothing is committed, but the statements do run — table locks, triggers, sequences fire). This applies to `--emit`, `--report`, and `--html` alike; only `--describe` and the static checks just read the catalog.

## Install

```bash
pip install rlsautotest
```

> Not on PyPI yet? Install straight from the repo:
> ```bash
> pip install git+https://github.com/unitautogen/rlsautotest
> ```

Then `rlsautotest --help` should work.

You'll also need a **connection string** for a database that has your schema and policies — your local Supabase, a branch, or CI (a disposable copy — **never production**; see [How it works](#how-it-works)). It looks like `postgresql://USER:PASSWORD@HOST:5432/DBNAME`. [Where to find it →](#finding-your-connection-string)

---

## Pick your path

There are **two separate things** rlsautotest does. Choose by what you're after — they don't overlap:

| You want… | Path | Saves test files? | Result |
|---|---|---|---|
| **A quick check** — "are my policies enforced right now?" | **[A](#path-a--quick-report)** | **No** | An HTML report you open in a browser |
| **A test suite to keep** — review, commit, run in CI forever | **[B](#path-b--generate-a-suite-to-commit)** | **Yes** | `.sql` files you commit to your repo |

Path A is the 30-second look. Path B is the one you do once and keep.

### Path A — quick report

One command. Generates the tests in memory, runs them against your copy, writes a single **HTML report** — **nothing is saved to your repo**.

```bash
rlsautotest --db-url "<your copy>" --schema public --html rls-report.html
```

The report is written to the path you give — here, `rls-report.html` in the folder you ran the command from (pass a path like `--html reports/rls-report.html` to put it elsewhere; the folder must already exist). Open it: a **per-identity access matrix** for each table — rows are identities (`service_role` / authorized user / other user / `anon`), columns are SELECT/INSERT/UPDATE/DELETE, each cell showing who **can** (✓) or is **blocked** (·). A `✓` in red is the thing to look for: an identity that can act when it shouldn't. Tables left **exposed** (RLS off) are flagged loud. Prefer the terminal? Use `--report` instead of `--html rls-report.html` to print the same grids (writes nothing).

That's all of Path A. If a quick check was all you wanted, you're done.

### Path B — generate a suite to commit

For RLS tests that live in your repo and run in CI.

```bash
# B1 — generate the files (probes your policies: seeds + runs queries, rolled back — use a copy)
rlsautotest --db-url "<your copy>" --schema public --emit rls-tests
#   -> rls-tests/tests/database/rls/000-setup-tests-hooks.sql
#   -> rls-tests/tests/database/rls/101-rls-<table>.test.sql

# B2 — review them: open the .sql files; plain pgTAP, meant to be read

# B3 — run them on a copy (executes/seeds data, rolled back per test)
pg_prove -d "<your copy>" rls-tests/tests/database/rls/*.sql
#   no pg_prove? run one file:  psql "<your copy>" -f rls-tests/tests/database/rls/101-rls-<table>.test.sql

# B4 — commit the rls-tests/ folder and wire B3 into CI
```

B2 is the step Path A skips: you inspect and own the tests before they become your suite.

> **Want both in one run?** Pass `--html` and `--emit` together to get the report *and* the saved suite at once:
> ```bash
> rlsautotest --db-url "<your copy>" --schema public --html rls-report.html --emit rls-tests
> ```

---

### Run on a local Supabase (`supabase test db`)

Using the Supabase CLI? The emitted files run with its built-in test runner. Generate into your project's `supabase/` folder, pointing `--db-url` at your **local** dev database (default Postgres port `54322`), then start the stack and run:

```bash
rlsautotest --db-url "postgresql://postgres:postgres@127.0.0.1:54322/postgres" --schema public --emit supabase/
supabase start          # requires Docker
supabase test db        # runs pg_prove in the local container over supabase/tests/database/
```

A failing RLS assertion - or the `010-rls-enabled` guard catching a table with RLS off - fails the run, so it gates CI. No CLI or Docker? Use the `pg_prove` / `psql` commands from Path B above against the same local copy.

## How it works

rlsautotest **reads your RLS policies** and tests *those exact policies on those exact tables*. Two consequences, and they matter:

1. **Every command that connects** — `--emit`, `--report`, and `--html` — **probes your policies by executing statements against the database in `--db-url`**: it seeds rows and runs real `SELECT`/`INSERT`/`UPDATE`/`DELETE`. Each probe is wrapped in a transaction and **rolled back** (nothing is committed), but the statements **do** run — table locks, triggers, sequences fire. (Only `--describe` and the static `lint`/`snapshot`/`diff`/`coverage` checks just read the catalog.)
2. So point `--db-url` at a **throwaway database that holds a copy of the one you want to test** — same tables, same policies — **never production**. Running an emitted suite later (`pg_prove`/`supabase test db`) seeds data the same way, so it also belongs on a copy.

That copy must **match what you ship** — same tables, same RLS policies — which in practice means a database built from the same migrations:

- your **local Supabase** (`supabase start` applies your migrations), or
- a **Supabase branch / preview** database, or
- a **CI** database where your migrations run first.

Run the tests against *different* policies and the green/red is meaningless. The model: **generate from your real policies → run against a faithful, throwaway copy of them.**

## Finding your connection string

- **Supabase:** Dashboard → Project Settings → Database → *Connection string*.
- **Local Supabase** (`supabase start`): `postgresql://postgres:postgres@127.0.0.1:54322/postgres`.

**Keep the password out of your shell history** by setting the standard Postgres environment variables and dropping `--db-url`:

```bash
export PGHOST=db.example.com PGPORT=5432 PGUSER=postgres PGPASSWORD=secret PGDATABASE=postgres
rlsautotest --schema public --html rls-report.html
```

## Several databases (Path B)

Give each database its own `--label` so their tests go into separate folders and never collide:

```bash
rlsautotest --db-url "<db A url>" --schema public --emit rls-tests --label app
rlsautotest --db-url "<db B url>" --schema public --emit rls-tests --label analytics
# -> rls-tests/tests/database/rls/app/   and   rls-tests/tests/database/rls/analytics/

pg_prove -d "<db A url>" rls-tests/tests/database/rls/app/*.sql
pg_prove -d "<db B url>" rls-tests/tests/database/rls/analytics/*.sql
```

> **Using the Supabase CLI?** Emit into your project's `supabase` folder (`--emit supabase`) and `supabase test db` from your project root runs everything against your local Supabase database. Purely a convenience; nothing else needs the CLI.

## Notes

- **Nothing to install into your database — including pgTAP.** The tests run *inside* your database and rely on what your RLS already uses: `auth.uid()`/`auth.jwt()` and the `anon`/`authenticated`/`service_role` roles, which every Supabase database already has. The one other thing they need is the **pgTAP** test engine, and rlsautotest handles it automatically — it uses your database's pgTAP if present, otherwise loads a small built-in copy itself. Genuinely zero-setup, on Supabase **or** plain Postgres.
- **Just want to try it without a real project?** Create a throwaway database and load `examples/schema.sql` from this repo — a tiny demo (a fake `auth` shim + two sample RLS tables) so you can see real output in a couple of minutes. A sandbox to try the tool, **not** something you apply to your own database.
- **`pipx` instead of `pip`?** If you have `pipx`, `pipx install rlsautotest` installs it in isolation — nice-to-have, not required.

## Uninstall

```bash
pip uninstall rlsautotest
```
