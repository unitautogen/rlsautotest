# Contributing to rlsautotest

Thanks for your interest! rlsautotest reads your Postgres / Supabase RLS policies and generates native [pgTAP](https://pgtap.org) tests (and the data) that prove who can access which rows.

## Setup

Requires Python 3.10+ and a throwaway Postgres/Supabase database (never run the generated suite against production — it seeds data).

```bash
git clone https://github.com/<you>/rlsautotest
cd rlsautotest
python -m pip install -e .        # installs the `rlsautotest` CLI and its dependencies
rlsautotest --help
```

You'll need a connection string for a database that has your schema and policies (local Supabase, a branch, or CI): `postgresql://USER:PASSWORD@HOST:5432/DBNAME`.

## What to run

There are two things rlsautotest does — full details in [INSTALL.md](INSTALL.md).

**Path A — a quick check** (nothing saved): runs the tests in memory and writes an HTML access-matrix report.

```bash
rlsautotest --db-url "<your db>" --schema public --html rls-report.html
# or --report to print the matrix in the terminal
```

**Path B — a suite to keep** (commit + run in CI): emits standard pgTAP `.sql` files, then run them with `supabase test db`, `pg_prove`, or `psql`.

```bash
rlsautotest --db-url "<your db>" --schema public --emit supabase/
pg_prove -d "<your db>" --ext .sql -r supabase/tests/database/rls
```

(With `pg_prove`, use `--ext .sql`, and on Windows run from a path without spaces.)

## Run the project's own tests

```bash
python -m pytest -q
```

Please keep the test suite green in any PR. The guiding principle of the project is that it must **never emit a false-passing or flaky test** — when something can't be verified soundly it's marked, not faked; changes shouldn't weaken that.

## Issues & PRs

Bug reports and feature requests are welcome via GitHub Issues — a minimal schema + the policy that reproduces the problem helps a lot. For PRs, keep `pytest` green and include an `examples/` fixture for any new behavior.
