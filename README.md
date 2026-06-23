# rlsautotest

**Deterministic pgTAP test generation for Postgres / Supabase Row-Level Security.**

> **Status: beta (v0.x).** Actively developed and the CLI may still change - but it's built to **never emit a false-passing test**: anything it can't verify soundly is marked, not faked.

Point it at your database. It reads your RLS policies from the catalog and **auto-generates both the tests and the seed data** — a native [pgTAP](https://pgtap.org) suite that *proves*, per table, per command, per identity, who can `SELECT` / `INSERT` / `UPDATE` / `DELETE` which rows, plus a per-identity access-matrix report and a CI gate that fails the build on any leak or unprotected table.

```bash
pip install rlsautotest

# Quick check: write a per-identity access report, then open rls-report.html in your browser (nothing saved)
rlsautotest --db-url "$DATABASE_URL" --schema public --html rls-report.html

# Or: generate a native pgTAP suite to commit and run in CI (pg_prove / supabase test db / psql)
rlsautotest --db-url "$DATABASE_URL" --schema public --emit supabase/
```

> ⚠️ **Point `--db-url` at a disposable copy of your database, never production.** rlsautotest probes each policy by seeding rows and running real `SELECT`/`INSERT`/`UPDATE`/`DELETE` — every probe is wrapped in a transaction and rolled back (nothing is committed), but the statements do run (table locks, triggers, sequences fire). `--emit`, `--report`, and `--html` all connect and probe; only `--describe` and the static checks (`lint`/`snapshot`/`diff`) just read the catalog.

_Running the suite - on a local Supabase (`supabase test db`), `pg_prove`, or in CI - is covered in [INSTALL.md](INSTALL.md)._

## Demo

**Path A - quick check (no files saved):** one command points at your database and reports who can touch what; an unprotected table is caught immediately.

![Path A - quick RLS check](docs/demo-path-a.gif)

**Path B - generate a suite to commit + run in CI:** generate native pgTAP and run it with `pg_prove` (video).

<!-- PASTE THE PATH B VIDEO HERE:
     1. Open this README on github.com and click the pencil (Edit).
     2. Click on the empty line just below this comment.
     3. Drag "Path B.mp4" into the editor; wait for it to finish uploading.
     4. GitHub inserts a https://github.com/user-attachments/assets/... line - leave it as is.
     5. Delete this comment block (optional), then Commit changes. -->

## What it does

RLS is the security boundary of a Supabase app, and Supabase's own docs note that writing pgTAP tests for it is "inaccessible to most web developers." So most RLS goes untested. `rlsautotest` closes that gap — without you writing a line of test SQL.

You point it at your database and it:

1. **reads your RLS policies** from the catalog,
2. **generates the test data and identities** that exercise each policy (owners, other users, anon, role-holders, tenants),
3. **proves — per table, per command, per identity — who can `SELECT` / `INSERT` / `UPDATE` / `DELETE` which rows**,
4. **emits a native pgTAP suite you commit and run** with `supabase test db`, `pg_prove`, or `psql`,
5. and gives you a **per-identity access report** plus a **CI gate** that fails the build on a leak or an unprotected table.

## How it does it

- **Auto-generates the data, not just the tests — this is what makes the generated tests mean something.** An auto-generated test only proves anything if the data driving it is also generated to match the policy and the identity; otherwise it passes against empty or mismatched rows and proves nothing. rlsautotest does this with **reverse-predicate seeding** — it works backward from each policy's predicate to the exact rows *and* identities (owner, other user, other tenant, role-holder, anon) that drive it true and false. So "the owner can see their row" is checked against a row that is actually theirs, and "another tenant can't" against a real, different tenant. You don't hand-write fixtures or scenarios.
- **Proves policies are correct, not just present.** It becomes each identity (owner, other user, anon, role-holder) and checks actual access, so a policy that's enabled but wrong — `USING (true)`, the wrong column, an always-true predicate — is caught, not just "RLS is on."
- **Every test asserts a real, owned row.** Assertions check the exact rows an identity can and can't see, so a passing suite means something: break a policy and the test turns red.
- **Proves multi-tenant isolation.** It seeds two tenants' data and claims and verifies one tenant sees only its own rows — the core invariant of most apps, checked directly.
- **Models "denied" the right way.** Row-level filtering is verified as zero rows visible; a missing grant is verified as a permission error — the two are distinguished, so a block is proven for the right reason.
- **Handles real schemas.** It seeds foreign-key parents in dependency order, so tables with required relationships are actually tested, and it handles the tricky policies: owner (`auth.uid()`), tenant/JWT-claim, membership (`EXISTS`/`IN`), array membership (`= ANY`), RBAC functions (`authorize()` / `has_role()`), recursive hierarchies, escape-hatch `OR` admin grants, and permissive + `AS RESTRICTIVE` composition.
- **Sound by design — never a false pass.** Tests are derived from your policies and the catalog, not guessed by an LLM. When a policy can't be proven soundly (e.g. an opaque function) it's marked clearly instead of turned into a green checkmark.
- **Native, ownable output.** Standard pgTAP into `supabase/tests/database/rls/`, runnable by `supabase test db`, `pg_prove`, or plain `psql`. Uses the [basejump test helpers](https://github.com/usebasejump/supabase-test-helpers) when present, or ships a tiny offline shim when they aren't — online or air-gapped.
- **Static checks too.** It flags open `USING (true)` reads, `WITH CHECK (true)` writes, asymmetric `USING`/`WITH CHECK`, self-referential (recursive) policies, RLS-on-but-no-policy, and policy drift via snapshot/diff.

## What it generates

```
supabase/tests/database/rls/     # our own folder, separate from your hand-written tests
  000-setup-tests-hooks.sql      # pgTAP + helpers (or offline shim if basejump absent)
  010-rls-enabled.test.sql       # guard: fails if any API-reachable table has RLS OFF
  101-rls-profiles.test.sql      # one file per table, native flat pgTAP
  102-rls-notes.test.sql
.rlsautotest/debug/               # nested/structured copies for debugging
```

Each test is Arrange-Act-Assert: seed as a privileged role (RLS bypassed), act as a mocked identity (`authenticate_as` / `set_config('request.jwt.claims', …)` + `SET ROLE`), assert the visible/affected rows — with `SAVEPOINT` isolation so a write test can't corrupt the next one.

## Modes

| Command | What you get |
|---|---|
| `--emit DIR` | full suite layout under `DIR/` (default; helper-based, looks native) |
| `--no-helpers` | fully self-contained tests (inline `set_config`/`SET ROLE`, no helper/000 dependency) |
| `--report` | run the suite and print the per-identity access matrix (`--report-json` for CI) |
| `--html FILE` | run the suite and write the access matrix as an HTML report |
| `--no-fail` | with `--report`/`--html`: don't exit non-zero on problems (default **does** — for CI gating) |
| `--table T` | a single table instead of the whole schema |
| `--describe` | show the identity classes the generator derived for a table |

## The report

One grid per table — rows are identities, columns are commands — so it reads like a permissions table:

```
notes                          SELECT  INSERT  UPDATE  DELETE
service_role                     ✓       ✓       ✓       ✓     bypasses RLS
authenticated, authorized        ✓       ✓       ✓       ✓
authenticated, not authorized    ·       ·       ·       ·
anon                             ·       ·       ·       ·
```

`✓` = can, `·` = blocked. The one thing that lights up red is a `✓` where it should be `·` — an *authenticated-but-not-authorized* user or *anon* that can act (a security hole) — so it jumps out without decoding anything. `service_role` is shown for completeness; it bypasses RLS by design. A table with **RLS off** is flagged loud (it has no row-level protection at all).

The identity rows are deliberately worded so they aren't mistaken for database roles: `authenticated, authorized` and `authenticated, not authorized` are the **same Postgres role** (`authenticated`) under different JWT identities/claims — only `service_role`, `authenticated`, and `anon` are actual Postgres roles. "Authorized" vs "not authorized" is simply whether that identity passes the table's policies (owns the row, is in the right tenant/org, or has the required role).

## Catching unprotected tables in CI (important)

A naive "generate tests, commit them, run them" setup has a dangerous blind spot: a table with **no RLS at all** generates no test, so the suite stays green and the exposure ships silently. `rlsautotest` closes that hole from **two** directions:

**1. The report is a CI gate.** `--report` and `--html` **exit non-zero (1)** when they find a problem — a table that's RLS-off-but-reachable (`anon`/`authenticated` can touch it), a check where a forbidden identity can act, or a **broken/unreadable** table (e.g. a self-referential policy that throws *infinite recursion detected in policy*, locking out every client role). So a single command fails the build:

```bash
rlsautotest --db-url "$DATABASE_URL" --schema public --report   # exits 1 if anything is exposed/leaking
```

Pass `--no-fail` to print the report without failing the pipeline (local or non-blocking use). Exit codes: `0` = clean, `1` = problems found.

**2. A schema-wide guard test.** `--emit` also writes `010-rls-enabled.test.sql`, which asserts that **every table reachable by `anon`/`authenticated` has RLS enabled**. A table shipped without RLS becomes a real `not ok` — so even teams that only run `supabase test db` on the committed files (and never re-run the generator) get a red build:

```
not ok 1 - public.exposed_tbl: RLS must be enabled (table is reachable by anon/authenticated)
```

It's scoped to *reachable* tables, so a genuinely-internal table with no client grant won't raise a false alarm.

### GitHub Actions

```yaml
name: rls
on: [push, pull_request]
jobs:
  rls:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16
        env: { POSTGRES_PASSWORD: postgres }
        ports: ["5432:5432"]
        options: >-
          --health-cmd pg_isready --health-interval 10s --health-timeout 5s --health-retries 5
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install rlsautotest
      # apply your migrations into the throwaway DB first, then:
      - name: Verify RLS
        env:
          DATABASE_URL: postgresql://postgres:postgres@localhost:5432/postgres
        run: rlsautotest --db-url "$DATABASE_URL" --schema public --report
```

The build goes red the moment a policy leaks or a reachable table is missing RLS.

## What it's tested on

The `examples/` folder is the runnable test corpus, covering the common and the hard RLS patterns: owner (`auth.uid()`), tenant/JWT-claim, membership (`EXISTS`), array claims (`= ANY`), RBAC functions, recursive policies, session-GUC, permissive + `AS RESTRICTIVE` composition, and role-gated status state machines (multi-policy `UPDATE`). On every commit, CI loads the owner-scoped and the multi-tenant example schemas, generates the suite, and runs it — so the core validation is reproducible rather than a claim. The corpus also includes deliberately broken cases — a self-referential policy, and a role-gated state machine with a cross-policy `WITH CHECK` leak (a role can write a status its own policy forbids) — that the tool is required to *catch*. It's been exercised against real-world Supabase schemas too, to harden the generator.

## Honest limitations

`rlsautotest` proves your database *enforces what your policies declare*. It cannot know your *intent* — a wrong policy will be faithfully (and greenly) confirmed. It tests the permissions your policies define; commands left with no policy show as `·` (implicit deny) and aren't asserted unless you opt in. Policies behind opaque/external functions it can't reason about are reported, not faked.

## Requirements

- Python 3.10+
- A Postgres database. **pgTAP is handled for you** — rlsautotest uses your database's pgTAP if present (Supabase ships it) and otherwise loads a small built-in copy, so there's nothing to install on the server.
- A throwaway/local database holding a copy of your schema + policies. Every command that connects (`--emit`, `--report`, `--html`) probes by seeding rows and running real `SELECT`/`INSERT`/`UPDATE`/`DELETE` — each rolled back, nothing committed, but the statements do run. Point it at a disposable copy, **never production**. (`--describe` and the static `lint`/`snapshot`/`diff` checks only read the catalog.)

## Part of the UnitAutogen family

`rlsautotest` is the free, open-source PostgreSQL member of **UnitAutogen** — we build *automated unit-test generators for databases*: tools that read your schema and generate the tests for you, instead of you hand-writing them. The test frameworks themselves are open source (pgTAP on Postgres, tSQLt on SQL Server); what UnitAutogen adds is the generator that writes the tests — and the data — for them.

The same idea runs deeper on other engines:

- **PostgreSQL** — `rlsautotest` (this project, free) and automated unit-test + branch-coverage generation for PL/pgSQL functions, emitting **pgTAP**.
- **SQL Server** — automated unit-test generation and branch coverage for stored procedures, emitting **tSQLt** (the open-source SQL Server test framework).
- **Oracle, Azure SQL** — in development.

If your team needs automated database test *generation* beyond Postgres RLS — SQL Server, Oracle, Azure — [get in touch](https://github.com/unitautogen).

## Credits

Built on [pgTAP](https://pgtap.org) and `pg_prove` (David Wheeler), the [basejump Supabase test helpers](https://github.com/usebasejump/supabase-test-helpers), and [pglast](https://github.com/lelit/pglast) / libpg_query for parsing. Thanks to the Supabase and PostgreSQL communities.

## License

Copyright (c) 2026 Munaf Ibrahim Khatri.

Licensed under Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
