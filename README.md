# rlsautotest

[![Featured in Supabase's July 2026 Developer Update](https://img.shields.io/badge/Featured_in-Supabase_Developer_Update-3ECF8E?logo=supabase&logoColor=white)](https://github.com/supabase/supabase/releases/tag/v1.26.07)

**Deterministic pgTAP test generation for Postgres / Supabase Row-Level Security.**

> Featured in Supabase's [July 2026 Developer Update](https://github.com/supabase/supabase/releases/tag/v1.26.07) under "Made with Supabase."

> **Status: beta (v0.x).** Actively developed and the CLI may still change - but it's built to **never emit a false-passing test**: anything it can't verify soundly is marked, not faked.

Point it at your database. It reads your RLS policies from the catalog and **auto-generates both the tests and the seed data**: a native [pgTAP](https://pgtap.org) suite that *proves*, per table, per command, per identity, who can `SELECT` / `INSERT` / `UPDATE` / `DELETE` which rows, plus a per-identity access-matrix report and a CI gate that fails the build on any leak or unprotected table.

```bash
pip install rlsautotest

# Quick check: write a per-identity access report, then open rls-report.html in your browser (nothing saved)
rlsautotest --db-url "$DATABASE_URL" --schema public --html rls-report.html

# Or: generate a native pgTAP suite to commit and run in CI (pg_prove / supabase test db / psql)
rlsautotest --db-url "$DATABASE_URL" --schema public --emit supabase/
```

> âš ï¸ **Point `--db-url` at a disposable copy of your database, never production.** rlsautotest probes each policy by seeding rows and running real `SELECT`/`INSERT`/`UPDATE`/`DELETE`. Every probe is wrapped in a transaction and rolled back (nothing is committed), but the statements do run (table locks, triggers, sequences fire). `--emit`, `--report`, and `--html` all connect and probe; only `--describe` and the static checks (`lint`/`snapshot`/`diff`) just read the catalog.

_Running the suite - on a local Supabase (`supabase test db`), `pg_prove`, or in CI - is covered in [INSTALL.md](INSTALL.md)._

## Demo

**Path A - quick check (no files saved):** one command points at your database and reports who can touch what; an unprotected table is caught immediately.

![Path A - quick RLS check](docs/demo-path-a.gif)

**Path B - generate a suite to commit + run in CI:** generate native pgTAP and run it with `pg_prove` (video).

https://github.com/user-attachments/assets/37103556-d097-4b71-8b8d-2f160b80bbba

## What it does

RLS is the security boundary of a Postgres or Supabase app, and Supabase's own docs note that writing pgTAP tests for it is "inaccessible to most web developers." So most RLS goes untested. `rlsautotest` closes that gap without you writing a line of test SQL.

You point it at your database and it:

1. **reads your RLS policies** from the catalog,
2. **generates the test data and identities** that exercise each policy (owners, other users, anon, role-holders, tenants),
3. **proves, per table, per command, per identity, who can `SELECT` / `INSERT` / `UPDATE` / `DELETE` which rows**,
4. **emits a native pgTAP suite you commit and run** with `supabase test db`, `pg_prove`, or `psql`,
5. and gives you a **per-identity access report** plus a **CI gate** that fails the build on a leak or an unprotected table.

## Verifying RLS for HIPAA and SOC 2

Storing PHI or other regulated data in PostgreSQL? RLS is the access control that keeps each patient, tenant, or customer to their own rows. It's the technical safeguard HIPAA's Security Rule requires ([45 CFR Â§164.312(a)(1), Access Control](https://www.law.cornell.edu/cfr/text/45/164.312)), enforced in the database itself on any Postgres, whether that's Supabase, RDS, Neon, or your own server. On Supabase specifically, [their HIPAA guidance](https://supabase.com/docs/guides/security/hipaa-compliance) calls out RLS for exactly this and offers a [BAA](https://supabase.com/docs/guides/platform/hipaa-projects).

But RLS only counts if it actually enforces what it claims. A policy with the wrong column or an always-true `USING (true)` passes review while silently exposing PHI across tenants. `rlsautotest` produces the evidence that it holds: a per-identity proof, per table and per command, that PHI can't cross a tenant boundary or reach an unauthorized role, plus a committed pgTAP suite and a CI gate that fails the build the moment a policy leaks. That's access-control verification you can put in front of a reviewer.

The same evidence serves [SOC 2](https://supabase.com/docs/guides/security/soc-2-compliance). RLS is a logical access control, so a passing suite is direct proof for the Common Criteria access-control requirement (CC6.1, logical access to protected data restricted to authorized users), turning "we use RLS" into "here is the test run showing our RLS restricts access as designed."

It verifies the access-control safeguard, not your whole HIPAA or SOC 2 program. Your BAA (with Supabase, your cloud provider, or however you host), encryption, audit logging, and the rest remain separate obligations.

**Further reading:** [Your Postgres RLS is a compliance control. Is it tested?](blog/rls-is-a-compliance-control.md)

## How it does it

- **Auto-generates the data, not just the tests. This is what makes the generated tests mean something.** An auto-generated test only proves anything if the data driving it is also generated to match the policy and the identity; otherwise it passes against empty or mismatched rows and proves nothing. rlsautotest does this with **reverse-predicate seeding**: it works backward from each policy's predicate to the exact rows *and* identities (owner, other user, other tenant, role-holder, anon) that drive it true and false. So "the owner can see their row" is checked against a row that is actually theirs, and "another tenant can't" against a real, different tenant. You don't hand-write fixtures or scenarios.
- **Proves policies are correct, not just present.** It becomes each identity (owner, other user, anon, role-holder) and checks actual access, so a policy that's enabled but wrong (`USING (true)`, the wrong column, an always-true predicate) is caught, not just "RLS is on."
- **Every test asserts a real, owned row.** Assertions check the exact rows an identity can and can't see, so a passing suite means something: break a policy and the test turns red.
- **Proves multi-tenant isolation.** It seeds two tenants' data and claims and verifies one tenant sees only its own rows: the core invariant of most apps, checked directly.
- **Models "denied" the right way.** Row-level filtering is verified as zero rows visible; a missing grant is verified as a permission error. The two are distinguished, so a block is proven for the right reason.
- **Catches the cross-policy `WITH CHECK` leak.** This fires when a table has **two or more *permissive* `UPDATE` (or `INSERT`) policies** whose per-policy `WITH CHECK` is a *narrow value constraint* (a partition, e.g. one allowed status per role), but the discriminator that's meant to limit *who* may write *what* (role, owner, tenant) sits **only in `USING`, not repeated in `WITH CHECK`**. Postgres OR-combines every permissive policy's `WITH CHECK` independently of which `USING` matched, so the effective check becomes the *union* of all of them, with no discriminator. Any identity that can target a row can then write *any* value *any* policy permits (e.g. a `cutter` setting `status='Completed'`). rlsautotest enumerates the value space and proves, per identity, exactly which forbidden values are accepted. Fix: repeat the role/owner/tenant guard inside each `WITH CHECK`, or enforce the transition in a trigger / `SECURITY DEFINER` function, or make the constraint `AS RESTRICTIVE` so it `AND`s instead of `OR`s.
- **Handles real schemas.** It seeds foreign-key parents in dependency order, so tables with required relationships are actually tested, and it handles the tricky policies: owner (`auth.uid()`), tenant/JWT-claim, membership (`EXISTS`/`IN`), array membership (`= ANY`), role lookups (`(select role from profiles where id = auth.uid())`), RBAC functions (`authorize()` / `has_role()`), recursive hierarchies, escape-hatch `OR` admin grants, and permissive + `AS RESTRICTIVE` composition.
- **Seeds rows it doesn't have a rule for, by asking the database.** When a table's constraints defeat a templated insert, a probe-and-repair synthesizer tries the insert, reads the real error, and fixes it: filling `NOT NULL` columns, seeding single and **composite** foreign-key parents, varying values to clear `UNIQUE` conflicts, and neutralizing a `CHECK` that delegates to a function (then restoring it). The result is that even an opaque-function-gated table with a composite FK and a function-backed CHECK still gets a valid row to test against, with no per-schema hand-coding.
- **Solves predicates it has never seen, instead of only matching known shapes.** When a policy doesn't fit any named pattern (say a numeric clearance threshold, `(auth.jwt() ->> 'clearance')::int >= sensitivity`), a general solver reads the predicate's operand roles, derives inputs that should make it pass and fail, and **verifies both against your database** before writing a test, so coverage extends to novel policies, and anything it can't confirm stays marked rather than guessed.
- **Sound by design: never a false pass.** Tests are derived from your policies and the catalog, not guessed by an LLM. When a policy can't be proven soundly (e.g. an opaque function) it's marked clearly instead of turned into a green checkmark. And if a test's data precondition can't be established (the seed for a row fails), the engine still probes, then marks that cell **UNRELIABLE** and fails loudly rather than letting a seeding failure masquerade as a policy outcome.
- **Native, ownable output.** Standard pgTAP into `supabase/tests/database/rls/`, runnable by `supabase test db`, `pg_prove`, or plain `psql`. Uses the [basejump test helpers](https://github.com/usebasejump/supabase-test-helpers) when present, or ships a tiny offline shim when they aren't, so it runs online or air-gapped.
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

Each test is Arrange-Act-Assert: seed as a privileged role (RLS bypassed), act as a mocked identity (`authenticate_as` / `set_config('request.jwt.claims', â€¦)` + `SET ROLE`), assert the visible/affected rows, with `SAVEPOINT` isolation so a write test can't corrupt the next one.

## Modes

| Command | What you get |
|---|---|
| `--emit DIR` | full suite layout under `DIR/` (default; helper-based, looks native) |
| `--no-helpers` | fully self-contained tests (inline `set_config`/`SET ROLE`, no helper/000 dependency) |
| `--report` | run the suite and print the per-identity access matrix (`--report-json` for CI) |
| `--html FILE` | run the suite and write the access matrix as an HTML report |
| `--no-fail` | with `--report`/`--html`: don't exit non-zero on problems (default **does**, for CI gating) |
| `--table T` | a single table instead of the whole schema |
| `--describe` | show the identity classes the generator derived for a table |
| `doctor` | subcommand: verify the probe environment (role privileges, pgTAP, policy-function ownership); writes `doctor.json` to attach to bug reports |

## The report

One grid per table (rows are identities, columns are commands), so it reads like a permissions table:

```
notes                          SELECT  INSERT  UPDATE  DELETE
service_role                     âœ“       âœ“       âœ“       âœ“     bypasses RLS
authenticated, authorized        âœ“       âœ“       âœ“       âœ“
authenticated, not authorized    Â·       Â·       Â·       Â·
anon                             Â·       Â·       Â·       Â·
```

`âœ“` = can, `Â·` = blocked. The one thing that lights up red is a `âœ“` where it should be `Â·`: an *authenticated-but-not-authorized* user or *anon* that can act (a security hole). It jumps out without decoding anything. `service_role` is shown for completeness; it bypasses RLS by design. A table with **RLS off** is flagged loud (it has no row-level protection at all).

The identity rows are deliberately worded so they aren't mistaken for database roles: `authenticated, authorized` and `authenticated, not authorized` are the **same Postgres role** (`authenticated`) under different JWT identities/claims. Only `service_role`, `authenticated`, and `anon` are actual Postgres roles. "Authorized" vs "not authorized" is simply whether that identity passes the table's policies (owns the row, is in the right tenant/org, or has the required role).

## When something looks wrong: `rlsautotest doctor`

The probe needs real privileges from the connection role: `SET ROLE` to the client roles (`anon`, `authenticated`, `service_role`), `CREATE` on the target schema (for the pgTAP shim and seed helpers), and the ability to replace any function your policies delegate to (for the mock-wiring proof). If the role can't do one of these, the affected cells show `â€¼ UNRELIABLE` instead of a result, the suite fails loudly on those tests, and the run exits 1. It never bakes a result it couldn't actually observe.

`doctor` checks all of this in seconds and prints the exact remedy for each failed check (for example, on Supabase local: connect as `supabase_admin`, which owns the helper functions). It is read-only: every write it attempts is savepoint-wrapped and rolled back.

```bash
rlsautotest doctor --schema public --db-url "postgresql://..."
```

It also writes `doctor.json` alongside the on-screen report. **Filing an issue? Attach that file.** It contains catalog metadata only (role, function and table names, sqlstates, check results, and a per-table classification summary). No row data, no credentials. It usually lets a problem be reproduced and fixed without any back-and-forth about your environment.

## Catching unprotected tables in CI (important)

A naive "generate tests, commit them, run them" setup has a dangerous blind spot: a table with **no RLS at all** generates no test, so the suite stays green and the exposure ships silently. `rlsautotest` closes that hole from **two** directions:

**1. The report is a CI gate.** `--report` and `--html` **exit non-zero (1)** when they find a problem: a table that's RLS-off-but-reachable (`anon`/`authenticated` can touch it), a check where a forbidden identity can act, or a **broken/unreadable** table (e.g. a self-referential policy that throws *infinite recursion detected in policy*, locking out every client role). So a single command fails the build:

```bash
rlsautotest --db-url "$DATABASE_URL" --schema public --report   # exits 1 if anything is exposed/leaking
```

Pass `--no-fail` to print the report without failing the pipeline (local or non-blocking use). Exit codes: `0` = clean, `1` = problems found.

**2. A schema-wide guard test.** `--emit` also writes `010-rls-enabled.test.sql`, which asserts that **every table reachable by `anon`/`authenticated` has RLS enabled**. A table shipped without RLS becomes a real `not ok`, so even teams that only run `supabase test db` on the committed files (and never re-run the generator) get a red build:

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

The `examples/` folder is the runnable test corpus, covering the common and the hard RLS patterns: owner (`auth.uid()`), tenant/JWT-claim, membership (`EXISTS`), array claims (`= ANY`), RBAC functions, recursive policies, session-GUC, permissive + `AS RESTRICTIVE` composition, and role-gated status state machines (multi-policy `UPDATE`). On every commit, CI loads the owner-scoped and the multi-tenant example schemas, generates the suite, and runs it, so the core validation is reproducible rather than a claim. The corpus also includes deliberately broken cases that the tool is required to *catch*: a self-referential policy, and a role-gated state machine with a cross-policy `WITH CHECK` leak (a role can write a status its own policy forbids). It's been exercised against real-world Supabase schemas too, to harden the generator.

## Honest limitations

`rlsautotest` proves your database *enforces what your policies declare*. It cannot know your *intent*: a wrong policy will be faithfully (and greenly) confirmed. It tests the permissions your policies define; commands left with no policy show as `Â·` (implicit deny) and aren't asserted unless you opt in. Policies behind opaque/external functions it can't reason about are reported, not faked.

## Requirements

- Python 3.10+
- A Postgres database. **pgTAP is handled for you.** rlsautotest uses your database's pgTAP if present (Supabase ships it) and otherwise loads a small built-in copy, so there's nothing to install on the server.
- A throwaway/local database holding a copy of your schema + policies. Every command that connects (`--emit`, `--report`, `--html`) probes by seeding rows and running real `SELECT`/`INSERT`/`UPDATE`/`DELETE`, each rolled back, nothing committed, but the statements do run. Point it at a disposable copy, **never production**. (`--describe` and the static `lint`/`snapshot`/`diff` checks only read the catalog.)

## Part of the UnitAutogen family

`rlsautotest` is the free, open-source PostgreSQL member of **UnitAutogen**. We build *automated unit-test generators for databases*: tools that read your schema and generate the tests for you, instead of you hand-writing them. The test frameworks themselves are open source (pgTAP on Postgres, tSQLt on SQL Server); what UnitAutogen adds is the generator that writes the tests (and the data) for them.

The same idea runs deeper on other engines:

- **PostgreSQL**: `rlsautotest` (this project, free) and automated unit-test + branch-coverage generation for PL/pgSQL functions, emitting **pgTAP**.
- **SQL Server**: automated unit-test generation and branch coverage for stored procedures, emitting **tSQLt** (the open-source SQL Server test framework).
- **Oracle, Azure SQL**: in development.

If your team needs automated database test *generation* beyond Postgres RLS (SQL Server, Oracle, Azure), [get in touch](https://github.com/unitautogen).

## Credits

Built on [pgTAP](https://pgtap.org) and `pg_prove` (David Wheeler), the [basejump Supabase test helpers](https://github.com/usebasejump/supabase-test-helpers), and [pglast](https://github.com/lelit/pglast) / libpg_query for parsing. Thanks to the Supabase and PostgreSQL communities.

## License

Copyright (c) 2026 Munaf Ibrahim Khatri.

Licensed under Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
