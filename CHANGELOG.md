# Changelog

All notable changes to **rlsautotest** are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/); this project is pre-1.0 and versions
roughly follow semantic versioning.

## [0.1.6] — 2026-06-24

### Added
- **Opaque scalar functions in a policy predicate are now wiring-tested instead of `NOT_TESTABLE`.** When a
  policy gates on a function the parser can't reason into — `realtime.topic() = room_topic`, a
  `current_tenant()`-style helper compared to a column or constant, or two such functions compared — the
  engine mocks the function(s) to force the predicate true (authorized → grant) and false (not authorized →
  deny), runs the real statement, and bakes the observed outcome. Covers a boolean function used as the
  predicate, `fn() = const`, `col = fn()` (including inside a membership `EXISTS` correlated to the scope
  column), and `fn() = fn()`.
  - **Sound by construction:** the engine probes the forced-grant first and falls back to honest
    `NOT_TESTABLE` if that grant isn't actually observed — it never bakes a false pass.
  - **Honest scope:** this is a *wiring proof* (the policy correctly delegates to the function), not a
    verification of the function's own logic — the report shows the "function logic NOT verified — test
    separately" footgun. The canonical Supabase `authorize()` RBAC is still *introspected* and tested for
    real (stronger); mocking is the fallback. Non-equality operators, multi-branch opaque predicates, and
    functions the test role can't `CREATE OR REPLACE` still fall to honest `NOT_TESTABLE`.
- New example `examples/mockforce.sql` — regression fixture for the force-mock fallback (`fn()=const`, `fn()=fn()`).
- **Pattern-match predicates are now tested** (`~`, `~*`, `!~`, `!~*`, `LIKE`, `ILIKE`). The solver constructs a
  string that matches the pattern (and one that doesn't), DB-verifies both, and bakes a real grant/deny test —
  e.g. `email ~ '@example\.com$'` flips from NOT_TESTABLE to ✓/blocked. Patterns it can't build a match for
  (complex regex) still fall to honest NT. The general solver now also probes **anon**, so its tables get a
  complete matrix instead of a stray `–`.
- **More predicate shapes are now tested** (each DB-verified, so anything unsupported still falls to honest NT): bare boolean columns and `NOT col` / `IS TRUE` / `IS FALSE`; JSONB `@>` (containment) and `?` / `?|` / `?&` (key-exists); `BETWEEN` ranges (incl. the deparsed `>= AND <=` form); text functions on a column (`lower`/`upper`/`trim`, `col::text`); cross-column inequalities (`start < end`); **array overlap / containment** — `tags && array['vip','beta']`, `roles @> array['admin']`, `perms <@ array[...]` (either operand order); and **many-to-one functions on a column** — `date_trunc('day', ts) = …`, `substring(code,1,3) = 'ABC'`, `left(name,1) = 'A'`, `to_char(ts,'YYYY-MM') = '2026-06'` (the engine constructs a column value whose function output hits the target); and **non-canonical subqueries** — an `EXISTS`/`IN` membership check with an extra condition (`… AND m.role = 'admin'`), two or more correlations, a boolean filter (`… AND s.can_read`), or `NOT EXISTS` (previously only the plain single-correlation membership was tested); the **null-safe operators** `IS DISTINCT FROM` / `IS NOT DISTINCT FROM` (e.g. `owner_id IS DISTINCT FROM auth.uid()`); and **`NOT` of a compound** — `NOT(A AND B)` / `NOT(A OR B)` are pushed inward (De Morgan) so each negated branch is witnessed instead of the whole negation being dropped. For each, the engine seeds a matching value/row and a non-matching one and verifies both.
- **`--implicit-deny` (opt-in): govern the full command matrix.** With `--emit --implicit-deny`, the suite also
  emits deny tests for commands a table has *no policy* for (RLS-on deny-by-default) — proving anon/authenticated
  can't `SELECT`/`INSERT`/`UPDATE`/`DELETE` where no policy grants it. So a future too-broad `GRANT` or policy
  that lets one of those through turns CI red. Probe-and-baked (only a cleanly-observed deny is asserted); off by
  default, so existing output is unchanged.
- **The emitted suite degrades gracefully on an un-seedable table.** If a table's data precondition can't be
  established (an unsatisfiable `CHECK`/FK the seeder can't defeat), the generated pgTAP file now prints clean
  `not ok … UNRELIABLE — seeded 0 rows … (seed error …)` lines under `pg_prove`/`supabase test db` instead of
  aborting the whole file on the seed error. Arrange statements run through a small error-swallowing helper so a
  failing seed leaves the table empty and the baked `UNRELIABLE` assertion still reports. (Still a loud failure,
  never a false pass — same as the `--report` path already did.)
- **Construct-first witness floor — a brand-new operator is testable with no operator-specific code.** When no
  named shape matches a predicate, the engine now collects the predicate's free row column + literal operands
  and *asks the database*: it seeds the column across a small candidate set and keeps the value that makes the
  policy grant and the one that makes it deny, then DB-verifies and bakes the pair. This solves predicates the
  engine has never seen — a bare boolean function (`starts_with(name,'Admin')`), an operator buried in an
  expression (`(n % 2) = 0`), even a **custom operator** — instead of leaving them `NOT_TESTABLE`. Sound by the
  same rule as everything else: only a DB-confirmed true+false pair is emitted; otherwise honest NT. When a
  single column isn't enough, the floor escalates to a **joint search** over the predicate's full signature —
  every row column *and* JWT claim it references — trying a bounded set of `(session × row)` assignments until
  the database grants for one and denies for another. This covers predicates that need *coordinated* inputs: two
  columns that must agree under a custom operator, or a claim compared to a column via an operator the engine has
  never seen. Budget-capped, so anything beyond the bound (or reading hidden/external state) stays honest NT.
  Opaque-function-dependent predicates keep their existing wiring-mock handling.
- **Cardinality / aggregate-gated policies are now tested — the relational-state floor.** When a policy's truth
  depends on *how many rows* it reads in another table rather than on the row under test — a `(SELECT count(*) …)
  >= N` threshold, a `sum(...)`/`avg(...)` limit, a multi-row condition — the engine seeds a *candidate number*
  of matching rows in that table (cardinalities drawn from the policy's own constants) and lets Postgres evaluate
  the real aggregate: the count that makes the gated row visible is the witness, one that hides it is the
  falsifier. So a "visible only if you own ≥ 3 of X" policy flips from `NOT_TESTABLE` to a real ✓/blocked test.
  This is a floor, not a per-operator handler — a brand-new aggregate gate is covered with no new code — and it is
  probe-and-baked like everything else (only a DB-confirmed grant/deny pair is emitted; otherwise honest NT). New
  example `examples/witness_cardinality.sql`.
- **The report now explains every `–` (not-tested) cell — a dash is never silent.** Two paths: (a) when a predicate uses an operator/atom the engine can't synthesize a sound witness for (an exotic operator or opaque shape), the footgun names the reason and points to `--debug-unhandled`; (b) a `–` with *no* known reason — a seed row the engine couldn't synthesize (an unsatisfiable `CHECK`/FK, a `UNIQUE` collision, an unknown column type) or a coverage gap — now gets an explicit "untested, no established cause — treat as not verified, not a pass" note. Combined with the loud `UNRELIABLE`/`BROKEN POLICY` paths (which fail the gate), every untested cell is accounted for. An unsatisfiable `<> ALL`/`NOT IN` (a dead, over-restrictive branch that can never grant) is now reported as exactly that.

## [0.1.5] — 2026-06-24

First release since 0.1.2. (An interim 0.1.4 was committed but never published — its CI was red — so all of
its changes are folded into this entry.)

### Added
- **Probe-and-repair seed synthesizer.** Builds a valid row to test against even when a table's
  constraints defeat a templated insert — filling `NOT NULL` columns, seeding single and **composite**
  foreign-key parents, varying values to clear `UNIQUE` conflicts, and neutralizing a `CHECK` that
  delegates to a function (then restoring it). Lets opaque-function-gated tables be exercised.
- **`UNRELIABLE` results.** The probe now separates the *arrange* (seeding) phase from the *act* phase
  and runs a post-arrange invariant. If a test's data precondition can't be established, the cell is
  marked `UNRELIABLE` and the suite/gate fails loudly — a seeding failure can no longer be mis-reported
  as a policy denial or a silent pass.
- **General, DB-verified predicate solver, now per-branch.** For policies that don't match a named shape,
  the engine derives inputs that should make the predicate pass and fail, verifies both against the
  database, and only then writes a test. It now also runs **per-min-term**, so a novel branch OR'd or
  AND'd with a recognized one is verified instead of dropped.
- **Cross-policy `WITH CHECK` leak detection.** Flags the Postgres behaviour where multiple permissive
  `UPDATE`/`INSERT` policies OR-combine their `WITH CHECK` clauses, letting an identity write a value
  only a *different* policy intended (e.g. a role jumping a status it shouldn't).
- **Wiring tests for shadowed opaque functions.** When an opaque function policy is OR'd with a
  classifiable one, the function branch is now mock-wired (and the table carries the "function logic not
  verified" note) instead of being silently untested.
- Broader policy recognition: scalar role-lookups (`(select role from profiles where id = auth.uid())`),
  `col = ANY(...)` / `IN` / `<> ALL`, numeric-threshold and JWT-claim/GUC gates.
- `--debug-unhandled`: read-only flag listing every policy branch the classifier can't recognize.
- New example schemas: `clearance`, `transitions`, `synth`, `seedfail`, `updcheck`, `adversarial`.

### Fixed
- **Report cells now reflect real grants.** RLS-off tables and the `service_role` row are no longer shown
  as fully accessible by assumption — each command's cell respects the actual table `GRANT` (a missing
  grant blocks it, even for the service key). Removes over-stated "security hole" / access cells.
- **UPDATE testing.** The probe now changes a *policy-neutral* column to a *constraint-valid* value
  (instead of possibly the gated/CHECK'd column), classifies a non-`42501` error as `UNRELIABLE` rather
  than a denial, and prints an explained `–` when a table has no neutral column to modify.
- **Membership seeding** for a table that is itself the FK-parent of its own scope table (e.g. `orgs`
  with `memberships.org_id → orgs.id`): the main row is now seeded idempotently, fixing a primary-key
  collision that was being mis-recorded as a denial.
- Seeding order: aux/scope rows are seeded before main rows so an identity-linking column isn't
  overwritten by a generic foreign-key fill.
- The general solver no longer skips tables that have a required foreign-key column, and emits
  type-valid witness values for `timestamp`/`date` columns.
- **CI integration workflow.** The negative-gate test steps (`seedfail`, `updcheck`) now capture the
  gate's exit code with `|| rc=$?` — no masking `tee` pipe, and exempt from `set -e` (a bare `cmd; rc=$?`
  aborts the step on the gate's expected non-zero before the code is read). Tooling behaviour was already
  correct; only the workflow's exit-code check was wrong.

### Changed
- Removed all "read-only" / "safe to run on production" claims. The tool seeds rows and runs
  `SELECT/INSERT/UPDATE/DELETE` while probing (each rolled back), so the docs and a startup banner now
  direct you to point it at a **disposable copy** of your database, never production.

## [0.1.2] — 2026-06-22

- Initial public release: deterministic pgTAP test **and seed-data** generation for Postgres / Supabase
  Row-Level Security, a per-identity access-matrix report (`--report` / `--html`), static `lint`,
  policy `snapshot`/`diff`, and a CI gate that fails on an exposed or unprotected table.
