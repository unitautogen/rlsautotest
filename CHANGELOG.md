# Changelog

All notable changes to **rlsautotest** are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/); this project is pre-1.0 and versions
roughly follow semantic versioning.

## [0.2.0] - 2026-07-12

### Fixed
- **A mock/helper `CREATE` permission failure can no longer produce a false-passing suite** (#2).
  When the connection role cannot `CREATE OR REPLACE` a policy function or install helpers (typical on
  Supabase when connecting as `postgres`, since helpers are owned by `supabase_admin`), the probe used to
  swallow the failure, observe the real (unmocked) function denying everything, and bake that degenerate
  outcome as the expected behavior. Now: any failed `CREATE`/`ALTER`/`DROP` in a probe's arrange marks the
  affected identity/command **UNRELIABLE** (a loud failing `fail()` test, a `‼` report cell, exit 1); the
  bool-UDF wiring battery preflights mock creatability and refuses to emit assertions it could not prove;
  the report files UNRELIABLE cells from generation-time observations even when the replay itself cannot
  run pgTAP (e.g. the shim is not creatable), with an explanatory note.
- **`--parallel N` no longer shares one connection across worker threads.** Each worker gets a private
  connection, fixing the `InFailedSqlTransaction` crash where one aborted probe poisoned every other
  table's transaction, and eliminating cross-thread identity/claim bleed. Parallel output is identical to
  sequential.
- **`--flat`/`--out` combined with `--report`/`--html` now writes the test files too** (the report path
  used to exit before the file was written); the CI gate exit code still applies.

### Added
- **`rlsautotest doctor`**: one command that verifies the probe environment (server/role, `SET ROLE` to
  each client role, schema `CREATE` privilege, pgTAP availability, and per-policy-function ownership /
  `CREATE OR REPLACE`-ability, each failed check printing its exact remedy) and always writes a redacted
  `doctor.json` diagnostic bundle to attach to bug reports: catalog metadata and sqlstates only, no row
  data, no credentials. All checks are savepoint-wrapped and rolled back.

### Changed
- **Internal architecture: the single-module engine was split into focused modules** (astutil, values,
  catalog, atoms, witness, probe, seeding, structs, emit, report, lint, snapshot, commands) and the
  emitter's nine nested strategy closures became plug-in **witness strategies** dispatched by an ordered
  registry (`rlsautotest/strategies/`). The four duplicated probe-then-bake sqlstate triages are unified
  in a single `ProbeBaker`. Behavior-preserving: the emitted SQL for the whole example corpus is
  byte-identical; `from rlsautotest.cli import X` still works for every symbol.
- **The report matrix is now filed from machine-readable observations, not from parsing the English test
  descriptions.** Every emitted test records what command/identity it exercises and the outcome it
  asserts; the report matches TAP lines to those records by test number. A strategy's label wording can
  no longer misfile a matrix cell (the old keyword parser remains only as a fallback for files emitted by
  older versions).

### Added
- **Zero-argument claim functions are introspected instead of mocked.** A policy gated on a
  zero-arg boolean function whose body is a transparent JWT-claim check (`is_admin()` as
  `auth.jwt()->>'app_role' = 'admin'`) previously fell to the opaque-fn mock wiring path (sound,
  but only a wiring proof plus a footgun note). The introspector now reads the expected value from
  the function body, so the authorized identity carries the real claim and the policy is tested for
  real. New fixture `examples/zeroarg.sql`. A wrong guess stays sound: the probe bakes only the
  observed outcome.

### Changed
- **The legacy nested `runtests()` debug artifact is no longer written by default.** It predates the
  probe engine (no probe, no transition audit, no UNRELIABLE, no solver) and drifted further from the
  real suite each release. `--emit` now writes only the native flat pgTAP suite; pass
  `--debug-emitter` to also get `.rlsautotest/debug/` (and `--out` still produces it for a single
  table). Reports get faster since the unused artifact is no longer generated per table.

### Added
- **Policies granted `TO some_custom_role` stop vanishing.** The client matrix models
  PUBLIC/authenticated/anon, so a policy for any other role used to be silently excluded. A new
  custom-role strategy probes each role named by a table's policies via a real `SET ROLE` (no JWT
  identity) against a synthesized existence row, bakes the observed grant/deny for every command,
  and the report grows a per-role row (`reporter (custom role)`). New fixture
  `examples/customrole.sql`.

### Added
- **A missing client grant on an opaque-fn-gated command is now a baked, passing deny test instead
  of an untested dash.** When a FOR ALL policy delegates to an opaque function but the client role
  was never granted the command (e.g. permission-override tables that allow INSERT/DELETE but not
  UPDATE), the suite records the expected behavior: even a fully policy-authorized identity is
  denied at the GRANT layer (`throws_ok ... 42501 ... denied as expected`). Only a cleanly observed
  42501 is baked; anything else stays an honest dash.

- **Commands no client policy grants are now proven under the authorized row too.** When a command
  is in the matrix only through non-client policies (a `service_role` FOR ALL, a custom role's
  policy), no identity could ever be "authorized", so the engine emits the expected-behavior proof
  for the whole authenticated population: the observed deny is baked as a passing test in the
  authorized row (like every other row's per-identity proofs) instead of an untested dash. Only a
  cleanly observed deny is baked; an unexpected grant stays visible as the not-authorized row's
  danger cell.

- **Every report cell is now backed by an emitted test.** Two inference-only areas remain tested:
  - **Implicit-deny tests are emitted by DEFAULT** (previously opt-in `--implicit-deny`, now kept as
    a no-op for compatibility; `--no-implicit-deny` restores the old behavior). Commands no policy
    mentions at all get their observed deny-by-default baked per client identity, so the full
    command matrix is governed in CI.
  - **The service_role row is probed and baked like every other identity** (via
    `tests.authenticate_as_service_role()` in helper mode, `SET LOCAL ROLE service_role` otherwise)
    instead of being inferred from the grants map. Its INSERT uses a fresh synthesizer-built row,
    since service INSERTs actually land and a reused identity row collided with the seed (23505).
    The report prefers the tested observation; the grants inference remains only as the fallback
    for cells where no sound test could be constructed.

### Added
- **Key-and-scope-only tables get a real UPDATE test via self-assignment.** When a table has no
  policy-neutral column at all (`wcard.events` pattern: just a primary key and the owner column the
  policy watches), the UPDATE probe falls back to `SET owner = owner`: nothing changes and no row
  moves between scopes, but Postgres still enforces the UPDATE privilege and re-evaluates
  USING/WITH CHECK — exactly what the cell claims to measure. The explained dash now appears only
  when nothing is even self-assignable (identity/generated or unique columns only; new negative
  fixture table `updcheck.t4` guards that residual path).

### Fixed
- **`--report-json` works again.** The in-memory report grew sets (`unreliable_cells`) and
  tuple-keyed dicts (`grants`) that `json.dumps` cannot serialize, so the flag crashed and wrote an
  empty file. The writer now renders sets as sorted lists and tuple keys as `a:b` strings.
- **The fresh-identity INSERT test now acts AS the fresh identity.** When the owner/link column is
  unique or the primary key (the classic `profiles` pattern: `WITH CHECK (auth.uid() = id)`), the
  authorized INSERT must use a fresh user whose uid matches the inserted row; the probe was
  authenticating with the class's claims instead, observed the WITH CHECK denial, and baked a
  wrong-direction "denied" cell (never a false pass, but the matrix said blocked where the policy
  clearly allows). The insert plan's own claims are now used, and the fresh identity's uuid is
  seeded into `auth.users` alongside the other synthetic subs. `public.profiles` INSERT flips from
  blocked to a real passing lives_ok across the corpus.
- **Solver aux rows (membership side-tables) now seed exotic column types, and solver-discovered
  tables are loaded on demand.** A non-canonical membership policy whose side table carries an
  exotic NOT NULL column (or any required column, since the classifier-rejected table was never
  loaded into the column map at all) failed its aux INSERT, the witness never confirmed, and the
  cells stayed an explained dash. `_seed_one` is now DB-oracle verified and the solver/relstate
  paths load a discovered table's columns and FKs on demand. New fixture tables `xtypes.rooms` /
  `xtypes.room_members`.
- **A boolean function whose name appears only inside a policy's string literal is no longer
  mock-listed.** The opaque-function detector matches actual function-call nodes in the policy parse
  tree instead of regexing the policy text, so the wiring tests mock (and their labels blame) only
  functions the policy really calls.
- **Tables where every column is defaultable can now be wiring-tested.** The synthesized existence
  row for such a table produced invalid SQL (`INSERT INTO t() VALUES ()`), which silently killed the
  mock-test precondition and turned the wiring tests red; it now emits `INSERT ... DEFAULT VALUES`
  (the INSERT wiring test also becomes possible). Fixture `rxf.reviews` covers both fixes.
- **A column name inside a policy's string literal no longer blocks the UPDATE probe.** The set of
  columns a policy references (used to pick the policy-neutral UPDATE column) is now read from the
  policy's parse tree instead of a regex over the policy text, so `status <> 'note deleted'` no longer
  disqualifies a real `note` column and the UPDATE cell is tested instead of an explained dash. New
  fixture `examples/regexfree.sql`.
- **Exotic column types are now seeded (and UPDATE-probed) on the classified path too.** 0.1.7 routed the
  probe-and-repair synthesizers through the DB-oracle literal check; now the classified seed plan and the
  UPDATE probe's SET value use it as well, so an owner/tenant-scoped table with `inet`/`macaddr`/`bytea`/
  DOMAIN columns flips from UNRELIABLE to a fully tested green matrix (new fixture table
  `xtypes.sensors` in `examples/exotic_types.sql`). Known types keep byte-identical literals.

## [0.1.7] — 2026-07-11

### Fixed
- **Real multi-tenant-RBAC extensions (e.g. supabase-tenant-rbac) now generate a correct, fully green suite.** Running the engine against a real RBAC extension's own tables surfaced a cluster of gaps; each is fixed and guarded by the new `examples/rbac_tenant.sql` regression fixture. None of these was ever a false pass — they were mis-classifications, seed failures, or file aborts.
  - **Per-command classification.** A login-only `WITH CHECK (auth.uid() IS NOT NULL)` is now recognized as "open to any authenticated user" and tested on its own predicate, instead of being mock-wired against helper functions the command never calls. A command is classified by its OWN predicate, not by the table's other policies.
  - **Identity seeding.** The synthetic test identities are registered in `auth.users`, so a bootstrap trigger that inserts an ownership row (foreign-keyed to `auth.users`) resolves during the probe; and every synthetic authenticated JWT now carries a future `exp`, so an expiry-aware helper (a `_jwt_is_expired`-style guard) returns false instead of raising `invalid_jwt`.
  - **Identity-neutral seeding.** Seeding as the privileged role now clears the JWT claim, so an ownership-on-insert trigger does not attribute a freshly seeded row to the last probed identity.
  - **UPDATE probe.** The policy-neutral column picker no longer excludes a column just because it has a `DEFAULT` (only `IDENTITY`/`GENERATED` columns are truly unsettable), and array columns are SET to a valid non-empty literal.
  - **Row synthesis.** The probe-and-repair synthesizer satisfies an array-cardinality `CHECK` (`cardinality(col) > 0`) by seeding a non-empty array, and the mock `INSERT` cleans the table first so the insert-under-test can't collide with a seeded row on a multi-column `UNIQUE`.
  - **Grant-aware mocking.** A command the client role has no `GRANT` for is no longer mock-"authorized" (which would hit `42501` and abort the pgTAP file); the real no-grant denial is baked instead.
  - **Role-scoped classes.** A policy granted only to `service_role` (e.g. `USING (true)`) no longer spawns a bogus authenticated "open" branch; the client matrix is derived only from `PUBLIC`/`authenticated`/`anon` policies.

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
- New example `examples/recursion.sql` — a VALID self-referential hierarchy (`WITH RECURSIVE` from an `owner = auth.uid()` base, reading the tree through a `SECURITY DEFINER` function so the policy does not re-enter its own RLS, i.e. no `42P17`). Wired into the CI green loop so the recursion strategy's happy path is guarded end-to-end; previously only the deliberately-broken `exotic.folders` case exercised that code, and it is excluded from the green loop.
- **Exotic column types can now be seeded (DB-oracle value synthesis).** The row synthesizers (`_synthesize_row` and the mock-path `_mock_valid_row`) previously filled a NOT NULL column with a substring-guessed literal (`'x'` for anything unrecognized), so a table with an `inet`, `macaddr`, `bytea`, `citext`, range, or `DOMAIN` column could not be seeded — the INSERT failed to cast and the policy branch degraded to UNRELIABLE / NOT_TESTABLE. A new `_castable_lit` verifies a literal against the live type (trying the fast guess first, so every previously-handled type is byte-for-byte unchanged) and, for an unknown type, probes a small candidate list with the database as the oracle. New regression fixture `examples/exotic_types.sql`. (The UPDATE-probe SET value and the classified `_seed_plan` fill are separate value sites not yet routed through the oracle.)
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
