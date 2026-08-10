# Changelog

All notable changes to **rlsautotest** are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/); this project is pre-1.0 and versions
roughly follow semantic versioning.

## [0.7.0] - 2026-08-07

### Added
- **The member-of-2-tenants probe: a seeded identity that belongs to TWO tenants, with the union cardinality it should see pinned as a test.** (#4) Every test identity used to hold exactly one membership, so a policy bug that only manifests when a real user belongs to two teams -- the classic being `team_id = (SELECT team_id FROM team_members WHERE user_id = auth.uid())`, which raises `21000` (or picks one team arbitrarily under `LIMIT 1`) the moment someone joins a second team -- passed every generated test. For a table whose SELECT branch is a canonical membership policy, the engine now seeds one identity with membership rows in two scopes plus one visible row in the second scope, probes what that identity actually sees, and judges it differentially against the single-membership branch identity: the union confirms -> the exact count is baked as a green `authenticated, member of 2 tenants` test (so any later policy drift that mis-serves users who belong to 2 tenants turns the suite red); the query errors, or the identity sees fewer/more rows than its two memberships grant -> a failing test is baked, the report marks the new `authenticated, member of 2 tenants` row (`✗`/`✓!`), a `MEMBER OF 2 TENANTS` note explains it, and the CI gate exits non-zero. Judgement is enforcement-only, never intent: the probe runs solely on a pure canonical-membership branch, where nothing in the policy (no claim or session input) could legitimately narrow a two-membership view to one. It is skipped, by construction, when the table under test is (or FK-reaches) the membership table itself -- seeding the two memberships would insert rows into the very table being measured (the rival identity's self-pollution guard, reused) -- and when the membership table's schema makes a second membership impossible (a unique user column), because then the state cannot exist in production. SELECT-only in this release; suites for tables without a canonical membership branch are byte-identical.
- **`lint` flags the scalar-subquery membership lookup.** (#4) `col = (SELECT ... FROM t WHERE ... = auth.uid())` works only while every user has at most one row in `t`; a second membership makes every query on the table error for that user (`21000`), and a `LIMIT` variant silently picks one membership arbitrarily. Flagged HIGH with a fix suggestion (use `EXISTS`/`IN` over the membership table, or resolve the value into a JWT claim at auth time). The detector reads the policy's parse tree, not a regex: the `(SELECT auth.uid())` initplan idiom (no `FROM`) and the multi-row-safe `EXISTS`/`IN`/`ANY` forms are never flagged, and a lookup keyed on a UNIQUE column (the classic read-my-role-from-my-profile-row shape, at most one row by schema) is exempt.
- New fixture `examples/multimembership.sql` (canonical EXISTS membership, the membership table itself, its FK parent, and the scalar-subquery hazard) wired into the CI green loop, plus a CI step proving all three guards: lint flags the scalar shape; the emitted union-cardinality pin goes red when the policy drifts to an arbitrary-pick shape; and the report gate catches the same drift at generation time.
- **The relational-state fallback now bakes anon's no-grant SELECT denial instead of leaving the cell untested.** When a table's SELECT policy is unclassified and the DB-oracle fallback (BL-12) probes anon, a table where anon holds no SELECT grant used to return an error rather than a count, so nothing was baked and the report showed a `-` (not tested) cell with a NOT TESTABLE note. But that specific denial is decided by GRANTs alone -- SQLSTATE `42501` fires before any policy row filtering -- so it is provable without understanding the policy. The fallback now recognizes the probed `42501` and bakes the same `throws_ok('42501')` denial test the write batteries emit for implicit deny, turning the cell into a tested "blocked". Only the observed insufficient-privilege case is baked (probe-and-bake, never a guess); any other anon probe error still leaves the cell honestly untested. Suites where anon holds a SELECT grant, or where the SELECT branch is classified, are byte-identical.
- **Obligation-based branch routing: every branch of every policy is now tested (or loudly declared untested) -- no branch rides along silently.** Four generic changes, no pattern-specific code: (1) the DNF dedup key now includes an unclassified atom's identity, so two DIFFERENT not-yet-understood branches can no longer collide and silently drop one of them from the model; (2) an unhandled min-term OR'd with a classified branch is routed, node-scoped, through the full fallback chain (general solver, then the relational-state DB-oracle floor) instead of only the bare per-min-term solver -- and the opaque-function refusal is now per-BRANCH, not per-table, so a solvable predicate is no longer refused because a SEPARATE policy delegates to a function; (3) the solver and the relational-state floor no longer stop at the first confirmed policy: EVERY permissive policy of a command gets its own battery, and an OR predicate additionally gets one battery per disjunct (labeled ` [branch N]`), so a second policy or a second branch can never hide behind the first one's green; (4) a branch that STILL cannot be witnessed is recorded and surfaced -- a `PARTIALLY TESTED` footgun note in the report naming the command, policy and reason, and a matching comment in the emitted suite -- instead of disappearing behind a green sibling cell. All new tests remain probe-and-baked (only DB-observed outcomes are asserted); suites for tables with a single fully-classified policy are byte-identical. New fixture `examples/mixedor.sql` (a classified-OR-novel branch, two permissive policies on one command, and a `NOT (a AND b)` De Morgan pair) plus CI guards that fail if the per-disjunct batteries or the branch rescue ever regress.
- **Function understanding: a policy that delegates to a user-defined boolean function is now tested with REAL inputs when the function's body is readable.** The engine expands the parsed body (SQL and single-expression plpgsql, `SELECT EXISTS(...)` and `count(*) > 0` shapes, call-site constants substituted for parameters, functions calling functions expanded transitively) into an effective predicate and uses it ONLY to decide what to seed; the probe and every baked test run the policy with the REAL function, so a wrong or incomplete expansion degrades to the existing mock wiring proof and can never fabricate a pass. Real-input batteries are emitted BEFORE the wiring block on purpose: wiring re-installs the generation-time function definition mid-file, so a battery emitted after it would exercise the restored body and a drifted function would slip through on replay -- emitted first, a function body that drifts (broadened OR narrowed) turns the suite red, which is the point. VOLATILE functions, non-constant arguments, multi-statement or control-flow bodies (the `rbac_tenant` shapes), and dynamic SQL stay on the honest wiring path unchanged. New fixture `examples/fnexpand.sql` (EXISTS body, `count(*)>0` body, a function calling a function, and a deliberately unexpandable dynamic-EXECUTE control) plus CI guards for both directions; `regexfree`'s reviews table upgrades from wiring-only to a DB-verified solver battery, and the rest of the corpus is byte-identical.
- **Mock-wiring batteries are probe-first now -- the last guessed-assertion path is retired (MB-1).** When a policy delegates to an opaque boolean function whose body cannot be read, the engine mocks the function true and false to prove the policy WIRES to it. Those wiring batteries used to bake reasoned expected outcomes (`count = 1`/`0`, `lives_ok`/`throws_ok`) without ever probing -- the codebase's one remaining exception to probe-and-bake. They now probe the mock-true and mock-false arrangements against the live database at generation time and bake the OBSERVED outcome through the same ProbeBaker every other strategy uses. A policy that does not actually gate on the mocked function (another permissive policy grants, or a restrictive conjunct blocks the row) bakes the honest observation instead of a guess that would false-fail on replay; and a new soundness guard turns an un-isolable wiring proof -- mocking the function TRUE does not grant the command -- into a loud UNRELIABLE naming the cause, never a misleading "authorized denied" cell. Because every existing wiring test already passed on replay, the observed outcomes equal the previous guesses: every report matrix cell is byte-identical, and only the assertion wording changes (the udf-table suites rebaseline to the `mock_force` wording).
- **Correct on every way Postgres names a policy audience.** A policy with no `TO` clause is stored as `polroles = {0}` -- the PUBLIC pseudo-role, which has no `pg_roles` row -- so literal role matching read "no policy references any role" for entire schemas that omit `TO` (the reported bug; the reporter's audited schema was 17/17 no-`TO`). Role discovery (`auth_profile`) now models PUBLIC explicitly, admits LOGIN client roles reachable only through PUBLIC (still excluding the connecting role and the schema owner), and tests audience membership with `pg_has_role` so a policy `TO some_group` is correctly attributed to every role that inherits it -- the same bug class reached through the role graph. Lint learned the same lesson: L001 and L007 now treat a no-`TO` policy as anon-inclusive (the reporter's exact `USING (true)` policy is CRITICAL, not HIGH), and a new HIGH rule, **L017**, flags a permissive no-`TO` policy sitting beside role-scoped policies -- the classic policy NAMED "Service role full access" whose actual audience is everyone (deliberately quiet when the whole schema omits `TO`, the tutorial norm). Emitted suites now conditionally quote role names in `SET LOCAL ROLE` (a mixed-case role no longer breaks the file; lowercase output is byte-identical), `pg_*` predefined group roles in a `TO` clause are reported as an informational note instead of being probed via `SET ROLE` (which Postgres refuses for `pg_database_owner`), and the `tests.clear_authentication()` helper -- which hardcodes role `anon` -- is only used when the unauthenticated role IS `anon`, so a generic provider's suite (and a custom role probed with empty claims) replays as the same role the generator actually probed. New fixture `examples/publicto.sql` plus CI guards on the CRITICAL/L017 lints and the discovered-role identity; the generated-test engine was already PUBLIC-correct, and the rest of the corpus is byte-identical except the custom-role suites, whose replay identity now matches the probed role.
- **An owner policy whose identity cannot be bound is now flagged loudly instead of read as "correctly denied."** When a rowlinked authorized identity sees zero of its OWN seeded row, the precondition (the `auth.uid()`/claim binding resolving to the seeded owner) was not established -- the row was filtered away, not denied by intent. The engine previously baked the observed zero as a silent "blocked" cell, which is the exact false alarm a correct-but-unbound policy produces (a valid policy that appears to hide every row). It now bakes an UNRELIABLE assertion that fails loudly and names the likely cause: an `auth.uid()` shape the probe does not drive (the older flat `request.jwt.claim.sub` GUC, as used by some GoTrue and hand-rolled setups) or a custom session GUC such as `current_setting('app.*')`. Sound and narrow: only a rowlinked identity's own-row miss is reclassified, never a genuine cross-identity denial. Verified in an isolated regression database (`examples/authshape.sql`, which redefines `auth.uid()` to the flat shape and so cannot share the corpus DB); suites where the identity binds correctly are byte-identical.
- **New lint L018: a self-owned write that leaves an access-scope column unconstrained.** When a
  write policy pins the row to the caller's own identity (a `col = auth.uid()` / claim self-check) but
  the schema uses ANOTHER column to define access scope (a column compared against the caller's
  identity in some policy) and the write side never re-checks it, a caller can edit their own row and
  change that column -- reassign ownership, or move the row to another tenant -- while every
  per-command assertion still passes. L018 (MEDIUM) reports the policy, the constrained columns, and
  the unconstrained scope column(s), with the fix (add them to WITH CHECK). Scope-ness is derived from
  predicate STRUCTURE, not column-name heuristics, so `body`/`title` are never mistaken for scope keys;
  and a role/admin-gated write (e.g. `has_role(org_id,'owner')` inserting any `user_id` into a
  membership table) is deliberately NOT flagged, since setting other columns is the admin's intent.
  New fixture `examples/writescope.sql`. Lint-only -- no change to generated suites or the report gate.
- **The general subquery witness now handles a two-table inner join.** A membership-through-a-join
  policy -- `EXISTS (SELECT 1 FROM memberships m JOIN roles r ON r.id = m.role_id WHERE m.user_id =
  auth.uid() AND m.org_id = docs.org_id AND r.name = 'admin')` -- previously fell to "not tested"
  because the subquery grammar accepted only a single base table. The reader now recognizes a 2-table
  INNER join (JoinExpr or comma-join), identifies the anchor table (the one carrying the caller
  correlation / `auth.uid()`) and the joined table reached by the equijoin key, and the witness seeds
  BOTH tables -- the joined row first (so an anchor->joined foreign key resolves) with the join key
  shared between the anchor row's FK and the joined row's key -- then DB-verifies the grant/deny pair.
  A wrong seed (a non-uuid key, an unsettable identity PK, an opaque function on the joined table)
  simply fails to confirm and stays NT -- never a false pass. The single-table grammar is unchanged,
  so existing suites are byte-identical; the classifier and the relational-state floor stay
  conservative on joins (they defer to this witness). Joins of three or more tables remain deferred.
  New fixture `examples/joinsub.sql`.
- **The subquery witness now also handles an OR inside the subquery WHERE (MB-2b).** A membership
  policy whose EXISTS/IN subquery ORs two conditions -- `EXISTS (SELECT 1 FROM members m WHERE
  m.org_id = docs.org_id AND (m.user_id = auth.uid() OR m.via_group))` -- previously fell to "not
  tested" because the single-signature reader accepted only an AND-only WHERE. The reader now
  distributes the WHERE to DNF min-terms and takes the identity/correlation arm (the direct-membership
  arm); because any condition ANDed OUTSIDE the OR appears in every min-term, the falsifier that breaks
  the correlation still denies every arm, so the deny side is real. The chosen arm is a best-effort
  witness HINT: the classifier and the relational-state extractor stay conservative on it, and the
  general solver DB-verifies the grant/deny pair before baking -- an OR whose arms it cannot soundly
  isolate simply stays not-tested, never a false pass. The single-arm (AND-only) grammar was refactored
  to share one code path but is behavior-preserving, so every existing suite is byte-identical. New
  fixture `examples/orsubquery.sql` (a member-directly-OR-via-group policy that upgrades from not-tested
  to a DB-verified `[solver]` battery). Joins of three or more tables remain deferred.
- **A regression fixture now guards the Neon (pg_session_jwt) adapter (MB-11).** rlsautotest's support
  for Neon's RLS vocabulary and role model was built and verified against a real Neon database in an
  earlier release, but nothing in the corpus guarded it against a future regression. `examples/neon.sql`
  adds a Neon-shaped schema -- identity via `auth.user_id()` and claims via `auth.session()` (recognized
  by construct as the equivalents of `auth.uid()` / `auth.jwt()`), the roles `authenticated` and
  `anonymous`, and no `service_role` -- and the engine handles it on its own terms: `documents` is
  owner-isolated through `auth.user_id()`, `posts` is gated on a custom `user_role` claim read via
  `auth.session()`, and the report shows a faithful three-row matrix (authenticated authorized /
  not-authorized plus `anonymous`) with no phantom `service_role` row, because the role model is
  discovered from the catalog rather than assumed.
- **The offline `--emit` helper shim is now flavor-aware, so a Neon suite is runnable with the default
  `--emit` (no `--no-helpers` needed) (MB-11).** The `000-setup-tests-hooks.sql` shim used to hardcode
  Supabase's client roles -- it granted the `tests` schema to `anon, authenticated, service_role`, made
  `clear_authentication()` set role `anon`, and defined an `authenticate_as_service_role()`. On a provider
  with a different role model (Neon uses `anonymous`, not `anon`, and has no `service_role`) those roles do
  not exist, so the generated suite could not run as-is. The shim now derives its role vocabulary from the
  same catalog-discovered role model the rest of the engine uses: the unauthenticated role is taken verbatim
  when it is a conventional `anon`/`anonymous` (otherwise it falls back to `anon`, so a login role that a
  no-`TO`/no-anon-grant schema causes to be discovered as the unauth slot never rewrites the shim), and the
  RLS-bypass helper is emitted only when the provider actually has such a role -- on one that does not (Neon)
  it becomes a loud-failing stub instead of a call against a missing role. A standard Supabase role model
  produces the previous shim byte-for-byte, so every existing suite is unchanged; a Neon schema's setup hook
  now grants to `anonymous`/`authenticated` and authenticates as `anonymous`, and the emitted Neon suite runs
  green end-to-end.
- **The plain-text `--report` now lists the bypass surfaces too (MB-9).** The objects and roles that can
  sidestep RLS even when the policies are correct -- a client-reachable SECURITY DEFINER view or function
  that reaches an RLS table, a mutable-search_path definer function, a dual-write path, a role that
  bypasses RLS -- were already surfaced in the HTML and `--report-json` output (the L011-L015 / L020
  bypass lint, shipped in 0.3.0); only the text report omitted them. It now prints a `bypass surfaces
  (N found)` section, severity-ordered and shown ONLY when findings exist (a clean report stays terse),
  reading the SAME findings the other formats do. The section is DELIBERATELY informational and NOT wired
  into the pass/fail exit gate: a corpus audit confirmed that legitimate green schemas routinely expose
  sanctioned SECURITY DEFINER helpers (recursion readers, write-rpcs, org-creation triggers), so gating on
  them would false-fail correct schemas -- a bypass surface is a review flag, never a generated test (there
  is no oracle to green a definer body). Two follow-on sub-parts of the original ask also shipped this
  release (their own entries below): an opt-in CI gate that can fail on bypass surfaces, and an UNRELIABLE
  cell for a PROBED client role that itself carries BYPASSRLS. The four corpus reports that carry definer helpers
  (rbt, recursion, dw, rcw) rebaseline to add the section; every other report is byte-identical and no
  emitted suite changes.
- **Custom-role column-level-security parity: a custom role's column grant now carries the same CLS
  assertion the standard roles get (MB-12).** Column-level security (0.4.0) flags a column-specific GRANT
  that a BROADER grant silently bypasses and bakes one parity assertion per column-scoped cell. It covered
  the standard client roles (service_role / authenticated / anon) but not a CUSTOM role: a policy-named
  role such as an `auditor` holding `GRANT SELECT (id, ...)` showed its column scope in the report grid
  while the emitted suite asserted nothing for it -- the report claimed a scope the suite never guarded.
  The suite's CLS role set now also gathers custom roles that hold a column-level grant
  (`pg_attribute.attacl`), through a shared `colsec.column_grant_roles` helper, so the report and the suite
  read the SAME roles and can never disagree about a custom role's column scope. A table with no
  custom-role column grant adds no roles, so every existing suite is byte-identical. New fixture
  `examples/clscustom.sql` -- a custom `clsc_auditor` role column-scoped to `[id, amount]` on one table
  where the scope holds (a passing assertion) and to `[id]` on another where a table-wide grant leaks
  owner/action/ip/secret past it (the assertion names the leak) -- wired into the local regression corpus
  and guarded in CI.
- **A `--no-probe`/`--structural-only` mode emits a suite that runs ZERO probes, safe to point at a
  production replica (MB-10).** Normally the engine executes real INSERT/UPDATE/DELETE against the target
  to observe each policy outcome (inside an always-rolled-back savepoint, so nothing commits) -- but a user
  who wants a hard guarantee of no side effects can now pass `--no-probe` (alias `--structural-only`). It
  runs no live probe at all and emits only the tests that need none: the schema-wide RLS-enabled guard, a
  per-table RLS-enabled assertion, and the column-level-security parity assertions. The row-level
  grant/deny matrix is honestly left NOT generated -- each file carries a loud note saying so and pointing
  the reader to re-run without the flag against a disposable copy for full coverage -- so partial coverage
  is never dressed up as a pass. The flag is strictly opt-in: without it every emitted suite is
  byte-identical to before (verified across the corpus). Two details keep each emitted file valid: the
  arrange block (test-user creates, the pre-seed DELETE, and the seed) is omitted so the file performs no
  writes at all, and a table that would otherwise plan zero assertions gets one genuine no-probe assertion
  (RLS must be enabled on the reachable table) so a real pgTAP `finish()` does not error on an empty file.
- **The member-of-2-tenants guard now also pins the WRITE union (MB-3b).** The two-membership probe
  previously pinned only what a user in two tenants can SEE (the SELECT union cardinality). It now also
  probes whether that user can WRITE into their SECOND tenant: for a canonical EXISTS-membership table that
  also takes a membership-scoped INSERT on the same scope column, the engine probes the 2-tenant member
  inserting a row scoped to their second org and bakes the OBSERVED outcome -- a correct WITH CHECK gives a
  passing `isnt_empty` (drift-pinned), and a later policy change that blocks the second tenant turns it red.
  The single-membership battery only ever exercised the first tenant, so this closes the write side of the
  same blind spot. Sound and narrow: it runs only when the seeder built the second-org insert row (a
  matching membership INSERT branch), so owner/other write shapes and every non-membership table stay
  byte-identical; in the corpus only the two canonical-membership-with-INSERT tables (mtt.docs,
  tenancy.projects) gain the assertion and a ✓ in the member-of-2-tenants INSERT cell.
- **The subquery join witness now handles chains of three or more tables (MB-2b).** A membership policy
  whose EXISTS subquery joins three or more tables -- `EXISTS (SELECT 1 FROM memberships m JOIN roles r ON
  r.id = m.role_id JOIN role_types t ON t.id = r.type_id WHERE m.user_id = auth.uid() AND m.org_id =
  docs.org_id AND t.name = 'admin')` -- previously fell to "not tested" because the reader accepted only a
  single two-table join. It now recursively flattens the FROM into its base tables and every ON condition,
  union-finds the columns tied by equijoins into shared-value groups (so one value flows correctly along the
  whole chain, even where a table joins another joined table rather than the anchor), and seeds one row per
  table in FK-parent-first order before DB-verifying the grant/deny pair. A wrong seed -- an unsatisfiable
  shape, a join key the schema does not actually share, or a joined lookup table the querying role cannot
  read -- simply fails to confirm and stays not-tested, never a false pass. The single- and two-table
  grammars are unchanged, so existing suites are byte-identical. New fixture `examples/joinsub3.sql`
  (a memberships -> roles -> role_types chain).
- **An opt-in CI gate on bypass surfaces, with a sanctioning list (MB-9).** rlsautotest already surfaces
  the objects that can sidestep RLS even when the policies are correct -- SECURITY DEFINER views/functions
  reachable by a client role, and roles with BYPASSRLS/superuser -- as review flags in the report. They can
  now also fail the CI gate, but only when you opt in: `--fail-on-bypass[=SEVERITY]` (a bare flag means
  CRITICAL) fails on any bypass finding at or above SEVERITY. Because an intentional definer helper is a
  legitimate, reviewed surface, `--allow-bypass CODE:OBJECT` (or a bare CODE) sanctions specific findings so
  only a NEW, unsanctioned surface trips the gate. The flag is off by default, so every existing suite,
  report, and gate is byte-identical; turning it on is how a team declares that no undeclared RLS bypass may
  land.
- **A client role that itself carries BYPASSRLS is now caught as UNRELIABLE, never a false pass (MB-9b).**
  If the role the tests run as (the `authenticated` identity, or the unauthenticated role) itself has
  BYPASSRLS, it sees every row regardless of policy -- so a passing row-level observation there cannot tell a
  correct policy from a broken one, exactly the false pass this tool exists to prevent. rlsautotest now detects
  it: client-role discovery no longer folds a conventionally-named bypassing role into the sanctioned
  service_role slot, and every matrix cell probed as such a role is baked as a loud UNRELIABLE (a failing
  assertion that names the cause) instead of a green. The sanctioned service_role bypass row is exempt, since
  showing that it bypasses is the point of that row. Off by construction for normal schemas (no client role
  bypasses RLS), so every existing suite and report stays byte-identical; it is covered by unit tests rather
  than a corpus fixture, because a shared BYPASSRLS client role cannot be added to the example database safely.
- **UNRELIABLE cells now tell you how to fix them (MB-24).** When rlsautotest cannot trust a probe result it
  marks the cell UNRELIABLE -- a loud failing test, never a false pass. Each UNRELIABLE finding now carries a
  specific `Fix:` for its cause: a client role that bypasses RLS says `ALTER ROLE <role> NOBYPASSRLS`; a mock
  or helper that could not be installed says to connect as the role that owns it or run `rlsautotest doctor`;
  an identity whose claim did not resolve to its own seeded row says to align the claim style or probe with
  `--as-user`; a write that tripped a table CHECK says to give the column a CHECK-satisfying value; and a
  seeded-0 cell distinguishes a row that could not be planted at all (the seed INSERT hit a table
  CHECK/constraint -- give the table a conforming fixture row, or treat the cell as not auto-probable) from a
  row that was planted but is invisible to the identity (an owner-claim / RLS mismatch -- align the claim
  style), so it no longer blames identity binding when the real blocker was the seed. The
  guidance appears in both the failing pgTAP message and the report's UNRELIABLE section, replacing the old
  blanket "investigate seeding" wording that was accurate for only one of the causes. Off-path for clean
  schemas: the emitted suites are byte-identical (only the report legend line changed).
- **`--allow-unreliable`: sanction a reviewed, un-probeable UNRELIABLE cell so CI can pass (MB-25).** Some
  UNRELIABLE cells cannot be made measurable -- the seed row can only violate a table CHECK, so no probe row
  exists. Such a cell fails CI with no clean escape before now: `--no-probe` drops row-level coverage for
  every table, `--no-fail` drops the whole gate, and there was no per-table exclude. Now `--allow-unreliable
  [schema.]table[:CMD]` (repeatable; a bare table covers all four commands), or the same entries in a
  checked-in `.rlsautotestignore` at the repo root, sanctions specific cells: they stay visible as UNRELIABLE
  in the report (a new SANCTIONED note names them, never hidden) but drop out of the exit gate, and the
  emitted pgTAP line becomes `SELECT skip(...)` instead of `fail(...)`, so a committed suite run under
  pg_prove / `supabase test db` goes green on that cell without ever asserting a possibly-wrong result. Any
  UNRELIABLE cell you did not list still fails loudly. Mirrors the `--allow-bypass` sanctioning model. Off by
  default, so no flag and no file leaves every emitted suite and report byte-identical.
- **The unauthenticated row in the report is labelled clearly, not by a bare role name (MB-26).** When a
  schema's unauthenticated client role is not literally `anon` -- a custom LOGIN role, or Neon's `anonymous` --
  the report used to show it in the bottom identity row by its plain name, which reads like an ordinary named
  role and makes readers wonder where the "anon" row went. It now renders as `anon,
  anonymous-(unauthenticated)`, with a note under the table naming the real Postgres role behind it, so nothing
  is lost. A row whose role really is `anon` is unchanged. Report-only: the generated pgTAP suites are
  byte-identical.
- **A custom role that reaches a table through a PUBLIC policy is now shown, even if no policy names it
  (MB-27).** A custom client role got its own row on a table only when a policy targeted it with `TO <role>`.
  So a role granted directly on a table alongside the anon role, and admitted by the same no-`TO` PUBLIC
  `USING (true)` policy, had identical access yet was invisible on that table. The report now also probes any
  custom role that holds a direct table grant and is covered by a PUBLIC policy, so it appears with the same
  cells as the anon row (reads all rows under a `USING (true)` policy). Only direct grants count -- a table
  granted to PUBLIC does not pull in every role -- and it is additive: a table without this shape is
  byte-identical.
- **New lint L020: a "dual write path".** An RLS table whose intended write path is a client-callable
  SECURITY DEFINER rpc that holds the validation, while a client role ALSO holds a direct
  INSERT/UPDATE/DELETE grant on the table. Every per-command RLS assertion passes -- a direct own-row
  write genuinely is allowed -- but the client can skip the rpc and its validation entirely. Reported
  as an advisory (there is no oracle for "all writes must go through the rpc"), with the fix: REVOKE the
  direct DML so the rpc is the only path, after which the direct-write denial becomes an assertable
  boundary. New fixture `examples/dualwrite.sql`.
- **New lint L019: unwrapped auth.uid() re-evaluated per row.** `auth.uid()`/`auth.jwt()`/`auth.role()`
  called bare in a policy predicate is evaluated once per row; `(select auth.uid())` is hoisted to a
  single InitPlan (Supabase's 0003_auth_rls_initplan). INFO -- a performance note, behavior unchanged.
  Both L019 and L020 are lint-only -- no change to generated suites or the report gate.
- **UPDATE is now probed on tables whose only settable column is UNIQUE.** The self-assignment
  fallback (`SET col = col`, used when a table has no policy-neutral column so the UPDATE grant can
  still be exercised) previously excluded unique columns and so left a "-" dash on tables that are
  nothing but an identity PK plus a unique policy column (e.g. `updcheck.t4`). Assigning a row its own
  current value cannot collide with another row, so a unique column is safe to self-assign: the UPDATE
  privilege and the USING/WITH CHECK re-check are exercised exactly as intended, and a column-level
  denial still surfaces as an observed 42501, never a false grant. That last dash cell is now a real
  tested cell.
- **The HTML report leads with a "Coming soon - UnitAutogen for PostgreSQL, Supabase & Neon" banner.** A
  highlighted accent callout at the top of the report (above the title) lists the roadmap -- automated
  pgTAP suite generation and coverage for functions and triggers ready for CI, a database
  security-coverage suite (every function and trigger exercised under every database role), and automated
  HIPAA compliance evidence generated as pgTAP -- and ends with an early-access mailto CTA
  (hello@unitautogen.com). The same roadmap and CTA are mirrored in the README's "Part of the UnitAutogen
  family" section. HTML report and README only; the text report and emitted-suite headers are byte-identical.
- **The shared footer/header tagline is repositioned to match.** The old "part of UnitAutogen -
  automated unit-test generation ... Need it for SQL Server (tSQLt), Oracle, or Azure?" line (text
  report footer, emitted pgTAP suite headers, and CLI output) now reads "part of UnitAutogen - the
  next-generation database security-coverage and code-coverage tool for functions and triggers." plus
  the project link; the cross-DB CTA is dropped.
- **The flat `request.jwt.claim.<key>` auth.uid() shape now binds (MB-23, follow-on to the loud
  unbound-identity fix).** When a schema's `auth.uid()`/`auth.jwt()` reads the older flat per-claim
  GUC (`request.jwt.claim.sub`, as some GoTrue and hand-rolled setups do) rather than the
  `request.jwt.claims` JSON, the identity emitters now also drive those flat GUCs, so a correct owner
  policy is tested green instead of flagged UNRELIABLE. Detected from the function bodies
  (`claim_style`), gated so JSON-shape schemas emit nothing new and stay byte-identical. A custom
  session GUC the tool cannot know (e.g. `current_setting('app.*')`) still stays UNRELIABLE by design.
  New isolated fixture `examples/flatclaim.sql`; `examples/authshape.sql` switched to the custom-GUC
  shape so it keeps exercising the loud-UNRELIABLE path.
- **RESTRICTIVE policies are now conjoined into rescued (solver) branches (MB-6).** When one permissive
  branch is classified and another is not, the obligation router hands the unclassified branch to the
  general solver. It previously received only the permissive predicate, so if a RESTRICTIVE policy
  also applied, the witness it built could violate that restrictive check; the real policy (which
  includes it) then denied the "authorized" row and the branch fell to PARTIALLY TESTED (sound, but a
  lost cell). The router now conjoins the restrictive predicate(s) into the routed obligation, so the
  solver seeds them too and the branch is DB-confirmed. A restrictive conjunct that delegates to an
  opaque function is expanded as witness hints; one that cannot be expanded is dropped from the
  obligation (still sound -- the probe runs the real restrictive function). Schemas with no restrictive
  policy, and fully-classified restrictive cases, emit byte-identical output. New fixture
  `examples/restrictconj.sql`.
- **The member-of-2-tenants differential now catches the SCALAR-subquery shape, on read AND write
  (MB-3).** The two-tenant probe previously ran only on canonical EXISTS membership and only for
  SELECT. It now also recognizes the scalar shape `col = (SELECT scope FROM junction WHERE
  user = auth.uid())` -- issue #4's classic broken pattern -- and probes INSERT/UPDATE/DELETE as well.
  A two-membership identity is seeded and the real command is probed; the moment Postgres raises 21000
  (the scalar subquery returns 2 rows) a FAILING test is baked naming the cause and the fix (use
  EXISTS/IN, or resolve the tenant into a JWT claim). This upgrades the shape from a static lint to a
  live, caught-red test in both directions. Recognition is deliberately tight (the FROM-less
  `= (SELECT auth.uid())` and the `(subquery) = const` role-lookup are excluded) and guarded like the
  canonical path (skip when the table under test reaches the junction, or when the junction enforces
  single membership), so every schema without this exact shape emits byte-identical output. The broken
  scalar table moved out of `examples/multimembership.sql` into a dedicated negative fixture
  `examples/scalarmulti.sql`.
- **Write batteries for the relational-state and recursion DB-oracle floors (MB-4).** Both floors --
  the cardinality/aggregate floor (a policy gated on `count(*) >= N` of another table) and the
  self-referential-hierarchy floor (`WITH RECURSIVE`) -- were SELECT-only, so a `FOR ALL` policy gated
  that way left INSERT/UPDATE/DELETE untested. They now also probe writes: seed a candidate number of
  matching rows (or an ancestor chain), perform the real write, and bake the observed grant/deny pair
  (INSERT gated by `WITH CHECK`, UPDATE/DELETE by `USING`). The DB evaluates the real aggregate, so a
  brand-new gate needs zero per-operator code; recursion INSERT stays a deliberate not-tested (a
  recursive `WITH CHECK` cannot be seeded soundly). The recursion detector is now command-scoped, so a
  `FOR SELECT` recursive policy never drives a write battery. Schemas with no write-command policy of
  these shapes emit byte-identical output. New fixtures `examples/relstatewrite.sql` and
  `examples/recursionwrite.sql`.

### Fixed
- **Suites for a table that is the FK parent of its own membership/scope table no longer abort mid-file.** The per-test re-seed ran a raw `DELETE FROM <table>` before clearing the aux (membership/rbac/lookup) tables that reference it, so on shapes like `tenancy.orgs` (memberships -> orgs) or `mtt.teams` (team_members -> teams) the delete raised a foreign-key violation inside the pgTAP transaction and every remaining test in the file was skipped (`pg_prove`: "planned N but ran M"; present in published 0.6.0). The re-seed now clears the aux tables first and the delete block is fault-tolerant like the header's, so an unrelated FK reference degrades to a loud failing count instead of a mid-file abort; the probe's arrange path got the same ordering so a swallowed q-first delete can no longer leave stale committed rows in the observed counts. Tables with no aux tables emit byte-identical files.
- **The report's "rlsautotest" link points to the project repo, not the org.** The "generated by
  rlsautotest" link in the HTML report header pointed at the UnitAutogen org (github.com/unitautogen)
  rather than the project repository; it now links to github.com/unitautogen/rlsautotest. HTML report
  only; emitted suites and text reports are byte-identical.

## [0.6.0] - 2026-08-05

### Added
- **`--all-schemas`: audit every RLS-bearing schema in the database in one run and, with `--html`, produce a single combined dashboard.** rlsautotest normally targets one schema per run (`--schema`); `--all-schemas` discovers every schema that owns at least one RLS-enabled table (sorted, system schemas excluded) and probes each exactly as a single-schema run does, so an exposed or RLS-off table inside any of those schemas is still caught. With `--html` it stitches the per-schema reports into one interactive page: a schema picker on the left, the selected schema's full report on the right. Each embedded report is byte-identical to that schema's own `--schema <s> --html` output -- the dashboard is a faithful container, never a re-render. The CI exit gate is aggregated across every scanned schema (table names schema-qualified), and `--report` prints each schema's text report under a header. With `--supabase` it binds to the local Supabase database (resolved the same way `--supabase` resolves it) and produces the whole-database dashboard without writing any test files. The mode is read-only orchestration over the existing probe and report; it does not combine with `--table` / `--emit` / `--as-user` / `--report-json`, and needs `--report` and/or `--html`.

## [0.5.0] - 2026-07-30

### Added
- **`--supabase`: a zero-config mode that emits an RLS suite straight into a Supabase project and runs under `supabase test db`.** rlsautotest finds the project by walking up for `supabase/config.toml` (so it runs from any subdirectory), defaults `--schema` to `public`, and resolves the database URL from the Supabase CLI itself (`supabase status -o env`) instead of assuming one -- it takes the host `127.0.0.1` connection string and never the container-internal `db:5432` one, with `--db-url` still overriding and a clear error if the local stack is not running. Tests are written directly into `supabase/tests/rls/` (no copy or rename step) with a `_rlsautotest.sql` suffix so they never collide with hand-written tests, and `supabase test db` discovers the nested folder on its own. Re-running reconciles by default: after a successful write it removes only its own stale `*_rlsautotest.sql` output (a dropped or renamed table, an old run) and never a file without that suffix, so regeneration stays clean and hand-written tests are untouched. Because the mode binds to the local, disposable Supabase database, it suppresses the "point at a disposable copy" probe warning that the general `--db-url` path prints. (Requested in #3.)

## [0.4.0] - 2026-07-28

### Added
- **Column-level security: the report and the emitted suite now flag a column-specific `GRANT` that a broader grant silently bypasses.** When a role holds a column-scoped grant (e.g. `GRANT UPDATE (display_name, bio)`) but *also* reaches columns outside that list through a table-wide or inherited grant, those extra columns stay writable/readable past the scope the developer expressed. This is the column analogue of the cross-policy `WITH CHECK` leak: a restriction stated in one place, defeated by a wider grant that unions back in. A new **column level security** grid in `--report` / `--html` (and `column_security` in `--report-json`) renders each role/command cell as one of: scoped (green, listing the permitted columns), leak (red, naming the columns that slip past the grant), or silent (a bare table-wide grant with no column grant expresses no scope, so nothing is flagged). It makes **no** assumption about which columns are "sensitive" (there is no column-name heuristic) and never flags a bare table-wide grant. The detector compares the developer's column grant (`pg_attribute.attacl`) against effective reach (`has_column_privilege`); leaked columns are effective minus granted.
- **The emitted pgTAP asserts the same fact the report cell is computed from, so the grid and the suite can never disagree.** For every column-scoped cell the suite emits one assertion that zero columns are reachable beyond the column grant (`has_column_privilege` vs the `attacl` grant set), re-derived live against the catalog so a legitimate change to the grant moves both sides together. A scoped cell passes; a leak cell fails and names the leaked columns; a cell with no column grant emits nothing. The change is additive: a table with no column-level grants generates byte-identical pgTAP. Column-level privileges exist for `SELECT` / `INSERT` / `UPDATE` (`DELETE` is whole-row and has none). Like the bypass-surface flags, the report cells are informational and do not change the `--report` exit gate; enforcement lives in the emitted suite.
- **Format-constrained columns are now seedable: a table blocked only by a `CHECK` the generic filler could not satisfy is testable instead of UNRELIABLE.** When a non-policy column carries a single-column format or length `CHECK` (a POSIX regex `~` / `~*`, a `LIKE`, or a `length` / `char_length` bound), the seed planner reads the constraint's parse tree, constructs one conforming value (`code ~ '^[0-9]{10}$'` gets ten digits, `char_length(note) between 5 and 40` gets a five-character string) and uses it for both the seed and the UPDATE probe. The construction is only a candidate: the probe still INSERTs it and observes the real outcome, so a value that did not actually satisfy the `CHECK` simply re-fails and the cell stays UNRELIABLE. This can only turn an UNRELIABLE cell into a real, probe-baked green, never a false pass. Shapes beyond construct-and-verify (a back-reference or look-around regex, a function-delegated or multi-column `CHECK`) are left honestly UNRELIABLE. New `examples/checkfmt.sql` covers the solvable shapes; `examples/seedfail.sql` moved to a back-reference `CHECK` so it stays a negative gate; `examples/updcheck.sql` uses one too, now resolved to a real green by the UPDATE-probe self-assign fallback (below).
- **The UPDATE probe self-assigns the neutral column (`SET col = col`) when no constraint-valid fresh value can be built, so a column carrying a `CHECK` beyond the filler's reach is testable instead of UNRELIABLE.** Proving "identity X can UPDATE its row" runs `UPDATE ... SET <neutral col> = <value>`; when the filler cannot synthesize a value that satisfies that column's `CHECK` (a back-reference or look-around regex, a function-delegated `CHECK`), the fresh-value SET raises `23514` -- the probe's own value failing, not the `42501` policy denial. Instead of conceding UNRELIABLE, the probe retries as a self-assignment of that same column: its current value already satisfies the `CHECK` (it is in the table), so no constraint error can recur, while Postgres still enforces the UPDATE privilege and re-evaluates `USING` / `WITH CHECK` -- exactly what the cell measures. The retry is adopted only when it resolves cleanly, so it can turn an UNRELIABLE cell into a real probe-baked pass or deny, never a false pass: a table whose row cannot be seeded at all (`examples/seedfail.sql`) keeps its unreliable-precondition flag and stays UNRELIABLE. This extends the self-assignment fallback (previously only for tables with no neutral column at all) to neutral columns, in both the identity battery and the custom-role battery. `examples/updcheck.sql` is now a positive fixture exercising the full UPDATE-probe ladder (fresh value, neutral self-assign, policy-column self-assign, explained dash).

## [0.3.1] - 2026-07-27

### Fixed
- **The access-matrix report now flags a cross-policy `WITH CHECK` leak in the grid itself, so it can no longer read greener than its own tests.** When two or more permissive `UPDATE`/`INSERT` policies each pin a narrow `WITH CHECK` value but the role/owner/tenant guard sits only in `USING`, Postgres OR-combines every policy's `WITH CHECK`, letting an authorized identity write a value only a *different* policy intended. The generated pgTAP suite already caught this (a failing `throws_ok` per forbidden value) and the CI gate already exited non-zero, but the report understated it: the offending `authenticated, authorized` cell showed a plain `✓` and the HTML summary counted the table under "enforced as declared / 0 with problems". That cell is now marked as a security hole (`✓!` in text, a red `✓` in HTML) and the table is counted in the report's problem summary. Report-only change; emitted pgTAP is byte-identical.

## [0.3.0] - 2026-07-19

### Added
- **Bypass-surface detection: the objects and roles that sidestep RLS even when every table policy is correct.**
  A new catalog scan (in `rlsautotest lint`, in a **Bypass surfaces** section of `--report` / `--html`, and as
  `bypass_surfaces` in `--report-json`) flags: owner-rights (`SECURITY DEFINER`) views and **materialized views**
  a client can read that reach an RLS-protected table; `SECURITY DEFINER` functions a client can `EXECUTE` that
  reach RLS data or whose body is opaque, plus any with a mutable `search_path` (search-path-injection risk);
  roles with `BYPASSRLS`/superuser that aren't sanctioned platform roles (higher severity when a client can log in
  as or `SET ROLE` into them, `--allow-bypass-role` to allowlist the expected ones); and RLS-enabled tables not
  `FORCE`d whose owner isn't a superuser. Reachability is judged by *effective* privilege
  (`has_table_privilege` / `has_function_privilege`, which include grants to `PUBLIC`), so a function reachable only
  through Postgres's default `PUBLIC` `EXECUTE` grant is surfaced too. These are informational review flags, not
  pass/fail, and do not change the exit gate.

### Changed
- **The internal lint codes (L0xx) are no longer shown in any output.** They were rlsautotest-specific identifiers,
  not a recognized community standard, so they've been removed from `lint` text output, `lint --json`, the HTML
  report, and `--report-json`. Findings are now identified by object, type, severity, and a plain-language reason.

## [0.2.2] - 2026-07-18

### Fixed
- **Quoted / mixed-case (PascalCase) identifiers are now handled correctly.** Tables and columns whose names
  require quoting — e.g. EF Core's `"Accounts"`, `"TenantId"` — were emitted unquoted, so Postgres folded them
  to lowercase and generation either crashed (`has_table_privilege` on a mixed-case table) or produced seed
  `INSERT`s that failed with `undefined column`, marking every cell UNRELIABLE. Every identifier the generator
  emits (table references and INSERT/UPDATE column lists across the catalog scan, seed planner, and all witness
  strategies) is now quoted **conditionally** via a `quote_ident`-style rule: a bare lowercase-simple name is
  left unchanged (so emitted SQL for existing schemas is byte-identical), and anything requiring quoting is
  double-quoted. A GUC-tenancy schema with PascalCase names (`"TenantId" = current_setting('app.tenant', true)`,
  admin override, app role) now generates a fully green, probe-baked pgTAP suite instead of an all-UNRELIABLE one.

## [0.2.1] - 2026-07-18

### Fixed
- **0.2.0 was uninstallable from PyPI.** The built wheel omitted the `rlsautotest.strategies` subpackage
  (introduced by the 0.2.0 modular refactor), so `pip install rlsautotest` followed by any invocation failed
  with `ModuleNotFoundError: No module named 'rlsautotest.strategies'`. Root cause: `pyproject.toml` hardcoded
  `packages = ["rlsautotest"]`, which excluded the subpackage from the wheel. Switched to setuptools package
  auto-discovery (`[tool.setuptools.packages.find]`, `include = ["rlsautotest*"]`) so every subpackage ships.
  0.1.6 was the last working release; **0.2.0 has been yanked**. No behavior change from 0.2.0 otherwise.

### Changed
- **CI now tests the packaged artifact, not just the source tree.** A `package` job builds the wheel and runs
  it (`rlsautotest --help` + `import rlsautotest.strategies`) from a clean venv, and a post-publish
  `release-smoke` workflow installs the released version from PyPI and smoke-tests it. A packaging regression
  now fails the build instead of shipping.

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
