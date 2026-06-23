# Changelog

All notable changes to **rlsautotest** are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/); this project is pre-1.0 and versions
roughly follow semantic versioning.

## [0.1.5] — 2026-06-24

### Fixed
- **CI integration workflow.** The negative-gate test steps (`seedfail`, `updcheck`) piped the gate's
  output through `tee`, so the pipeline reported `tee`'s exit code (always 0) and masked the tool's real
  non-zero gate exit — turning a correctly-failing gate into a red "did NOT fail the gate" step. They now
  capture the exit code via redirect instead of a pipe. No change to the tool itself; `0.1.4`'s behaviour
  was correct (the gate did exit non-zero) — only the workflow's exit-code check was wrong.

## [0.1.4] — 2026-06-23

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

### Changed
- Removed all "read-only" / "safe to run on production" claims. The tool seeds rows and runs
  `SELECT/INSERT/UPDATE/DELETE` while probing (each rolled back), so the docs and a startup banner now
  direct you to point it at a **disposable copy** of your database, never production.

## [0.1.2] — 2026-06-22

- Initial public release: deterministic pgTAP test **and seed-data** generation for Postgres / Supabase
  Row-Level Security, a per-identity access-matrix report (`--report` / `--html`), static `lint`,
  policy `snapshot`/`diff`, and a CI gate that fails on an exposed or unprotected table.
