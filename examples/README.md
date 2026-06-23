# Example

`schema.sql` is a self-contained mini Supabase-style schema — a minimal `auth` shim
(so it runs on plain Postgres), the `anon`/`authenticated`/`service_role` roles, and two
RLS tables (`profiles`, owner-scoped; `notes`, owner-scoped FOR ALL).

Try it against any local Postgres with pgTAP available:

```bash
createdb app
psql -d app -c "CREATE EXTENSION IF NOT EXISTS pgtap;"
psql -d app -f examples/schema.sql

# generate the suite
rlsautotest --db-url postgresql:///app --schema public --emit out

# run it
for f in out/tests/database/rls/*.sql; do psql -d app -f "$f"; done

# coverage matrix
rlsautotest --db-url postgresql:///app --schema public --report
```

## The corpus

The other `*.sql` files are the regression corpus — each isolates RLS patterns the generator must
handle. CI loads the green ones and runs their suites to prove there are no false passes:

- **tenancy.sql** — multi-tenant isolation two ways: JWT-claim (`invoices`) and membership (`projects`). Green.
- **rbac.sql** — a table whose every command is gated by an opaque `has_*_permission()` function (no open read); writes are still tested by mocking the function. Green.
- **exotic.sql** — owner + `AS RESTRICTIVE` tenant, array-claim, session-GUC, and a deliberately **broken** self-referential policy. A *negative* example — the gate is meant to FAIL on it (proving detection), so CI does not load it into the green set.
- **transitions.sql** — a role-gated status state machine (cutter → packager → loader → …) whose permissive `UPDATE` policies' `WITH CHECK` clauses OR-combine into a **cross-policy leak**: a role can write a status its own policy forbids (e.g. a cutter jumping a row straight to `Completed`). Another *negative* example — the gate must flag it.

  **What triggers this leak (the pattern to watch for):** ALL of —
  1. **two or more `PERMISSIVE` policies** for the same write command (`UPDATE` or `INSERT`) on one table (permissive is the default; `RESTRICTIVE` policies `AND` instead and don't leak this way);
  2. each policy's **`WITH CHECK` is a narrow, per-policy value constraint** — together they *partition* the allowed new values (one status/value per role/case), each policy intending only its own slice;
  3. the **discriminator** that's supposed to decide *who* may write *what* — role, owner, tenant, current state — is written **in `USING` only and NOT repeated in `WITH CHECK`** (an asymmetry between the two clauses);
  4. the `USING` sets **overlap** enough that a row one identity can target can have its *new* value validated by a *different* policy's `WITH CHECK`.

  Because Postgres OR-combines the `WITH CHECK`s of all applicable permissive policies *independently of which `USING` matched*, the effective check is the **union** of every policy's check, stripped of the per-policy discriminator. So any identity that passes *any* policy's `USING` can write *any* value *any* `WITH CHECK` permits. (A policy that omits `WITH CHECK` reuses its `USING` as the check for `UPDATE`, so if its discriminator is in `USING` it *doesn't* leak — which is why the manager policy in `order_items` is clean.) **Fix:** put the discriminator inside each `WITH CHECK` too, or enforce the transition in a `BEFORE` trigger / `SECURITY DEFINER` function, or use `AS RESTRICTIVE`. rlsautotest detects it automatically — it enumerates the constrained column's value domain, probes each forbidden value per identity, and bakes a failing assertion for every value that's wrongly accepted.
- **clearance.sql** — numeric clearance-level read access (`(auth.jwt() ->> 'clearance')::int >= sensitivity`). No named shape matches this threshold predicate, so the **general witness solver** derives a high-clearance reader (sees the row) and a low-clearance reader (sees nothing) and DB-verifies both. Green — proves the solver tests a predicate the catalog can't classify.
- **adversarial.sql** — policies the named-shape classifier does NOT recognize, OR'd with a branch it does: `owner OR deleted_at IS NULL` and `owner OR status <> 'deleted'`. The classifier drops the novel branch, but the **per-min-term solver** derives a witness, DB-verifies it, and bakes a `[solver]` grant/deny — so the novel branch isn't silently lost. A third table (`email ~ '@…$'`) is a pattern-match the solver can't yet construct, so it stays a clear `–` and `--debug-unhandled` lists it. Green — proves a novel branch beside a classifiable one is no longer dropped.
- **seedfail.sql** — a deliberately UN-SEEDABLE table (`code` must be exactly ten digits — a format `CHECK` the generic filler can't satisfy). A *negative* example: the probe still runs (arrange → act → observe), but because the precondition can't be established the engine marks those cells **‼ UNRELIABLE** — a loud, failing test that shows what it observed — and FAILS the gate, instead of printing "– not tested" or baking the seed error as a policy denial. The regression guard for "a seeding failure can never masquerade as a policy result."
- **updcheck.sql** — the UPDATE probe's correctness guards. To prove an UPDATE *grant*, the probe does `UPDATE … SET <col>=<value>`, which only measures the grant if the column is **policy-neutral** and the value is **constraint-valid**. `t1` (a value-set `CHECK`) is SET to a valid value and tested; `t2` (a `CHECK` the generic filler can't satisfy) raises `23514` — a constraint error, **not** the RLS denial `42501` — so it's flagged **‼ UNRELIABLE** instead of a false "denied"; `t3` (no neutral column) gets an **explained `–`**. A *negative* example — the gate must flag `t2`.
- **synth.sql** — the hardest *seeding* shape: an opaque `SECURITY DEFINER`-gated policy (so only wiring can be proven, by mocking it) on a table that ALSO has a **composite foreign key** and a **`CHECK` that delegates to a UDF**. To get a row to act on, the **probe-and-repair synthesizer** reacts to the real `INSERT` errors — seeding the composite-FK parent tuple and neutralizing the CHECK function for the insert — none of it hand-coded per shape. Green — the regression guard for the synthesizer.
