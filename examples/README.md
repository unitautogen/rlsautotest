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
