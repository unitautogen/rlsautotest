# test-schemas

Real-world RLS schemas shared for testing rlsautotest (reproduced faithfully under their own schema
namespace so they don't touch `public`). They reference Supabase's `auth.users` / `auth.uid()` /
`auth.jwt()`, so apply them to a Supabase-like database. Each starts with `drop schema if exists … cascade`,
so applying is a clean reinstall:

```
psql "$DATABASE_URL" -f test-schemas/<file>.sql
```

| File | Schema | What it exercises |
|---|---|---|
| `order_items_bug.sql` | `orderbug` | The Discord report: five role-gated `UPDATE` policies whose `WITH CHECK` clauses OR-combine, so a role can write a status its own policy forbids (e.g. a cutter → `Completed`). The cross-policy WITH CHECK leak. A clean minimal version also lives in `examples/transitions.sql`. |
| `acl.sql` | `acl` | A `SECURITY DEFINER` RBAC function (`check_user_project_access`) over org/project membership, gating `documents` SELECT/UPDATE/INSERT. Opaque-function wiring (mock) path. |
| `vault.sql` | `vault` | Data-rooms: a `UNION ALL` share-or-owner validation function plus a second owner-only `FOR ALL` policy on `room_documents`. The scope table (`data_rooms`) is also an FK parent — the seeding-order case. |
| `multifk.sql` | `multifk` | A table with three FK parents, one of which is the membership/scope table — the parent-scope seeding-collision case. |

These are kept for reference/regression. They are NOT wired into CI (the curated public corpus is in
`examples/`); treat this folder as a private working set and gitignore it if you don't want it published.
