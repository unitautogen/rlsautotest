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
