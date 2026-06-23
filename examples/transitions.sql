-- Role-gated status state machine with a CROSS-POLICY `WITH CHECK` LEAK — a real pattern
-- surfaced by a Supabase user. Several PERMISSIVE UPDATE policies each let one role advance a
-- row to the next status (the role is read from a `profile` lookup table). Each policy's own
-- WITH CHECK pins the *target* status, e.g. a cutter may only set 'In Cutting'.
--
-- The bug: Postgres OR-combines the WITH CHECK of every permissive policy INDEPENDENTLY of which
-- policy's USING matched, and the role guard lives ONLY in USING. So the combined check any
-- authenticated user faces is { 'In Cutting','In Packaging','In Loading','Completed' } — and a
-- cutter can jump a row straight to 'Completed', bypassing the state machine its own policy implies.
--
-- rlsautotest must (1) derive the per-role identities from the `= ANY(array[...])` status guard and
-- the `(select role from profile where id = auth.uid())` lookup, and (2) prove, per role, that no
-- forbidden target status is writable — flagging every value the combined WITH CHECK accepts but the
-- role's own policy forbids. This file is the regression for both. It is a DELIBERATE leak: the gate
-- is meant to FAIL on it (like examples/exotic.sql), not pass.
--
-- Requires the auth shim + roles from examples/schema.sql (or the supabase_ext test DB):
-- auth.uid()/auth.users + the anon/authenticated/service_role roles.

DROP SCHEMA IF EXISTS transitions CASCADE;
CREATE SCHEMA transitions;
GRANT USAGE ON SCHEMA transitions TO anon, authenticated, service_role;

CREATE TYPE transitions.status_item_type AS ENUM ('Queued','In Cutting','In Packaging','In Loading','Completed');
CREATE TYPE transitions.role_type        AS ENUM ('cutter','packager','loader','manager');

-- the caller's role, read by the policies via a correlated scalar subquery (the common Supabase shape)
CREATE TABLE transitions.profile (
  id   uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  role transitions.role_type NOT NULL
);
GRANT SELECT ON transitions.profile TO authenticated, service_role;
ALTER TABLE transitions.profile ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Read own profile." ON transitions.profile
  FOR SELECT TO authenticated USING (id = (SELECT auth.uid()));

-- note: a NO-DEFAULT uuid PK (the work items carry externally-assigned ids) — also a seeding regression
CREATE TABLE transitions.work_items (
  id     uuid PRIMARY KEY,
  title  text,
  status transitions.status_item_type DEFAULT 'Queued'
);
ALTER TABLE transitions.work_items ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON transitions.work_items TO authenticated, service_role;

-- any logged-in staff member can see the queue (so an UPDATE can find its rows)
CREATE POLICY "Staff can read work items." ON transitions.work_items
  FOR SELECT TO authenticated USING (true);

-- ===== the role-gated UPDATE policies (the leak lives in how their WITH CHECK clauses OR-combine) =====
CREATE POLICY "Cutter can update status." ON transitions.work_items FOR UPDATE TO authenticated USING (
  status = ANY (ARRAY['Queued'::transitions.status_item_type, 'In Cutting'::transitions.status_item_type])
  AND (SELECT role FROM transitions.profile WHERE id = (SELECT auth.uid())) = 'cutter'::transitions.role_type
) WITH CHECK (status = 'In Cutting'::transitions.status_item_type);

CREATE POLICY "Packager can update status." ON transitions.work_items FOR UPDATE TO authenticated USING (
  status = ANY (ARRAY['In Cutting'::transitions.status_item_type, 'In Packaging'::transitions.status_item_type])
  AND (SELECT role FROM transitions.profile WHERE id = (SELECT auth.uid())) = 'packager'::transitions.role_type
) WITH CHECK (status = 'In Packaging'::transitions.status_item_type);

CREATE POLICY "Loader can update status." ON transitions.work_items FOR UPDATE TO authenticated USING (
  status = ANY (ARRAY['In Packaging'::transitions.status_item_type, 'In Loading'::transitions.status_item_type])
  AND (SELECT role FROM transitions.profile WHERE id = (SELECT auth.uid())) = 'loader'::transitions.role_type
) WITH CHECK (status = 'In Loading'::transitions.status_item_type);

CREATE POLICY "Loader can complete." ON transitions.work_items FOR UPDATE TO authenticated USING (
  status = ANY (ARRAY['In Loading'::transitions.status_item_type, 'Completed'::transitions.status_item_type])
  AND (SELECT role FROM transitions.profile WHERE id = (SELECT auth.uid())) = 'loader'::transitions.role_type
) WITH CHECK (status = 'Completed'::transitions.status_item_type);

-- manager: a USING-only policy (no explicit WITH CHECK -> defaults to USING)
CREATE POLICY "Manager can update." ON transitions.work_items FOR UPDATE TO authenticated USING (
  status <> ALL (ARRAY['In Cutting','In Packaging','In Loading','Completed']::transitions.status_item_type[])
  AND (SELECT role FROM transitions.profile WHERE id = (SELECT auth.uid())) = 'manager'::transitions.role_type
);
