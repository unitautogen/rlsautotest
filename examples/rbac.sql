-- Example / regression: a table whose EVERY command (including SELECT) is gated by an opaque
-- RBAC function — so there is no open read and therefore no base row to seed. This is the shape
-- a real user surfaced (an `rbac.has_team_permission(team_id, '<perm>')`-gated `creditors` table):
-- rlsautotest must still generate INSERT/UPDATE/DELETE tests by MOCKING the function and
-- SYNTHESIZING a valid row (FK parents + required columns), not just the SELECT test.
--
-- Contrast with examples/exotic.sql `posts`, which has `FOR SELECT USING (true)` — an open read
-- gives a base row for free, so the write-mock path worked there and this gap stayed hidden.

DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='anon')          THEN CREATE ROLE anon NOLOGIN; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='authenticated') THEN CREATE ROLE authenticated NOLOGIN; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='service_role')  THEN CREATE ROLE service_role NOLOGIN BYPASSRLS; END IF;
END $$;

CREATE SCHEMA IF NOT EXISTS rbac;
GRANT USAGE ON SCHEMA rbac TO anon, authenticated, service_role;

-- An opaque RBAC check. Its body is irrelevant to rlsautotest — the generator MOCKS it to prove
-- the policy WIRES to it (true -> allowed, false -> denied). First arg is a COLUMN (team_id),
-- exactly like real has_*_permission(...) helpers (so the value can't be supplied as input).
CREATE OR REPLACE FUNCTION rbac.has_team_permission(p_team uuid, p_perm text)
  RETURNS boolean LANGUAGE sql STABLE AS $$ SELECT false $$;

CREATE TABLE IF NOT EXISTS rbac.teams (
  id   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL
);

CREATE TABLE IF NOT EXISTS rbac.creditors (
  id      bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  team_id uuid NOT NULL REFERENCES rbac.teams(id),
  name    text NOT NULL,
  amount  numeric(12,2)
);
ALTER TABLE rbac.creditors ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON rbac.creditors TO authenticated, service_role;

CREATE POLICY creditors_select ON rbac.creditors FOR SELECT
  USING (rbac.has_team_permission(team_id, 'creditor.read'));
CREATE POLICY creditors_insert ON rbac.creditors FOR INSERT
  WITH CHECK (rbac.has_team_permission(team_id, 'creditor.create'));
CREATE POLICY creditors_update ON rbac.creditors FOR UPDATE
  USING (rbac.has_team_permission(team_id, 'creditor.update'));
CREATE POLICY creditors_delete ON rbac.creditors FOR DELETE
  USING (rbac.has_team_permission(team_id, 'creditor.delete'));
