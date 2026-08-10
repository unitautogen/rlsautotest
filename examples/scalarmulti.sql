-- SCALAR-SUBQUERY MULTI-TENANT HAZARD (schema scm) -- NEGATIVE fixture (MB-3).
-- The member-of-2-tenants differential now runs on the SCALAR-subquery membership shape (not just the
-- canonical EXISTS shape) and on WRITE commands, so the DB OBSERVES the 21000 error live instead of
-- relying only on the static lint. This is issue #4's classic broken pattern.
--   scm.notes  SELECT USING  (team_id = (SELECT team_id FROM scm.memberships WHERE user_id = auth.uid()))
--              INSERT CHECK   (same)
--              -> works while every user has ONE membership; the moment a user joins a SECOND team the
--                 scalar subquery returns 2 rows and EVERY read AND every insert raises 21000. The
--                 differential seeds a two-membership identity and bakes a FAILING member-of-2-tenants
--                 test in BOTH directions (gate red). Fix: EXISTS/IN, or a single-tenant JWT claim.
--   scm.memberships  the junction (PRIMARY KEY (team_id, user_id) -> user_id NOT unique, so the
--                    two-membership state can exist; a single-membership junction would be skipped).
-- Requires the auth shim + roles from examples/schema.sql.

DROP SCHEMA IF EXISTS scm CASCADE;
CREATE SCHEMA scm;
GRANT USAGE ON SCHEMA scm TO anon, authenticated, service_role;

CREATE TABLE scm.teams (
  id   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL
);

CREATE TABLE scm.memberships (
  team_id uuid NOT NULL REFERENCES scm.teams(id),
  user_id uuid NOT NULL REFERENCES auth.users(id),
  PRIMARY KEY (team_id, user_id)
);

CREATE TABLE scm.notes (
  id      bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  team_id uuid NOT NULL REFERENCES scm.teams(id),
  body    text NOT NULL
);

ALTER TABLE scm.teams       ENABLE ROW LEVEL SECURITY;
ALTER TABLE scm.memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE scm.notes       ENABLE ROW LEVEL SECURITY;

-- the broken scalar shape, on BOTH read and write
CREATE POLICY notes_sel ON scm.notes FOR SELECT TO authenticated
  USING (team_id = (SELECT team_id FROM scm.memberships WHERE user_id = auth.uid()));
CREATE POLICY notes_ins ON scm.notes FOR INSERT TO authenticated
  WITH CHECK (team_id = (SELECT team_id FROM scm.memberships WHERE user_id = auth.uid()));

-- users see their own membership rows (junction table itself -> the differential skips it)
CREATE POLICY m_sel ON scm.memberships FOR SELECT TO authenticated
  USING (user_id = auth.uid());

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA scm TO authenticated, service_role;
