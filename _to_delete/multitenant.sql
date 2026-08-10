-- Multi-tenant membership fixture (issue #4): the TWO-membership user scenario.
-- A membership-join policy (EXISTS over team_members) is exercised by every single-membership test
-- user, but a policy bug that only manifests when ONE user belongs to TWO teams stays invisible.
-- rlsautotest seeds a two-membership identity ("authenticated, multi-tenant") plus one row in each
-- of its teams, probes what it ACTUALLY sees, and pins the union cardinality:
--   mtt.docs         canonical EXISTS membership -> the multi-tenant row is probed and stays green;
--                    the emitted suite pins "sees rows from BOTH memberships" (drift guard, see ci.yml)
--   mtt.team_members the membership table ITSELF -> the probe must SKIP it (self-pollution guard:
--                    seeding the two memberships would insert rows INTO the measured table)
--   mtt.teams        FK-parent of the membership table -> also skipped (same guard, transitively)
--   mtt.notes_scalar the HAZARD shape `team_id = (SELECT team_id FROM team_members WHERE user_id =
--                    auth.uid())` -> green under single-membership data, ERRORS (21000) the moment a
--                    real user joins a second team; `rlsautotest lint` flags it HIGH
-- Requires the auth shim + roles from examples/schema.sql.

DROP SCHEMA IF EXISTS mtt CASCADE;
CREATE SCHEMA mtt;
GRANT USAGE ON SCHEMA mtt TO anon, authenticated, service_role;

CREATE TABLE mtt.teams (
  id   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL
);

CREATE TABLE mtt.team_members (
  team_id uuid NOT NULL REFERENCES mtt.teams(id),
  user_id uuid NOT NULL REFERENCES auth.users(id),
  PRIMARY KEY (team_id, user_id)
);

CREATE TABLE mtt.docs (
  id      bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  team_id uuid NOT NULL REFERENCES mtt.teams(id),
  title   text NOT NULL
);

CREATE TABLE mtt.notes_scalar (
  id      bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  team_id uuid NOT NULL REFERENCES mtt.teams(id),
  body    text NOT NULL
);

ALTER TABLE mtt.teams        ENABLE ROW LEVEL SECURITY;
ALTER TABLE mtt.team_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE mtt.docs         ENABLE ROW LEVEL SECURITY;
ALTER TABLE mtt.notes_scalar ENABLE ROW LEVEL SECURITY;

-- canonical EXISTS membership: correct for ANY number of memberships (union semantics)
CREATE POLICY docs_select ON mtt.docs FOR SELECT TO authenticated
  USING (EXISTS (SELECT 1 FROM mtt.team_members m WHERE m.team_id = docs.team_id AND m.user_id = auth.uid()));
CREATE POLICY docs_insert ON mtt.docs FOR INSERT TO authenticated
  WITH CHECK (EXISTS (SELECT 1 FROM mtt.team_members m WHERE m.team_id = docs.team_id AND m.user_id = auth.uid()));

-- users see their own membership rows (the table under test IS the membership table -> multi probe skips)
CREATE POLICY tm_select ON mtt.team_members FOR SELECT TO authenticated
  USING (user_id = auth.uid());

-- teams visible to their members (teams is an FK-ANCESTOR of team_members -> multi probe skips)
CREATE POLICY teams_select ON mtt.teams FOR SELECT TO authenticated
  USING (EXISTS (SELECT 1 FROM mtt.team_members m WHERE m.team_id = teams.id AND m.user_id = auth.uid()));

-- issue #4's broken shape: a scalar subquery works ONLY while every user has a single membership
CREATE POLICY ns_select ON mtt.notes_scalar FOR SELECT TO authenticated
  USING (team_id = (SELECT team_id FROM mtt.team_members WHERE user_id = auth.uid()));

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA mtt TO authenticated, service_role;
