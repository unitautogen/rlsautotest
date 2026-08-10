-- JOIN-SUBQUERY fixture (schema jsq): a membership-through-a-JOIN policy (MB-2). The canonical
-- single-table membership grammar can't model it, and before MB-2 the whole subquery fell to NT.
-- Now the general witness seeds BOTH joined tables (the equijoin key shared between them) and
-- DB-verifies the grant/deny pair.
--   jsq.docs  SELECT visible when the caller has an 'admin' membership in the doc's org:
--             EXISTS (SELECT 1 FROM memberships m JOIN roles r ON r.id = m.role_id
--                     WHERE m.user_id = auth.uid() AND m.org_id = docs.org_id AND r.name = 'admin')
--             anchor = m (auth.uid + org correlation), joined = roles (role-name filter, r.id = m.role_id).
-- Requires the auth shim + roles from examples/schema.sql.

DROP SCHEMA IF EXISTS jsq CASCADE;
CREATE SCHEMA jsq;
GRANT USAGE ON SCHEMA jsq TO anon, authenticated, service_role;

CREATE TABLE jsq.roles (
  id   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL
);

CREATE TABLE jsq.memberships (
  id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id),
  org_id  uuid NOT NULL,
  role_id uuid NOT NULL REFERENCES jsq.roles(id)
);

CREATE TABLE jsq.docs (
  id     bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  org_id uuid NOT NULL,
  title  text NOT NULL
);

ALTER TABLE jsq.roles       ENABLE ROW LEVEL SECURITY;
ALTER TABLE jsq.memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE jsq.docs        ENABLE ROW LEVEL SECURITY;

-- the MB-2 target: membership-through-a-join with a role-name filter on the joined table
CREATE POLICY docs_select ON jsq.docs FOR SELECT TO authenticated
  USING (EXISTS (SELECT 1 FROM jsq.memberships m JOIN jsq.roles r ON r.id = m.role_id
                 WHERE m.user_id = auth.uid() AND m.org_id = docs.org_id AND r.name = 'admin'));

-- support tables readable by their own user / all members (kept simple + green)
CREATE POLICY m_select ON jsq.memberships FOR SELECT TO authenticated
  USING (user_id = auth.uid());
CREATE POLICY r_select ON jsq.roles FOR SELECT TO authenticated
  USING (true);

GRANT SELECT ON ALL TABLES IN SCHEMA jsq TO authenticated, service_role;
