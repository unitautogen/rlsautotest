-- MB-2b: a 3-table INNER-join membership CHAIN. docs are visible to a user who holds a membership in the
-- doc's org whose role is of type 'admin'. The subquery chains memberships -> roles -> role_types, so the
-- deepest table (role_types, carrying the 'admin' filter) connects to roles, NOT to the anchor membership.
-- Anchor = memberships (auth.uid() + correlation on docs.org_id). Requires the auth shim from schema.sql.
DROP SCHEMA IF EXISTS jsq3 CASCADE;
CREATE SCHEMA jsq3;
GRANT USAGE ON SCHEMA jsq3 TO anon, authenticated, service_role;
CREATE TABLE jsq3.role_types (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL);
CREATE TABLE jsq3.roles (
  id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  type_id uuid NOT NULL REFERENCES jsq3.role_types(id)
);
CREATE TABLE jsq3.memberships (
  user_id uuid NOT NULL REFERENCES auth.users(id),
  org_id  uuid NOT NULL,
  role_id uuid NOT NULL REFERENCES jsq3.roles(id),
  PRIMARY KEY (user_id, org_id)
);
CREATE TABLE jsq3.docs (
  id     bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  org_id uuid NOT NULL,
  title  text NOT NULL
);
ALTER TABLE jsq3.role_types  ENABLE ROW LEVEL SECURITY;
ALTER TABLE jsq3.roles       ENABLE ROW LEVEL SECURITY;
ALTER TABLE jsq3.memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE jsq3.docs        ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON jsq3.docs FOR SELECT TO authenticated USING (
  EXISTS (SELECT 1 FROM jsq3.memberships m
            JOIN jsq3.roles r      ON r.id = m.role_id
            JOIN jsq3.role_types t ON t.id = r.type_id
          WHERE m.user_id = auth.uid() AND m.org_id = docs.org_id AND t.name = 'admin')
);
CREATE POLICY mem_self ON jsq3.memberships FOR SELECT TO authenticated USING (user_id = auth.uid());
-- lookup tables readable by authenticated (else the docs subquery can never resolve them -> the policy
-- would be broken at runtime). This is the realistic shape: role/role-type reference data is world-readable.
CREATE POLICY roles_sel      ON jsq3.roles      FOR SELECT TO authenticated USING (true);
CREATE POLICY role_types_sel ON jsq3.role_types FOR SELECT TO authenticated USING (true);
GRANT SELECT ON ALL TABLES IN SCHEMA jsq3 TO authenticated, service_role;
