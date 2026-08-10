-- ROLE-AUDIENCE fixture (schema pto): every way Postgres names a policy audience that literal
-- role-name matching gets wrong (RA-1..RA-5, RA-8). A GENERIC provider: NO Supabase role names,
-- LOGIN client roles, and the no-`TO` PUBLIC shape from the issue-#4 commenter's report:
--   pto.settings  ONE policy, no TO clause, USING (true)  -> polroles = {0} (PUBLIC pseudo-role,
--                 no pg_roles row): discovery must still see that a policy applies to every role,
--                 L001 must report CRITICAL (PUBLIC includes anon), and L017 must fire because a
--                 role-scoped policy exists elsewhere in the schema (name-vs-audience divergence).
--   pto.notes     user-scoped policy TO pto_member (the role-scoped sibling), plus a policy
--                 TO pto_editors -- a NOLOGIN GROUP role: pto_member inherits it, so the policy
--                 applies to pto_member through the role graph (RA-5), not by literal OID match.
-- Roles (cluster-level, created idempotently): pto_member + pto_visitor are LOGIN client roles
-- (RA-1's admit-LOGIN-via-PUBLIC path); pto_editors is a NOLOGIN group granted to pto_member.
-- Requires the auth shim from examples/schema.sql.

DO $$ BEGIN CREATE ROLE pto_member LOGIN;  EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE pto_visitor LOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE pto_editors NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
GRANT pto_editors TO pto_member;

DROP SCHEMA IF EXISTS pto CASCADE;
CREATE SCHEMA pto;
GRANT USAGE ON SCHEMA pto TO pto_member, pto_visitor;

CREATE TABLE pto.settings (
  id    bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  key   text NOT NULL,
  value text NOT NULL
);

CREATE TABLE pto.notes (
  id      bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES auth.users(id),
  body    text NOT NULL
);

ALTER TABLE pto.settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE pto.notes    ENABLE ROW LEVEL SECURITY;

-- the reporter's shape: the NAME promises a role, the missing TO delivers EVERYONE (PUBLIC)
CREATE POLICY "Service role full access" ON pto.settings FOR SELECT
  USING (true);

-- role-scoped siblings (what makes L017's divergence real)
CREATE POLICY notes_own ON pto.notes FOR SELECT TO pto_member
  USING (user_id = auth.uid());
CREATE POLICY notes_editors ON pto.notes FOR SELECT TO pto_editors   -- reaches pto_member via inheritance (RA-5)
  USING (user_id = auth.uid());

GRANT SELECT ON pto.settings TO pto_member, pto_visitor;
GRANT SELECT ON pto.notes    TO pto_member;
