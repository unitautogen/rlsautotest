-- examples/sessionident.sql
-- Owner checks whose identity is NOT a JWT claim: a session GUC and the login (session) role.
--   sid.docs     : tenant = current_setting('app.tenant', true)  -> the probe drives the REAL GUC
--                  (authorized tenant vs a different, set tenant), never a mock.
--   sid.rolemine : ownr = SESSION_USER                            -> the probe acts as two real roles via
--                  SET SESSION AUTHORIZATION (needs a superuser connection), then SET ROLE authenticated.
-- Both were NOT TESTABLE ("unhandled atom: eq") before; both must now be 8/8 and stay green, and CI
-- loosens both policies to USING (true) and requires the same emitted suite to go red.

-- Two session users. NOINHERIT: they act only through SET ROLE authenticated, so they never show up as
-- inherited client roles in other schemas. The direct USAGE grant below makes them the preferred session
-- users for this schema (roles are cluster-wide; discovery prefers roles granted on the schema under test).
DO $$ BEGIN CREATE ROLE sid_alice NOLOGIN NOINHERIT; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE sid_bob   NOLOGIN NOINHERIT; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
GRANT authenticated TO sid_alice, sid_bob;

DROP SCHEMA IF EXISTS sid CASCADE;
CREATE SCHEMA sid;
GRANT USAGE ON SCHEMA sid TO anon, authenticated, service_role, sid_alice, sid_bob;

-- 1) tenant from a session GUC
CREATE TABLE sid.docs (
  id     int primary key,
  tenant text not null,
  body   text not null
);
ALTER TABLE sid.docs ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON sid.docs TO authenticated, service_role;
GRANT SELECT ON sid.docs TO anon;
CREATE POLICY tenant_iso ON sid.docs FOR ALL USING (tenant = current_setting('app.tenant', true));

-- 2) owner is the login (session) role
CREATE TABLE sid.rolemine (
  id   int primary key,
  ownr name not null,
  body text not null
);
ALTER TABLE sid.rolemine ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON sid.rolemine TO authenticated, service_role;
GRANT SELECT ON sid.rolemine TO anon;
CREATE POLICY own_rows ON sid.rolemine FOR ALL USING (ownr = SESSION_USER);
