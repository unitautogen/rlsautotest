-- examples/customrole.sql
-- F5 (custom-role policies stop vanishing): policies granted TO a role beyond the client trio
-- (PUBLIC / authenticated / anon) were previously excluded from the DNF and left the command
-- looking policy-less — a silent drop. The custom_role strategy now probes each such role via a
-- real SET ROLE, bakes the observed grant/deny, and the report grows a per-role row.

DO $$ BEGIN CREATE ROLE reporter NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DROP SCHEMA IF EXISTS crole CASCADE;
CREATE SCHEMA crole;
GRANT USAGE ON SCHEMA crole TO anon, authenticated, service_role, reporter;

-- 1) a table whose ONLY policy audience is the custom role (reads everything; clients get nothing)
CREATE TABLE crole.metrics (
  id    bigint generated always as identity primary key,
  name  text not null,
  value numeric
);
ALTER TABLE crole.metrics ENABLE ROW LEVEL SECURITY;
GRANT SELECT ON crole.metrics TO reporter;
GRANT SELECT, INSERT, UPDATE, DELETE ON crole.metrics TO authenticated, service_role;
CREATE POLICY metrics_reporter ON crole.metrics FOR SELECT TO reporter USING (true);

-- 2) a mixed table: owner-scoped for authenticated PLUS a read-everything policy for the role
CREATE TABLE crole.incidents (
  id     bigint generated always as identity primary key,
  owner  uuid not null,
  note   text
);
ALTER TABLE crole.incidents ENABLE ROW LEVEL SECURITY;
GRANT SELECT ON crole.incidents TO reporter;
GRANT SELECT, INSERT, UPDATE, DELETE ON crole.incidents TO authenticated, service_role;
CREATE POLICY incidents_owner ON crole.incidents FOR ALL TO authenticated
  USING (owner = (SELECT auth.uid())) WITH CHECK (owner = (SELECT auth.uid()));
CREATE POLICY incidents_reporter ON crole.incidents FOR SELECT TO reporter USING (true);
