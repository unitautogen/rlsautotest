-- RELATIONAL-STATE WRITE floor (schema rsw): MB-4. The cardinality/aggregate floor previously ran
-- for SELECT only; a FOR ALL policy gated on the STATE of another table left INSERT/UPDATE/DELETE as
-- untested dashes. Now the write-direction floor seeds a CANDIDATE NUMBER of matching rows, performs
-- the real write, and bakes the observed grant/deny pair (the cardinality that lets the write land is
-- the witness; one that blocks it is the falsifier). Zero per-operator code -- Postgres evaluates the
-- real aggregate.
--   rsw.gated   FOR ALL, permitted only if the caller owns >= 2 rsw.tickets:
--                 SELECT -> the existing relational-state floor (unchanged)
--                 INSERT -> WITH CHECK gate: 2 tickets -> insert lands; 0 -> 42501 denial
--                 UPDATE/DELETE -> USING gate: 2 tickets -> affects the row; 0 -> affects nothing
--   rsw.tickets own-row scope table (keeps the count caller-scoped; idiomatic)
-- Requires the auth shim + roles from examples/schema.sql.

DROP SCHEMA IF EXISTS rsw CASCADE;
CREATE SCHEMA rsw;
GRANT USAGE ON SCHEMA rsw TO anon, authenticated, service_role;

CREATE TABLE rsw.tickets (
  id    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner uuid NOT NULL
);

CREATE TABLE rsw.gated (
  id    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  label text NOT NULL DEFAULT 'x'
);

ALTER TABLE rsw.tickets ENABLE ROW LEVEL SECURITY;
ALTER TABLE rsw.gated   ENABLE ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON rsw.tickets TO authenticated, service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON rsw.gated   TO authenticated, service_role;

-- the cardinality gate on EVERY command (FOR ALL): act on gated rows only if you own >= 2 tickets
CREATE POLICY gated_all ON rsw.gated
  FOR ALL TO authenticated
  USING      ( (SELECT count(*) FROM rsw.tickets t WHERE t.owner = (SELECT auth.uid())) >= 2 )
  WITH CHECK ( (SELECT count(*) FROM rsw.tickets t WHERE t.owner = (SELECT auth.uid())) >= 2 );

-- own-row policy on the scope table (idiomatic; keeps the count caller-scoped)
CREATE POLICY own_tickets ON rsw.tickets
  FOR ALL TO authenticated
  USING      ( owner = (SELECT auth.uid()) )
  WITH CHECK ( owner = (SELECT auth.uid()) );
