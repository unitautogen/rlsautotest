-- RESTRICTIVE-CONJUNCT fixture (schema rcj): the MB-6 target. A permissive policy with TWO OR
-- branches -- one the classifier NAMES (owner = auth.uid()), one it cannot name but the general
-- solver CAN witness (priority > 5, a bare inequality) -- PLUS a RESTRICTIVE tenant policy.
-- Postgres AND's the restrictive policy onto whichever permissive branch grants.
--
-- Before MB-6 the obligation router handed the solver only the PERMISSIVE branch (`priority > 5`);
-- the witness it built left tenant_id / the JWT claim unset, so the REAL policy (which includes the
-- restrictive tenant check) denied the "authorized" row and the branch fell to PARTIALLY TESTED --
-- sound, but a lost cell. MB-6 conjoins the restrictive predicate into the routed obligation, so the
-- solver seeds tenant_id AND the matching claim too, and the branch is DB-confirmed green [solver].
--
--   rcj.tickets  SELECT: (owner = auth.uid() OR priority > 5)  [permissive]
--                    AND (tenant_id = (auth.jwt() ->> 'tid')::uuid)  [RESTRICTIVE]
--                The owner branch is classified (identity battery). The priority branch is routed;
--                MB-6 makes it green instead of "partially tested".
-- Requires the auth shim + roles from examples/schema.sql.

DROP SCHEMA IF EXISTS rcj CASCADE;
CREATE SCHEMA rcj;
GRANT USAGE ON SCHEMA rcj TO anon, authenticated, service_role;

CREATE TABLE rcj.tickets (
  id        bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  owner     uuid NOT NULL REFERENCES auth.users(id),
  tenant_id uuid NOT NULL,
  priority  int  NOT NULL,
  body      text
);

ALTER TABLE rcj.tickets ENABLE ROW LEVEL SECURITY;

-- permissive: own it, OR it's high priority (the second branch is unclassified -> routed to the solver)
CREATE POLICY t_read ON rcj.tickets FOR SELECT TO authenticated
  USING (owner = auth.uid() OR priority > 5);

-- RESTRICTIVE: AND'd onto BOTH permissive branches -- caller must be in the row's tenant
CREATE POLICY t_tenant ON rcj.tickets AS RESTRICTIVE FOR SELECT TO authenticated
  USING (tenant_id = (auth.jwt() ->> 'tid')::uuid);

GRANT SELECT ON ALL TABLES IN SCHEMA rcj TO authenticated, service_role;
