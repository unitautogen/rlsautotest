-- FLAT-CLAIM fixture (schema fc) -- ISOLATED-DB ONLY (redefines auth.uid(), would clobber the shared
-- corpus). Purpose (MB-23): auth.uid() reads the OLD flat GUC request.jwt.claim.sub (older GoTrue /
-- cekuu35's supabase-rls-leak-demo shape). The probe now ALSO drives the flat per-claim GUCs
-- (claim_style='flat'), so a CORRECT owner policy BINDS and goes GREEN instead of UNRELIABLE.

CREATE SCHEMA IF NOT EXISTS auth;
-- FLAT-GUC variant: reads request.jwt.claim.sub (a per-claim GUC), not the request.jwt.claims JSON.
CREATE OR REPLACE FUNCTION auth.uid() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT nullif(current_setting('request.jwt.claim.sub', true), '')::uuid
$$;

DROP SCHEMA IF EXISTS fc CASCADE;
CREATE SCHEMA fc;
GRANT USAGE ON SCHEMA fc TO anon, authenticated, service_role;

CREATE TABLE fc.notes (
  id      bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id uuid NOT NULL,
  body    text NOT NULL
);

ALTER TABLE fc.notes ENABLE ROW LEVEL SECURITY;

CREATE POLICY notes_owner ON fc.notes FOR SELECT TO authenticated
  USING (user_id = auth.uid());

GRANT SELECT ON ALL TABLES IN SCHEMA fc TO authenticated, service_role;
