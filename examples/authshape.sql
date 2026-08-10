-- IDENTITY-BINDING fixture (schema ash) -- ISOLATED-DB ONLY (redefines auth.uid(), would clobber the
-- shared corpus). Purpose (MB-19b): a CLASSIFIED owner policy whose identity CANNOT be bound must be
-- flagged LOUDLY (UNRELIABLE), never a silent "correctly denied" cell. auth.uid() here reads a CUSTOM
-- session GUC (current_setting('app.current_user')) that the probe cannot know about (the app-role /
-- SaaS-Factory shape) -- this is the case MB-23 deliberately does NOT bind, so it stays UNRELIABLE.

CREATE SCHEMA IF NOT EXISTS auth;
-- CUSTOM-GUC variant: NOT request.jwt.claims and NOT the flat request.jwt.claim.* either -> unbindable.
CREATE OR REPLACE FUNCTION auth.uid() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT nullif(current_setting('app.current_user', true), '')::uuid
$$;

DROP SCHEMA IF EXISTS ash CASCADE;
CREATE SCHEMA ash;
GRANT USAGE ON SCHEMA ash TO anon, authenticated, service_role;

CREATE TABLE ash.notes (
  id      bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id uuid NOT NULL,
  body    text NOT NULL
);

ALTER TABLE ash.notes ENABLE ROW LEVEL SECURITY;

-- a CORRECT owner policy; the only problem is the probe cannot bind this custom-GUC auth.uid()
CREATE POLICY notes_owner ON ash.notes FOR SELECT TO authenticated
  USING (user_id = auth.uid());

GRANT SELECT ON ALL TABLES IN SCHEMA ash TO authenticated, service_role;
