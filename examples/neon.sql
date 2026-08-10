-- NEON fixture (schema neon): guards rlsautotest's provider-agnostic support for Neon's pg_session_jwt
-- RLS vocabulary + role model (MB-11). Neon uses auth.user_id() (== Supabase auth.uid()) and
-- auth.session() (== auth.jwt()), the roles `authenticated` + `anonymous` (NO `anon`, NO `service_role`).
-- The engine recognizes the identity/claims functions by CONSTRUCT (astutil `_FN_ALIASES`) and DISCOVERS
-- the role model from the catalog (catalog `auth_profile`), so this schema is understood on its own terms:
--   * neon.documents  owner isolation via auth.user_id() -> the owner battery (all commands)
--   * neon.posts      a custom `user_role=admin` claim via auth.session() -> the claim battery; `anonymous`
--                     holds a SELECT grant but no policy -> a faithful denied `anonymous` row (no phantom
--                     service_role / anon)
-- Requires schema.sql (auth.users + the `authenticated` role) loaded first by the CI/regression loop.

DROP SCHEMA IF EXISTS neon CASCADE;
CREATE SCHEMA neon;

DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='anonymous') THEN CREATE ROLE anonymous NOLOGIN; END IF;
END $$;

-- Neon pg_session_jwt vocabulary shim (present for real on Neon). Reads the SAME PostgREST-compatible
-- request.jwt.claims GUC the probe already drives, so no probe change is needed.
CREATE OR REPLACE FUNCTION auth.session() RETURNS jsonb LANGUAGE sql STABLE AS $$
  SELECT coalesce(nullif(current_setting('request.jwt.claims', true), '')::jsonb, '{}'::jsonb)
$$;
CREATE OR REPLACE FUNCTION auth.user_id() RETURNS uuid LANGUAGE sql STABLE AS $$
  SELECT nullif(auth.session() ->> 'sub', '')::uuid
$$;

GRANT USAGE ON SCHEMA neon TO authenticated, anonymous;

-- owner-scoped table: per-user isolation via the Neon identity function
CREATE TABLE neon.documents (
  id    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner uuid NOT NULL REFERENCES auth.users(id),
  body  text
);
ALTER TABLE neon.documents ENABLE ROW LEVEL SECURITY;
CREATE POLICY documents_owner ON neon.documents FOR ALL TO authenticated
  USING (owner = auth.user_id()) WITH CHECK (owner = auth.user_id());

-- claim-scoped table: a custom role claim read via auth.session(); anonymous is granted SELECT but no
-- policy scopes to it, so it is a faithful "denied" row in the report.
CREATE TABLE neon.posts (
  id    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  title text NOT NULL
);
ALTER TABLE neon.posts ENABLE ROW LEVEL SECURITY;
CREATE POLICY posts_admin ON neon.posts FOR SELECT TO authenticated
  USING (auth.session() ->> 'user_role' = 'admin');

GRANT SELECT, INSERT, UPDATE, DELETE ON neon.documents TO authenticated;
GRANT SELECT ON neon.posts TO authenticated, anonymous;
