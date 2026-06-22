-- Self-contained example: a minimal Supabase-like schema (auth shim + roles + two RLS tables).
-- Lets you run rlsautotest against a plain Postgres (no Supabase needed) — used by CI.

-- ---- Supabase auth shim (present for real on Supabase) ----
CREATE SCHEMA IF NOT EXISTS auth;

CREATE OR REPLACE FUNCTION auth.jwt() RETURNS jsonb LANGUAGE sql STABLE AS $$
  SELECT coalesce(nullif(current_setting('request.jwt.claims', true), '')::jsonb, '{}'::jsonb)
$$;
CREATE OR REPLACE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS $$
  SELECT nullif(auth.jwt() ->> 'sub', '')::uuid
$$;
CREATE OR REPLACE FUNCTION auth.role() RETURNS text LANGUAGE sql STABLE AS $$
  SELECT auth.jwt() ->> 'role'
$$;

CREATE TABLE IF NOT EXISTS auth.users (
  id uuid PRIMARY KEY,
  email text, phone text,
  raw_user_meta_data jsonb DEFAULT '{}'::jsonb,
  raw_app_meta_data  jsonb DEFAULT '{}'::jsonb,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='anon')          THEN CREATE ROLE anon NOLOGIN; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='authenticated') THEN CREATE ROLE authenticated NOLOGIN; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='service_role')  THEN CREATE ROLE service_role NOLOGIN BYPASSRLS; END IF;
END $$;
GRANT USAGE ON SCHEMA auth TO anon, authenticated, service_role;

-- ---- App tables with RLS ----
-- profiles: classic per-user ownership (auth.uid() = id)
CREATE TABLE IF NOT EXISTS public.profiles (
  id uuid PRIMARY KEY REFERENCES auth.users(id),
  handle text
);
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY profiles_select ON public.profiles FOR SELECT USING ((SELECT auth.uid()) = id);
CREATE POLICY profiles_insert ON public.profiles FOR INSERT WITH CHECK ((SELECT auth.uid()) = id);
CREATE POLICY profiles_update ON public.profiles FOR UPDATE USING ((SELECT auth.uid()) = id);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.profiles TO authenticated, service_role;
GRANT SELECT ON public.profiles TO anon;

-- notes: owner-scoped for all commands
CREATE TABLE IF NOT EXISTS public.notes (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  owner uuid NOT NULL,
  body text
);
ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_all ON public.notes FOR ALL
  USING (owner = (SELECT auth.uid())) WITH CHECK (owner = (SELECT auth.uid()));
GRANT SELECT, INSERT, UPDATE, DELETE ON public.notes TO authenticated, service_role;
