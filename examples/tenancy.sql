-- Multi-tenant separation test schema for rlsautotest.
-- Demonstrates tenant isolation TWO ways (the two patterns real Supabase apps use):
--   1. JWT-claim isolation   : row.org_id must equal the caller's app_metadata.org_id claim   (table: invoices)
--   2. membership isolation  : caller must have a membership row linking them to row.org_id     (table: projects)
-- Both must enforce: a user in org A can see/modify ONLY org A's rows, never org B's.
-- Requires the supabase_ext test DB (auth.uid()/auth.jwt() shim + auth.users stub + pgtap).

DROP SCHEMA IF EXISTS tenancy CASCADE;
CREATE SCHEMA tenancy;
GRANT USAGE ON SCHEMA tenancy TO anon, authenticated, service_role;

-- ── tables (created first so cross-referencing policies resolve) ──────────────
CREATE TABLE tenancy.orgs (
  id   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL
);

CREATE TABLE tenancy.memberships (
  org_id  uuid NOT NULL REFERENCES tenancy.orgs(id),
  user_id uuid NOT NULL REFERENCES auth.users(id),
  PRIMARY KEY (org_id, user_id)
);

CREATE TABLE tenancy.invoices (
  id     bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  org_id uuid NOT NULL REFERENCES tenancy.orgs(id),
  amount numeric(12,2) NOT NULL DEFAULT 0,
  note   text
);

CREATE TABLE tenancy.projects (
  id     bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  org_id uuid NOT NULL REFERENCES tenancy.orgs(id),
  name   text NOT NULL
);

ALTER TABLE tenancy.orgs        ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenancy.memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenancy.invoices    ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenancy.projects    ENABLE ROW LEVEL SECURITY;

GRANT SELECT ON tenancy.orgs, tenancy.memberships TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON tenancy.invoices, tenancy.projects TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA tenancy TO service_role;

-- ── policies ─────────────────────────────────────────────────────────────────
-- a user may see an org only if they are a member of it
CREATE POLICY orgs_member_read ON tenancy.orgs FOR SELECT TO authenticated
  USING (EXISTS (SELECT 1 FROM tenancy.memberships m WHERE m.org_id = orgs.id AND m.user_id = (select auth.uid())));

-- a user may see only their OWN membership rows (also lets the EXISTS subqueries resolve)
CREATE POLICY memberships_self_read ON tenancy.memberships FOR SELECT TO authenticated
  USING (user_id = (select auth.uid()));

-- pattern 1: JWT app_metadata.org_id claim
CREATE POLICY invoices_tenant ON tenancy.invoices FOR ALL TO authenticated
  USING      (org_id = (auth.jwt() -> 'app_metadata' ->> 'org_id')::uuid)
  WITH CHECK (org_id = (auth.jwt() -> 'app_metadata' ->> 'org_id')::uuid);

-- pattern 2: membership table
CREATE POLICY projects_member ON tenancy.projects FOR ALL TO authenticated
  USING      (EXISTS (SELECT 1 FROM tenancy.memberships m WHERE m.org_id = projects.org_id AND m.user_id = (select auth.uid())))
  WITH CHECK (EXISTS (SELECT 1 FROM tenancy.memberships m WHERE m.org_id = projects.org_id AND m.user_id = (select auth.uid())));
