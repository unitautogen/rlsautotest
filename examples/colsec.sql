-- Column-level security fixture: three RLS tables with IDENTICAL row-level policies (own-row), so the
-- row-level matrix is the SAME for all three and the ONLY difference lives in the column-level grid.
-- The grid flags exactly one thing, by the same principle as the cross-policy WITH CHECK leak: a
-- column-specific GRANT (the developer's expressed scope) that a BROADER grant silently bypasses. It makes
-- NO judgement about which columns are "sensitive" and never flags a bare table-wide grant.
--   colsec.profiles -> SCOPED (green): column grants only; effective == granted, the scope holds.
--   colsec.accounts -> LEAK  (red)  : column grants PLUS a table-wide grant that bypasses them, so the
--                      columns outside the column grant (id/role/is_admin/tenant_id) leak back in.
--   colsec.members  -> SILENT       : a BARE table-wide grant, no column grant -> no scope expressed, so
--                      nothing is flagged even though it carries is_admin/tenant_id (proves we do NOT
--                      guess "sensitivity" from column names).
-- Requires the auth shim + roles (auth.uid()/auth.users + anon/authenticated/service_role), as in supabase_ext.

DROP SCHEMA IF EXISTS colsec CASCADE;
CREATE SCHEMA colsec;
GRANT USAGE ON SCHEMA colsec TO anon, authenticated, service_role;

-- == SCOPED: column grants only; the scope holds (green) ================================
CREATE TABLE colsec.profiles (
  id           uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  display_name text,
  bio          text,
  role         text NOT NULL DEFAULT 'member',
  tenant_id    uuid,
  is_admin     boolean NOT NULL DEFAULT false,
  created_at   timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE colsec.profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY "profiles select own" ON colsec.profiles FOR SELECT TO authenticated USING (id = (SELECT auth.uid()));
CREATE POLICY "profiles insert own" ON colsec.profiles FOR INSERT TO authenticated WITH CHECK (id = (SELECT auth.uid()));
CREATE POLICY "profiles update own" ON colsec.profiles FOR UPDATE TO authenticated USING (id = (SELECT auth.uid())) WITH CHECK (id = (SELECT auth.uid()));
-- column grants ONLY (no table-wide grant): reads/writes are scoped to the user-editable columns,
-- so role / tenant_id / is_admin stay off-limits and the scope holds.
GRANT SELECT (id, display_name, bio, created_at) ON colsec.profiles TO authenticated;
GRANT INSERT (id, display_name, bio)             ON colsec.profiles TO authenticated;
GRANT UPDATE (display_name, bio)                 ON colsec.profiles TO authenticated;
GRANT ALL ON colsec.profiles TO service_role;

-- == LEAK: column grants PLUS a table-wide grant that bypasses them (red) ===============
CREATE TABLE colsec.accounts (
  id        uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  name      text,
  role      text NOT NULL DEFAULT 'member',
  is_admin  boolean NOT NULL DEFAULT false,
  tenant_id uuid
);
ALTER TABLE colsec.accounts ENABLE ROW LEVEL SECURITY;
CREATE POLICY "accounts select own" ON colsec.accounts FOR SELECT TO authenticated USING (id = (SELECT auth.uid()));
CREATE POLICY "accounts insert own" ON colsec.accounts FOR INSERT TO authenticated WITH CHECK (id = (SELECT auth.uid()));
CREATE POLICY "accounts update own" ON colsec.accounts FOR UPDATE TO authenticated USING (id = (SELECT auth.uid())) WITH CHECK (id = (SELECT auth.uid()));
-- the developer SCOPED writes/reads via column grants...
GRANT SELECT (id, name) ON colsec.accounts TO authenticated;
GRANT INSERT (id, name) ON colsec.accounts TO authenticated;
GRANT UPDATE (name)     ON colsec.accounts TO authenticated;
-- ...but this table-wide grant is STILL in force and silently bypasses the column grants above:
-- id / role / is_admin / tenant_id become reachable again = the leak the grid must flag.
GRANT SELECT, INSERT, UPDATE ON colsec.accounts TO authenticated;
GRANT ALL ON colsec.accounts TO service_role;

-- == SILENT: a BARE table-wide grant, no column grant -> no scope expressed (not flagged) =
CREATE TABLE colsec.members (
  id        uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  name      text,
  is_admin  boolean NOT NULL DEFAULT false,
  tenant_id uuid
);
ALTER TABLE colsec.members ENABLE ROW LEVEL SECURITY;
CREATE POLICY "members select own" ON colsec.members FOR SELECT TO authenticated USING (id = (SELECT auth.uid()));
CREATE POLICY "members insert own" ON colsec.members FOR INSERT TO authenticated WITH CHECK (id = (SELECT auth.uid()));
CREATE POLICY "members update own" ON colsec.members FOR UPDATE TO authenticated USING (id = (SELECT auth.uid())) WITH CHECK (id = (SELECT auth.uid()));
-- bare table-wide grant, NO column grant: the tool expresses no opinion on is_admin / tenant_id here.
GRANT SELECT, INSERT, UPDATE ON colsec.members TO authenticated;
GRANT ALL ON colsec.members TO service_role;
