-- rbac_tenant.sql — regression corpus for the multi-tenant-RBAC patterns (distilled from a real Supabase
-- RBAC extension) that each exposed an engine gap. A GREEN example: with the engine fixes in place every
-- cell is correct and the suite passes; a regression in any of the fixes turns it red. Requires the
-- supabase_ext / CI shim (auth.uid()/auth.jwt()/auth.role() + auth.users + anon/authenticated/service_role).
--
-- Patterns exercised (and the fix each guards):
--   rbt.orgs    login-only INSERT `auth.uid() IS NOT NULL` (NOT a helper) beside helper-gated SELECT/UPDATE/DELETE
--               + an ownership-on-insert trigger  -> per-command classification; auth.users identity seeding;
--                 clearing the JWT while seeding so the trigger doesn't own the seeded row.
--   rbt.mships  multi-column UNIQUE(org_id,user_id) + a roles text[] column + a mixed
--               `has_role(...) OR user_id = auth.uid()` DELETE -> clean-before-mock-INSERT (no 23505);
--                 UPDATE column picker (default != unsettable) + a non-empty array literal for the SET;
--                 `exp` on every synthetic JWT so the OR'd expiry-aware helper doesn't RAISE.
--   rbt.invs    roles text[] with DEFAULT '{}' but CHECK (cardinality(roles) > 0) -> cardinality-aware row
--                 synthesizer + non-empty array UPDATE SET (an empty '{}' would violate the CHECK).
--   rbt.mperms  composite FK (org_id,user_id) -> mships, multi-col UNIQUE, a FOR ALL policy but NO UPDATE
--                 grant, and a service_role `USING (true)` policy -> grant-aware mock (skip the no-grant
--                 UPDATE) + role-scoped client DNF (the service_role policy must not spawn an authenticated
--                 "open" branch).

DROP SCHEMA IF EXISTS rbt CASCADE;
CREATE SCHEMA rbt;
GRANT USAGE ON SCHEMA rbt TO anon, authenticated, service_role;

-- ── opaque, claims-driven RBAC helpers (STABLE plpgsql; body reads the JWT so they are NOT classifiable ──
-- ── -> the engine mock-wires them). Each guards on JWT expiry, like the real extension. ─────────────────
CREATE OR REPLACE FUNCTION rbt.is_member(org_id uuid) RETURNS boolean LANGUAGE plpgsql STABLE AS $$
BEGIN
  IF auth.role() = 'authenticated' THEN
    IF coalesce(nullif(auth.jwt() ->> 'exp', ''), '0')::numeric < extract(epoch FROM now()) THEN
      RAISE EXCEPTION 'invalid_jwt' USING HINT = 'jwt is expired or missing';
    END IF;
    RETURN coalesce(auth.jwt() -> 'groups' ? org_id::text, false);
  END IF;
  RETURN false;
END $$;
CREATE OR REPLACE FUNCTION rbt.has_role(org_id uuid, role text) RETURNS boolean LANGUAGE plpgsql STABLE AS $$
BEGIN
  IF auth.role() = 'authenticated' THEN
    IF coalesce(nullif(auth.jwt() ->> 'exp', ''), '0')::numeric < extract(epoch FROM now()) THEN
      RAISE EXCEPTION 'invalid_jwt' USING HINT = 'jwt is expired or missing';
    END IF;
    RETURN coalesce(auth.jwt() -> 'roles' ? role, false);
  END IF;
  RETURN false;
END $$;
CREATE OR REPLACE FUNCTION rbt.has_permission(org_id uuid, perm text) RETURNS boolean LANGUAGE plpgsql STABLE AS $$
BEGIN
  IF auth.role() = 'authenticated' THEN
    IF coalesce(nullif(auth.jwt() ->> 'exp', ''), '0')::numeric < extract(epoch FROM now()) THEN
      RAISE EXCEPTION 'invalid_jwt' USING HINT = 'jwt is expired or missing';
    END IF;
    RETURN coalesce(auth.jwt() -> 'perms' ? perm, false);
  END IF;
  RETURN false;
END $$;
GRANT EXECUTE ON FUNCTION rbt.is_member(uuid), rbt.has_role(uuid, text), rbt.has_permission(uuid, text)
  TO anon, authenticated, service_role;

-- ── tables (orgs first so mships/invs/mperms can reference it) ──────────────────────────────────────────
CREATE TABLE rbt.orgs (
  id   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL
);
CREATE TABLE rbt.mships (
  id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id  uuid NOT NULL REFERENCES rbt.orgs(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  roles   text[] NOT NULL DEFAULT '{}'::text[],
  UNIQUE (org_id, user_id)
);
CREATE TABLE rbt.invs (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id     uuid NOT NULL REFERENCES rbt.orgs(id) ON DELETE CASCADE,
  roles      text[] NOT NULL DEFAULT '{}'::text[] CHECK (cardinality(roles) > 0),
  invited_by uuid NOT NULL REFERENCES auth.users(id)
);
CREATE TABLE rbt.mperms (
  id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id  uuid NOT NULL REFERENCES rbt.orgs(id) ON DELETE CASCADE,
  user_id uuid NOT NULL,
  perm    text NOT NULL,
  UNIQUE (org_id, user_id, perm),
  FOREIGN KEY (org_id, user_id) REFERENCES rbt.mships(org_id, user_id) ON DELETE CASCADE
);

-- ── ownership-on-insert trigger (skips when auth.uid() is NULL, i.e. seeding as the privileged role) ─────
CREATE OR REPLACE FUNCTION rbt.on_org_created() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  IF auth.uid() IS NOT NULL THEN
    INSERT INTO rbt.mships (org_id, user_id, roles) VALUES (NEW.id, auth.uid(), ARRAY['owner'])
      ON CONFLICT DO NOTHING;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER on_org_created AFTER INSERT ON rbt.orgs FOR EACH ROW EXECUTE FUNCTION rbt.on_org_created();

ALTER TABLE rbt.orgs   ENABLE ROW LEVEL SECURITY;
ALTER TABLE rbt.mships ENABLE ROW LEVEL SECURITY;
ALTER TABLE rbt.invs   ENABLE ROW LEVEL SECURITY;
ALTER TABLE rbt.mperms ENABLE ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON rbt.orgs, rbt.mships, rbt.invs TO authenticated;
GRANT SELECT, INSERT, DELETE           ON rbt.mperms                    TO authenticated;   -- NB: NO UPDATE grant
GRANT ALL ON ALL TABLES IN SCHEMA rbt TO service_role;

-- ── policies ────────────────────────────────────────────────────────────────────────────────────────────
-- orgs: any logged-in user may create; membership reads; owners update/delete.
CREATE POLICY orgs_insert ON rbt.orgs FOR INSERT TO authenticated WITH CHECK ((select auth.uid()) IS NOT NULL);
CREATE POLICY orgs_select ON rbt.orgs FOR SELECT TO authenticated USING (rbt.is_member(id));
CREATE POLICY orgs_update ON rbt.orgs FOR UPDATE TO authenticated USING (rbt.has_role(id, 'owner')) WITH CHECK (rbt.has_role(id, 'owner'));
CREATE POLICY orgs_delete ON rbt.orgs FOR DELETE TO authenticated USING (rbt.has_role(id, 'owner'));

-- mships: members read; owners add/update; owners OR the member themself may remove.
CREATE POLICY mships_select ON rbt.mships FOR SELECT TO authenticated USING (rbt.is_member(org_id));
CREATE POLICY mships_insert ON rbt.mships FOR INSERT TO authenticated WITH CHECK (rbt.has_role(org_id, 'owner'));
CREATE POLICY mships_update ON rbt.mships FOR UPDATE TO authenticated USING (rbt.has_role(org_id, 'owner')) WITH CHECK (rbt.has_role(org_id, 'owner'));
CREATE POLICY mships_delete ON rbt.mships FOR DELETE TO authenticated USING (rbt.has_role(org_id, 'owner') OR user_id = (select auth.uid()));

-- invs: members read; owners manage (roles text[] must be non-empty).
CREATE POLICY invs_select ON rbt.invs FOR SELECT TO authenticated USING (rbt.is_member(org_id));
CREATE POLICY invs_insert ON rbt.invs FOR INSERT TO authenticated WITH CHECK (rbt.has_role(org_id, 'owner'));
CREATE POLICY invs_update ON rbt.invs FOR UPDATE TO authenticated USING (rbt.has_role(org_id, 'owner')) WITH CHECK (rbt.has_role(org_id, 'owner'));
CREATE POLICY invs_delete ON rbt.invs FOR DELETE TO authenticated USING (rbt.has_role(org_id, 'owner'));

-- mperms: members read; permission-holders manage (FOR ALL, but authenticated has NO UPDATE grant);
-- service_role full access via USING(true) (must NOT create an authenticated "open" branch).
CREATE POLICY mperms_select ON rbt.mperms FOR SELECT TO authenticated USING (rbt.is_member(org_id));
CREATE POLICY mperms_manage ON rbt.mperms FOR ALL TO authenticated USING (rbt.has_permission(org_id, 'members.manage')) WITH CHECK (rbt.has_permission(org_id, 'members.manage'));
CREATE POLICY mperms_service ON rbt.mperms FOR ALL TO service_role USING (true) WITH CHECK (true);
