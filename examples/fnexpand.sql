-- FN-EXPANSION fixture (schema fnx): policies that delegate to user-defined BOOLEAN functions
-- whose bodies the narrow claim/RBAC introspectors do NOT recognize. The engine must expand each
-- body into an effective predicate (witness hints), seed real inputs, and bake DB-verified tests
-- with the REAL function running -- instead of stopping at the mock wiring proof:
--   fnx.docs   gate = is_member():   zero-arg SQL fn, EXISTS over a membership table keyed on
--              auth.uid() (no JWT claim -> dodges both introspectors)
--   fnx.tasks  gate = has_role('manager'): const-arg SQL fn, `count(*) > 0` body shape
--              (rewritten to EXISTS by the expander)
--   fnx.wiki   gate = can_edit(): a function CALLING a function (transitive expansion)
--   fnx.vault  gate = opaque_gate(): plpgsql with dynamic EXECUTE -> unexpandable BY DESIGN,
--              must stay on the mock wiring path (the honest maximum)
-- Requires the auth shim + roles from examples/schema.sql.

DROP SCHEMA IF EXISTS fnx CASCADE;
CREATE SCHEMA fnx;
GRANT USAGE ON SCHEMA fnx TO anon, authenticated, service_role;

CREATE TABLE fnx.memberships (
  user_id uuid NOT NULL REFERENCES auth.users(id),
  role    text NOT NULL,
  PRIMARY KEY (user_id, role)
);

CREATE FUNCTION fnx.is_member() RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT EXISTS (SELECT 1 FROM fnx.memberships m WHERE m.user_id = auth.uid())
$$;

CREATE FUNCTION fnx.has_role(wanted text) RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT count(*) > 0 FROM fnx.memberships m WHERE m.user_id = auth.uid() AND m.role = wanted
$$;

CREATE FUNCTION fnx.can_edit() RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT fnx.has_role('editor')
$$;

CREATE FUNCTION fnx.opaque_gate() RETURNS boolean
LANGUAGE plpgsql STABLE AS $f$
DECLARE ok boolean;
BEGIN
  EXECUTE 'SELECT true' INTO ok;   -- dynamic SQL: unparseable by design
  RETURN ok;
END $f$;

CREATE TABLE fnx.docs   (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, title text NOT NULL);
CREATE TABLE fnx.tasks  (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, title text NOT NULL);
CREATE TABLE fnx.wiki   (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, title text NOT NULL);
CREATE TABLE fnx.vault  (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, title text NOT NULL);

ALTER TABLE fnx.memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE fnx.docs   ENABLE ROW LEVEL SECURITY;
ALTER TABLE fnx.tasks  ENABLE ROW LEVEL SECURITY;
ALTER TABLE fnx.wiki   ENABLE ROW LEVEL SECURITY;
ALTER TABLE fnx.vault  ENABLE ROW LEVEL SECURITY;

CREATE POLICY m_select     ON fnx.memberships FOR SELECT TO authenticated USING (user_id = auth.uid());
CREATE POLICY docs_select  ON fnx.docs  FOR SELECT TO authenticated USING (fnx.is_member());
CREATE POLICY tasks_select ON fnx.tasks FOR SELECT TO authenticated USING (fnx.has_role('manager'));
CREATE POLICY wiki_select  ON fnx.wiki  FOR SELECT TO authenticated USING (fnx.can_edit());
CREATE POLICY vault_select ON fnx.vault FOR SELECT TO authenticated USING (fnx.opaque_gate());

GRANT SELECT ON ALL TABLES IN SCHEMA fnx TO authenticated, service_role;
