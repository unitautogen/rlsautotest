-- examples/zeroarg.sql
-- F10 (zero-arg claim-fn introspection): a policy gated on a ZERO-argument boolean function whose
-- body is a transparent JWT-claim check. Before, classify_node required a constant first argument to
-- reach introspection, so is_admin() fell to the opaque-fn MOCK wiring path (sound, but only a wiring
-- proof + a footgun note). Now the body's inline constant is introspected -> a claim_const atom -> the
-- authorized identity carries the real claim and the suite tests the policy FOR REAL (no mock).

DROP SCHEMA IF EXISTS za CASCADE;
CREATE SCHEMA za;
GRANT USAGE ON SCHEMA za TO anon, authenticated, service_role;

CREATE FUNCTION za.is_admin() RETURNS boolean LANGUAGE sql STABLE AS
$$ SELECT (auth.jwt()->>'app_role') = 'admin' $$;

CREATE TABLE za.settings (
  id    bigint generated always as identity primary key,
  key   text not null,
  value text
);
ALTER TABLE za.settings ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON za.settings TO authenticated, service_role;
CREATE POLICY settings_admin ON za.settings FOR ALL TO authenticated
  USING (za.is_admin()) WITH CHECK (za.is_admin());
