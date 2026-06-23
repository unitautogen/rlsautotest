-- Numeric clearance-level read access — a predicate the named-shape catalog does NOT recognize.
-- A row is readable only if the caller's JWT `clearance` is at least the row's `sensitivity`:
--
--     USING ((auth.jwt() ->> 'clearance')::int >= sensitivity)
--
-- This isn't owner / tenant / membership / role / array — it's a numeric threshold, so the catalog
-- marks it NOT_TESTABLE. The GENERAL WITNESS SOLVER handles it without a named shape: it reads the
-- operand roles (a JWT claim on one side, a column on the other, compared with `>=`), derives a
-- high-clearance reader that should see the row and a low-clearance reader that should not, then
-- VERIFIES both against the live database before baking the test. A green run proves the threshold
-- is enforced; if it can't confirm a witness it stays NOT_TESTABLE (never a false pass).
--
-- Requires the auth shim from examples/schema.sql (auth.jwt()) + the anon/authenticated/service_role roles.

DROP SCHEMA IF EXISTS clearance CASCADE;
CREATE SCHEMA clearance;
GRANT USAGE ON SCHEMA clearance TO anon, authenticated, service_role;

CREATE TABLE clearance.documents (
  id          uuid PRIMARY KEY,
  title       text,
  sensitivity int NOT NULL
);
ALTER TABLE clearance.documents ENABLE ROW LEVEL SECURITY;
GRANT SELECT ON clearance.documents TO authenticated, service_role;

CREATE POLICY "Read by clearance level." ON clearance.documents
  FOR SELECT TO authenticated
  USING ((auth.jwt() ->> 'clearance')::int >= sensitivity);
