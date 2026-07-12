-- examples/regexfree.sql
-- F6 (retire regex-on-SQL, _policy_cols site): the policy's WITH CHECK contains the WORD "note"
-- inside a STRING LITERAL. The old regex-over-policy-text saw the word and disqualified the real
-- `note` column from being the policy-neutral UPDATE column; with no other neutral column left the
-- UPDATE cell degraded to the explained "-" (not tested). The AST reader sees that `note` the
-- column is never referenced -> `note` stays neutral -> UPDATE is tested for real.

DROP SCHEMA IF EXISTS rxf CASCADE;
CREATE SCHEMA rxf;
GRANT USAGE ON SCHEMA rxf TO anon, authenticated, service_role;

CREATE TABLE rxf.tickets (
  id     bigint generated always as identity primary key,
  owner  uuid not null,
  status text not null default 'open',
  note   text
);
ALTER TABLE rxf.tickets ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON rxf.tickets TO authenticated, service_role;
CREATE POLICY tickets_owner ON rxf.tickets FOR ALL TO authenticated
  USING (owner = (SELECT auth.uid()))
  WITH CHECK (owner = (SELECT auth.uid()) AND status <> 'note deleted');

-- F6 (_policy_bool_udfs site): rxf.audit_note() is a boolean function the reviews policy NEVER
-- calls; its name appears only inside a string literal in the policy. The old regex over the policy
-- text mock-listed it, so the wiring tests mocked (and their labels blamed) a function the policy
-- does not use. The AST reader lists only the really-called rxf.is_staff().
CREATE FUNCTION rxf.is_staff() RETURNS boolean LANGUAGE sql STABLE AS
$$ SELECT auth.uid() IS NOT NULL $$;
CREATE FUNCTION rxf.audit_note(t text) RETURNS boolean LANGUAGE sql STABLE AS
$$ SELECT t <> '' $$;

CREATE TABLE rxf.reviews (
  id   bigint generated always as identity primary key,
  body text,
  tag  text not null default 'x'
);
ALTER TABLE rxf.reviews ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON rxf.reviews TO authenticated, service_role;
CREATE POLICY reviews_staff ON rxf.reviews FOR ALL TO authenticated
  USING (rxf.is_staff() AND tag <> 'audit_note(x)')
  WITH CHECK (rxf.is_staff());

-- F6 (_synth_gate site): the GUC gate written in REVERSED order. The old text-regex demanded
-- `col = current_setting(...)` with the column first, so this spelling fell past the synth
-- strategy; the AST reader accepts either side. Must be green (and handled by the synth gate).
CREATE TABLE rxf.jobs (
  id     bigint generated always as identity primary key,
  tenant text not null,
  body   text
);
ALTER TABLE rxf.jobs ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON rxf.jobs TO authenticated, service_role;
CREATE POLICY jobs_tenant ON rxf.jobs FOR ALL TO authenticated
  USING (current_setting('app.tenant2'::text, true) = tenant)
  WITH CHECK (current_setting('app.tenant2'::text, true) = tenant);

-- F6 (_constraint_meta site): the CHECK wraps the column in a CAST. The old regex over the
-- constraint text captured the cast name ("text") as the column, so the real `status` column got
-- no CHECK-satisfying fill, the seed row violated its own CHECK (23514) and every cell went
-- UNRELIABLE. The AST reader unwraps the cast, checks[status]='live', and the matrix is green.
CREATE TABLE rxf.posts (
  id     bigint generated always as identity primary key,
  owner  uuid not null,
  status character varying(16) not null CHECK ((status)::text = ANY (ARRAY['live'::text, 'draft'::text])),
  body   text
);
ALTER TABLE rxf.posts ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON rxf.posts TO authenticated, service_role;
CREATE POLICY posts_owner ON rxf.posts FOR ALL TO authenticated
  USING (owner = (SELECT auth.uid())) WITH CHECK (owner = (SELECT auth.uid()));
