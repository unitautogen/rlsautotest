-- Custom-role column-level-security fixture (MB-12): the column-scope parity that colsec.sql proves for the
-- STANDARD client roles, proven here for a CUSTOM role. A policy-named custom role (clsc_auditor) that reads
-- rows AND carries a column-specific SELECT grant used to appear in the report's CLS grid (the report builds
-- its CLS role set from the standard roles PLUS the policy-named customs it renders) while the emitted pgTAP
-- suite asserted NOTHING for it -- the report claimed a column scope the suite never guarded. MB-12 gathers
-- custom roles holding a column grant (pg_attribute.attacl) into the suite's CLS role set too, so report and
-- suite cover the SAME cells. Same principle as always: we do NOT guess which columns are "sensitive" -- we
-- flag exactly the contradiction of a column-specific GRANT that a BROADER grant silently bypasses.
--   clsc.ledger       -> clsc_auditor SCOPED (green): a column grant only (id, amount), no table-wide grant;
--                        effective == granted, so the custom role's scope holds -> a passing parity assertion.
--   clsc.audit_events -> clsc_auditor LEAK  (red)  : a column grant (id) PLUS a table-wide SELECT that reaches
--                        past it, so owner/action/ip/secret leak back in -> the SAME failing assertion a
--                        standard-role leak would emit, now for the custom role.
-- Both tables keep an ordinary authenticated own-row policy so the ROW-LEVEL matrix is green; the auditor's
-- USING(true) SELECT is its intended read-everything audience (a ✓, never a ✓! hole), exactly like crole's
-- reporter. Requires the auth shim + roles (auth.uid()/auth.users + anon/authenticated/service_role), as in
-- examples/schema.sql (loaded first by the regression harness).

DO $$ BEGIN CREATE ROLE clsc_auditor NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DROP SCHEMA IF EXISTS clsc CASCADE;
CREATE SCHEMA clsc;
GRANT USAGE ON SCHEMA clsc TO anon, authenticated, service_role, clsc_auditor;

-- == SCOPED: the custom role's column grant only; effective == granted, the scope holds (green) ==========
CREATE TABLE clsc.ledger (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner       uuid NOT NULL,
  amount      numeric NOT NULL DEFAULT 0,
  memo        text,
  secret_note text
);
ALTER TABLE clsc.ledger ENABLE ROW LEVEL SECURITY;
-- ordinary owner-scoped audience (keeps the row-level matrix green)
CREATE POLICY ledger_owner ON clsc.ledger FOR ALL TO authenticated
  USING (owner = (SELECT auth.uid())) WITH CHECK (owner = (SELECT auth.uid()));
GRANT SELECT, INSERT, UPDATE, DELETE ON clsc.ledger TO authenticated;
GRANT ALL ON clsc.ledger TO service_role;
-- the custom role: reads every row (its intended audience) but its SELECT is column-SCOPED to (id, amount)
-- with NO table-wide grant, so memo / owner / secret_note stay off-limits and the scope holds.
CREATE POLICY ledger_auditor ON clsc.ledger FOR SELECT TO clsc_auditor USING (true);
GRANT SELECT (id, amount) ON clsc.ledger TO clsc_auditor;
-- anon is the unauthenticated client role (RLS denies it here -- no anon policy). Granting it a bare table
-- privilege, exactly as examples/schema.sql does for public.profiles, is what lets auth_profile recognise
-- anon as the schema's unauth slot; without it, the only non-authed role holding a grant is clsc_auditor,
-- which would then be MISTAKEN for the anon slot and never exercise the custom-role column-grant path.
GRANT SELECT ON clsc.ledger TO anon;

-- == LEAK: the custom role's column grant PLUS a table-wide grant that bypasses it (red) =================
CREATE TABLE clsc.audit_events (
  id     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner  uuid NOT NULL,
  action text NOT NULL DEFAULT 'view',
  ip     inet,
  secret text
);
ALTER TABLE clsc.audit_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY audit_owner ON clsc.audit_events FOR ALL TO authenticated
  USING (owner = (SELECT auth.uid())) WITH CHECK (owner = (SELECT auth.uid()));
GRANT SELECT, INSERT, UPDATE, DELETE ON clsc.audit_events TO authenticated;
GRANT ALL ON clsc.audit_events TO service_role;
CREATE POLICY audit_auditor ON clsc.audit_events FOR SELECT TO clsc_auditor USING (true);
-- the developer SCOPED the auditor's read via a column grant...
GRANT SELECT (id) ON clsc.audit_events TO clsc_auditor;
-- ...but this table-wide SELECT is STILL in force and silently bypasses it: owner / action / ip / secret
-- become reachable again = the leak the grid must flag AND the suite must assert (now, with MB-12).
GRANT SELECT ON clsc.audit_events TO clsc_auditor;
GRANT SELECT ON clsc.audit_events TO anon;   -- anon = the unauth slot (denied by RLS); see the note on clsc.ledger
