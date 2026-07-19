-- Bypass-surface corpus for `rlsautotest lint` codes L011-L013 (schema `bypasssurf`).
-- Half of these MUST be flagged (real side doors), half MUST NOT (safe by construction) — the test asserts both.
DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='anon') THEN CREATE ROLE anon NOLOGIN; END IF; END $$;
DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='authenticated') THEN CREATE ROLE authenticated NOLOGIN; END IF; END $$;

DROP SCHEMA IF EXISTS bypasssurf CASCADE;
CREATE SCHEMA bypasssurf;
GRANT USAGE ON SCHEMA bypasssurf TO anon, authenticated;

-- an RLS-protected base table
CREATE TABLE bypasssurf.secrets (id int PRIMARY KEY, owner text NOT NULL, data text NOT NULL);
ALTER TABLE bypasssurf.secrets ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON bypasssurf.secrets FOR SELECT USING (owner = current_setting('app.uid', true));

-- FLAG L011 (CRITICAL): definer view over the RLS table, readable by anon
CREATE VIEW bypasssurf.leaky_secrets AS SELECT * FROM bypasssurf.secrets;
GRANT SELECT ON bypasssurf.leaky_secrets TO anon;

-- SAFE: security_invoker view (the base RLS applies to the caller) -> must NOT be flagged
CREATE VIEW bypasssurf.safe_secrets WITH (security_invoker=on) AS SELECT * FROM bypasssurf.secrets;
GRANT SELECT ON bypasssurf.safe_secrets TO anon;

-- SAFE: definer view but no client grant (only the backend can read it) -> must NOT be flagged
CREATE VIEW bypasssurf.internal_secrets AS SELECT * FROM bypasssurf.secrets;

-- FLAG L012 (CRITICAL): SECURITY DEFINER fn, anon-executable, reads the RLS table; search_path pinned so NO L013
CREATE FUNCTION bypasssurf.all_secrets() RETURNS SETOF bypasssurf.secrets
  LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$ SELECT * FROM bypasssurf.secrets $$;

-- FLAG L012 + L013: SECURITY DEFINER fn, anon-executable, reads the RLS table, mutable search_path
CREATE FUNCTION bypasssurf.count_secrets() RETURNS bigint
  LANGUAGE sql SECURITY DEFINER AS $$ SELECT count(*) FROM bypasssurf.secrets $$;

-- SAFE: SECURITY DEFINER helper with EXECUTE revoked from PUBLIC (in-policy / internal use only) -> must NOT be flagged
CREATE FUNCTION bypasssurf.internal_helper() RETURNS boolean
  LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$ SELECT true $$;
REVOKE EXECUTE ON FUNCTION bypasssurf.internal_helper() FROM PUBLIC;

-- a NON-RLS control table
CREATE TABLE bypasssurf.public_menu (id int PRIMARY KEY, item text);

-- SAFE: definer view over a NON-RLS table, anon-readable -> nothing to bypass -> must NOT be flagged
CREATE VIEW bypasssurf.menu_view AS SELECT * FROM bypasssurf.public_menu;
GRANT SELECT ON bypasssurf.menu_view TO anon;

-- FLAG L011 (HIGH): definer view over the RLS table, readable by AUTHENTICATED only (not anon)
CREATE VIEW bypasssurf.auth_secrets AS SELECT * FROM bypasssurf.secrets;
GRANT SELECT ON bypasssurf.auth_secrets TO authenticated;

-- FLAG L011 (CRITICAL): materialized view over the RLS table, anon-readable (matviews are always definer-rights)
CREATE MATERIALIZED VIEW bypasssurf.mv_secrets AS SELECT * FROM bypasssurf.secrets WITH NO DATA;
GRANT SELECT ON bypasssurf.mv_secrets TO anon;

-- FLAG L011b (MEDIUM): definer view that reads ANOTHER view (chain not resolvable to a base table here), anon-readable
CREATE VIEW bypasssurf.chain_view AS SELECT * FROM bypasssurf.leaky_secrets;
GRANT SELECT ON bypasssurf.chain_view TO anon;

-- FLAG L012 (HIGH, opaque): plpgsql SECURITY DEFINER fn, anon-executable, opaque body (no textual RLS-table ref)
CREATE FUNCTION bypasssurf.opaque_fn() RETURNS int
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$ BEGIN RETURN 42; END $$;

-- SAFE: SECURITY DEFINER SQL fn reading only a NON-RLS table, anon-executable -> nothing to bypass -> must NOT be flagged
CREATE FUNCTION bypasssurf.menu_count() RETURNS bigint
  LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$ SELECT count(*) FROM bypasssurf.public_menu $$;
