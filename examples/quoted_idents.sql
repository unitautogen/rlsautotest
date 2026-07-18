-- Quoted / mixed-case (PascalCase) identifiers with GUC tenancy.
-- Guards the #357 identifier-quoting fix: the generator must quote table + column names it emits, or a
-- PascalCase schema (EF Core, quoted names) crashes / seeds UNRELIABLE. This schema must stay GREEN.
DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='anon') THEN CREATE ROLE anon NOLOGIN; END IF; END $$;
DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='authenticated') THEN CREATE ROLE authenticated NOLOGIN; END IF; END $$;
DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='service_role') THEN CREATE ROLE service_role NOLOGIN BYPASSRLS; END IF; END $$;

CREATE SCHEMA IF NOT EXISTS qident;
GRANT USAGE ON SCHEMA qident TO authenticated, anon;

-- PascalCase table + columns, tenant isolation driven by a session GUC (not a JWT claim)
CREATE TABLE qident."Widgets" (
  "Id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "TenantId" text NOT NULL,
  "DisplayName" text NOT NULL
);
ALTER TABLE qident."Widgets" ENABLE ROW LEVEL SECURITY;
ALTER TABLE qident."Widgets" FORCE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON qident."Widgets" TO authenticated;
CREATE POLICY tenant_isolation ON qident."Widgets" FOR ALL
  USING ("TenantId" = current_setting('app.current_tenant_id', true))
  WITH CHECK ("TenantId" = current_setting('app.current_tenant_id', true));
