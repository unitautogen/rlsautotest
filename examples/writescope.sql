-- WRITE-SCOPE fixture (schema wsc): the unconstrained-column write hole (lint L018 / cekuu35 audit
-- query #3). A write policy re-checks only SOME of the columns the schema uses to define access
-- scope, so a caller can set/change the others on write -- reassign ownership or hop tenants -- even
-- though every per-command assertion passes (the policy IS enforced as written).
--   wsc.docs  scope columns are owner_id (UPDATE checks it) AND tenant_id (SELECT scopes on it), but
--             the UPDATE WITH CHECK names only owner_id -> tenant_id is unconstrained on write ->
--             L018 fires (a user can UPDATE their row into another tenant).
--   wsc.safe  same shape, but the UPDATE WITH CHECK re-checks BOTH owner_id and tenant_id -> no L018.
-- Requires the auth shim + roles from examples/schema.sql.

DROP SCHEMA IF EXISTS wsc CASCADE;
CREATE SCHEMA wsc;
GRANT USAGE ON SCHEMA wsc TO anon, authenticated, service_role;

CREATE TABLE wsc.docs (
  id        bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  owner_id  uuid NOT NULL REFERENCES auth.users(id),
  tenant_id uuid NOT NULL,
  title     text NOT NULL
);

CREATE TABLE wsc.safe (
  id        bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  owner_id  uuid NOT NULL REFERENCES auth.users(id),
  tenant_id uuid NOT NULL,
  title     text NOT NULL
);

ALTER TABLE wsc.docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE wsc.safe ENABLE ROW LEVEL SECURITY;

-- docs: tenant_id is an access-scope key (SELECT scopes on it against a JWT claim) ...
CREATE POLICY docs_select ON wsc.docs FOR SELECT TO authenticated
  USING (tenant_id = (auth.jwt() ->> 'tenant')::uuid);
-- ... but the UPDATE write side re-checks only owner_id, leaving tenant_id writable -> L018
CREATE POLICY docs_update ON wsc.docs FOR UPDATE TO authenticated
  USING (owner_id = auth.uid())
  WITH CHECK (owner_id = auth.uid());

-- safe: the UPDATE write check re-checks BOTH scope columns -> no unconstrained scope column
CREATE POLICY safe_select ON wsc.safe FOR SELECT TO authenticated
  USING (tenant_id = (auth.jwt() ->> 'tenant')::uuid);
CREATE POLICY safe_update ON wsc.safe FOR UPDATE TO authenticated
  USING (owner_id = auth.uid())
  WITH CHECK (owner_id = auth.uid() AND tenant_id = (auth.jwt() ->> 'tenant')::uuid);

GRANT SELECT, UPDATE ON ALL TABLES IN SCHEMA wsc TO authenticated, service_role;
