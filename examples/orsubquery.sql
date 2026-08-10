-- OR-IN-SUBQUERY fixture (schema orsub): a membership policy whose EXISTS subquery WHERE contains an
-- OR (MB-2b). Before MB-2b the single-signature reader bailed on OR inside a subquery WHERE, so the
-- whole cell fell to "not tested". Now the reader distributes the WHERE to DNF min-terms, takes the
-- identity/correlation arm (the direct-membership arm), and the general witness DB-verifies the
-- grant/deny pair. The correlation (m.org_id = docs.org_id) is ANDed OUTSIDE the OR, so it appears in
-- EVERY min-term -- the falsifier that breaks the correlation denies every arm, so the deny side is real.
--   orsub.docs  SELECT visible when the caller is a member of the doc's org DIRECTLY, or the org has a
--               group-shared membership row:
--               EXISTS (SELECT 1 FROM orsub.members m
--                       WHERE m.org_id = docs.org_id AND (m.user_id = auth.uid() OR m.via_group))
-- Requires the auth shim + roles from examples/schema.sql (loaded first by the CI/regression loop).

DROP SCHEMA IF EXISTS orsub CASCADE;
CREATE SCHEMA orsub;
GRANT USAGE ON SCHEMA orsub TO anon, authenticated, service_role;

CREATE TABLE orsub.members (
  id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id   uuid NOT NULL REFERENCES auth.users(id),
  org_id    uuid NOT NULL,
  via_group boolean NOT NULL DEFAULT false
);

CREATE TABLE orsub.docs (
  id     bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  org_id uuid NOT NULL,
  title  text NOT NULL
);

ALTER TABLE orsub.members ENABLE ROW LEVEL SECURITY;
ALTER TABLE orsub.docs    ENABLE ROW LEVEL SECURITY;

-- the MB-2b target: an OR inside the membership EXISTS subquery's WHERE
CREATE POLICY docs_select ON orsub.docs FOR SELECT TO authenticated
  USING (EXISTS (SELECT 1 FROM orsub.members m
                 WHERE m.org_id = docs.org_id AND (m.user_id = auth.uid() OR m.via_group)));

-- membership rows are readable by all authenticated (a lookup table), so the docs policy's subquery
-- can see them under RLS; kept simple + green.
CREATE POLICY m_select ON orsub.members FOR SELECT TO authenticated
  USING (true);

GRANT SELECT ON ALL TABLES IN SCHEMA orsub TO authenticated, service_role;
