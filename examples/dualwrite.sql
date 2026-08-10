-- DUAL-WRITE-PATH fixture (schema dw): lint L020 (MB-18 / a Reddit-reported vector). A table whose
-- intended write path is a SECURITY DEFINER rpc that holds the validation, while a client role ALSO
-- holds a direct DML grant + a permissive owner policy. Every per-command RLS assertion passes -- a
-- direct own-row insert genuinely IS allowed -- but the client can skip the rpc and its validation.
--   dw.orders   has both a client-callable definer rpc (dw.place_order) that INSERTs it AND a direct
--               GRANT INSERT to authenticated -> L020 fires.
--   dw.safe     same rpc-writes shape, but NO direct client DML grant (only the rpc path) -> no L020.
-- Requires the auth shim + roles from examples/schema.sql.

DROP SCHEMA IF EXISTS dw CASCADE;
CREATE SCHEMA dw;
GRANT USAGE ON SCHEMA dw TO anon, authenticated, service_role;

CREATE TABLE dw.orders (
  id       bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id  uuid NOT NULL REFERENCES auth.users(id),
  amount   numeric NOT NULL
);

CREATE TABLE dw.safe (
  id       bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id  uuid NOT NULL REFERENCES auth.users(id),
  amount   numeric NOT NULL
);

ALTER TABLE dw.orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE dw.safe   ENABLE ROW LEVEL SECURITY;

CREATE POLICY orders_own ON dw.orders FOR SELECT TO authenticated USING (user_id = auth.uid());
CREATE POLICY orders_ins ON dw.orders FOR INSERT TO authenticated WITH CHECK (user_id = auth.uid());
CREATE POLICY safe_own   ON dw.safe   FOR SELECT TO authenticated USING (user_id = auth.uid());

-- the intended write path: a definer rpc that validates then writes (search_path pinned to avoid L013 noise)
CREATE OR REPLACE FUNCTION dw.place_order(amt numeric) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  IF amt <= 0 THEN RAISE EXCEPTION 'amount must be positive'; END IF;   -- the validation the rpc holds
  INSERT INTO dw.orders(user_id, amount) VALUES (auth.uid(), amt);
END $$;

CREATE OR REPLACE FUNCTION dw.place_safe(amt numeric) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  IF amt <= 0 THEN RAISE EXCEPTION 'amount must be positive'; END IF;
  INSERT INTO dw.safe(user_id, amount) VALUES (auth.uid(), amt);
END $$;

GRANT EXECUTE ON FUNCTION dw.place_order(numeric), dw.place_safe(numeric) TO authenticated;

-- dw.orders ALSO grants direct DML to the client -> the rpc is skippable -> L020.
GRANT SELECT, INSERT ON dw.orders TO authenticated;
-- dw.safe grants only SELECT (writes MUST go through the rpc) -> no dual path -> no L020.
GRANT SELECT ON dw.safe TO authenticated;
