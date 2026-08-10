-- GENERALITY fixture (schema mor): policies that MIX patterns the classifier only partially
-- understands, proving the obligation router tests EVERY branch instead of the first one:
--   mor.t_mixed   a classified owner branch OR'd with an UNCLASSIFIED uncorrelated-EXISTS admin
--                 branch -> the admin branch must get its own DB-verified battery (not silent NT)
--   mor.t_twopol  TWO permissive SELECT policies (owner + department membership) -> BOTH tested,
--                 no first-win (the second policy used to ride along untested)
--   mor.t_notand  NOT (flag_a AND flag_b) -> De Morgan yields TWO unclassified min-terms; both
--                 survive dedup and each disjunct gets its own battery
-- Requires the auth shim + roles from examples/schema.sql.

DROP SCHEMA IF EXISTS mor CASCADE;
CREATE SCHEMA mor;
GRANT USAGE ON SCHEMA mor TO anon, authenticated, service_role;

CREATE TABLE mor.admins (
  user_id uuid PRIMARY KEY REFERENCES auth.users(id)
);

CREATE TABLE mor.dept_members (
  dept_id uuid NOT NULL,
  user_id uuid NOT NULL REFERENCES auth.users(id),
  PRIMARY KEY (dept_id, user_id)
);

CREATE TABLE mor.t_mixed (
  id       bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  owner_id uuid NOT NULL REFERENCES auth.users(id),
  note     text NOT NULL
);

CREATE TABLE mor.t_twopol (
  id       bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  owner_id uuid NOT NULL REFERENCES auth.users(id),
  dept_id  uuid NOT NULL,
  note     text NOT NULL
);

CREATE TABLE mor.t_notand (
  id     bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  flag_a boolean NOT NULL DEFAULT false,
  flag_b boolean NOT NULL DEFAULT false,
  note   text NOT NULL
);

ALTER TABLE mor.admins       ENABLE ROW LEVEL SECURITY;
ALTER TABLE mor.dept_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE mor.t_mixed      ENABLE ROW LEVEL SECURITY;
ALTER TABLE mor.t_twopol     ENABLE ROW LEVEL SECURITY;
ALTER TABLE mor.t_notand     ENABLE ROW LEVEL SECURITY;

-- owner branch (classified) OR uncorrelated admin EXISTS (unclassified -> router rescue)
CREATE POLICY mix_select ON mor.t_mixed FOR SELECT TO authenticated
  USING (owner_id = auth.uid()
         OR EXISTS (SELECT 1 FROM mor.admins a WHERE a.user_id = auth.uid()));

-- TWO permissive policies on the same command: both must be tested
CREATE POLICY two_owner ON mor.t_twopol FOR SELECT TO authenticated
  USING (owner_id = auth.uid());
CREATE POLICY two_dept ON mor.t_twopol FOR SELECT TO authenticated
  USING (EXISTS (SELECT 1 FROM mor.dept_members d
                 WHERE d.dept_id = t_twopol.dept_id AND d.user_id = auth.uid()));

-- NOT (a AND b): two unclassified De Morgan disjuncts, each needing its own witness
CREATE POLICY na_select ON mor.t_notand FOR SELECT TO authenticated
  USING (NOT (flag_a AND flag_b));

-- membership/support tables readable by their own user
CREATE POLICY adm_select ON mor.admins FOR SELECT TO authenticated
  USING (user_id = auth.uid());
CREATE POLICY dm_select ON mor.dept_members FOR SELECT TO authenticated
  USING (user_id = auth.uid());

GRANT SELECT ON ALL TABLES IN SCHEMA mor TO authenticated, service_role;
