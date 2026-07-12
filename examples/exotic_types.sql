-- examples/exotic_types.sql
-- F3 (TypeValueProvider / _castable_lit) demonstration: a table whose NOT NULL columns use types the
-- static substring value-table cannot represent (inet, macaddr, bytea, and a DOMAIN over int). Before F3
-- the seeder filled these with 'x', the INSERT failed to cast, the row could not be synthesized, and the
-- policy branch degraded to UNRELIABLE / NOT_TESTABLE. The DB-oracle _castable_lit probes a candidate
-- list against the live type and finds a valid literal for each, so the branch is now testable.
--
-- The table is gated by an opaque boolean function (no classifiable atom), which routes seeding through
-- the mock/probe-and-repair path (the same family examples/synth.sql exercises). Scoped FOR SELECT so
-- the demonstration is fully green; the UPDATE-probe SET-value and the classified _seed_plan fill are
-- separate value sites still on the F3 backlog (they do not yet use the DB-oracle).

DROP SCHEMA IF EXISTS xtypes CASCADE;
CREATE SCHEMA xtypes;
GRANT USAGE ON SCHEMA xtypes TO anon, authenticated, service_role;

-- a DOMAIN with a permissive CHECK the candidate list can satisfy (1 > 0)
CREATE DOMAIN xtypes.positive AS integer CHECK (VALUE > 0);

-- opaque boolean gate -> forces the synthesize-a-row path
CREATE FUNCTION xtypes.allowed(o uuid) RETURNS boolean LANGUAGE sql STABLE AS $$ SELECT o IS NOT NULL $$;

CREATE TABLE xtypes.devices (
  id      bigint generated always as identity primary key,
  owner   uuid            not null,
  ip      inet            not null,   -- exotic: static _lit -> 'x' -> 22P02
  mac     macaddr         not null,   -- exotic
  blob    bytea           not null,   -- exotic
  level   xtypes.positive not null,   -- DOMAIN over int with a CHECK
  note    text
);
ALTER TABLE xtypes.devices ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON xtypes.devices TO authenticated, service_role;
CREATE POLICY dev_gate ON xtypes.devices FOR SELECT TO authenticated
  USING (xtypes.allowed(owner));

-- F3 part 2 (classified-path seeding + UPDATE-probe SET through the DB oracle): an OWNER-scoped
-- table (classifiable policy -> the classified _seed_plan seeder builds the seed rows) whose other
-- NOT NULL columns are exotic. Before, fill() seeded ip/mac with 'x' -> the seed INSERT failed the
-- cast -> every cell UNRELIABLE; and the UPDATE probe SET ip='x' raised 22P02 -> UNRELIABLE. With
-- the oracle-verified fill both seed and SET get castable values and the whole matrix goes green.
CREATE TABLE xtypes.sensors (
  id      bigint generated always as identity primary key,
  owner   uuid            not null,
  ip      inet            not null,
  mac     macaddr         not null,
  note    text
);
ALTER TABLE xtypes.sensors ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON xtypes.sensors TO authenticated, service_role;
CREATE POLICY sensors_owner ON xtypes.sensors FOR ALL TO authenticated
  USING (owner = (SELECT auth.uid())) WITH CHECK (owner = (SELECT auth.uid()));

-- F3 part 3 (solver AUX rows through the DB oracle): a NON-canonical membership (extra `active`
-- condition) routes to the general subquery solver, whose aux row for room_members is built by
-- _seed_one. room_members carries a NOT NULL inet column: before, _seed_one filled it with 'x',
-- the aux INSERT failed the cast, the witness never confirmed, and the cells stayed '-'.
-- With the oracle-verified fill the aux row seeds and the matrix goes green.
CREATE TABLE xtypes.rooms (
  id    uuid primary key default gen_random_uuid(),
  title text
);
CREATE TABLE xtypes.room_members (
  room_id uuid not null,
  user_id uuid not null,
  active  boolean not null default true,
  ip      inet not null
);
ALTER TABLE xtypes.rooms ENABLE ROW LEVEL SECURITY;
ALTER TABLE xtypes.room_members ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON xtypes.rooms, xtypes.room_members TO authenticated, service_role;
CREATE POLICY members_self ON xtypes.room_members FOR SELECT TO authenticated USING (true);
CREATE POLICY rooms_member ON xtypes.rooms FOR SELECT TO authenticated
  USING (EXISTS (SELECT 1 FROM xtypes.room_members m
                 WHERE m.room_id = rooms.id AND m.user_id = (SELECT auth.uid()) AND m.active));

-- F10 (composite-FK aux rows): the solver's membership side-table has a COMPOSITE foreign key.
-- _seed_one walks only single-column FK parents, so the aux row hit 23503, the witness never
-- confirmed, and the cells stayed '-'. Composite-FK aux tables now route through the
-- probe-and-repair synthesizer, which reacts to the real FK error and seeds the parent tuple.
CREATE TABLE xtypes.projects2 (
  org uuid not null,
  num int  not null,
  PRIMARY KEY (org, num)
);
CREATE TABLE xtypes.assignments (
  user_id uuid not null,
  org     uuid not null,
  num     int  not null,
  active  boolean not null default true,
  FOREIGN KEY (org, num) REFERENCES xtypes.projects2 (org, num)
);
CREATE TABLE xtypes.tasks (
  id    uuid primary key default gen_random_uuid(),
  org   uuid not null,
  title text
);
ALTER TABLE xtypes.assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE xtypes.tasks ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON xtypes.projects2 TO service_role;   -- FK target only; no client reach
GRANT SELECT, INSERT, UPDATE, DELETE ON xtypes.assignments, xtypes.tasks TO authenticated, service_role;
CREATE POLICY assignments_self ON xtypes.assignments FOR SELECT TO authenticated
  USING (user_id = (SELECT auth.uid()));
CREATE POLICY tasks_assigned ON xtypes.tasks FOR SELECT TO authenticated
  USING (EXISTS (SELECT 1 FROM xtypes.assignments a
                 WHERE a.org = tasks.org AND a.user_id = (SELECT auth.uid()) AND a.active));
