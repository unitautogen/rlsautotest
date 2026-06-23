-- synth.sql — exercises the probe-and-repair seed synthesizer on the hardest seeding shape:
-- a table whose policy delegates to an OPAQUE SECURITY DEFINER function (so the engine can only
-- prove WIRING by mocking it) AND that also carries a COMPOSITE foreign key plus a CHECK that
-- DELEGATES TO A UDF. To seed a row to act on, the engine has to (1) seed the composite-FK parent
-- tuple and (2) neutralize the CHECK's function for the insert — both discovered by reacting to the
-- real INSERT errors (NOT NULL / FK / CHECK), not by any hand-coded rule. This schema is expected to
-- be GREEN (the suite proves the policy wires to can_access() both ways); it is the regression guard
-- for the synthesizer. See README "What it can and can't do".
drop schema if exists synth cascade;
create schema synth;
grant usage on schema synth to anon, authenticated, service_role;

create table synth.combo (a int, b int, label text not null, primary key (a, b));

create or replace function synth.payload_ok(p text) returns boolean
  language sql immutable as $$ select length(p) > 3 $$;

-- opaque gate: external state, SECURITY DEFINER — the engine can only mock-and-prove-wiring here
create or replace function synth.can_access(rid uuid) returns boolean
  language sql security definer set search_path = '' stable as $$ select true $$;

create table synth.docs (
  id uuid primary key default gen_random_uuid(),
  ca int not null,
  cb int not null,
  payload text not null,
  foreign key (ca, cb) references synth.combo(a, b),     -- composite FK -> parent tuple must be seeded
  check (synth.payload_ok(payload))                       -- CHECK delegates to a UDF -> must be neutralized to seed
);
alter table synth.docs enable row level security;
grant select, insert, update, delete on synth.docs to authenticated, service_role;
create policy g on synth.docs for all to authenticated
  using ( (select synth.can_access(id)) ) with check ( (select synth.can_access(id)) );
