-- seedfail.sql — a table the generic seeder genuinely CANNOT populate: `code` must be exactly ten
-- digits (a format CHECK the templated filler doesn't satisfy, with no UDF to mock in the classified
-- owner path). The point is NOT the policy (a normal owner policy) but the SEEDING: the probe tries to
-- arrange an owned row, the INSERT fails the CHECK, the post-arrange invariant sees the table is still
-- empty, and the engine must mark those cells UNRELIABLE (a loud, failing test) instead of silently
-- printing "– not tested" or — worse — baking the seed error as a policy denial. A *negative* example
-- like exotic.sql / transitions.sql: the gate MUST flag it (exit non-zero). It is the regression guard
-- for "a seeding failure can never masquerade as a policy result."
drop schema if exists seedfail cascade;
create schema seedfail;
grant usage on schema seedfail to anon, authenticated, service_role;

create table seedfail.locked (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id),
  code text not null check (code ~ '^[0-9]{10}$'),    -- exactly 10 digits; the generic filler can't satisfy it
  data text not null
);
alter table seedfail.locked enable row level security;
grant select, insert, update, delete on seedfail.locked to authenticated, service_role;
create policy own on seedfail.locked for all to authenticated
  using ( owner_id = (select auth.uid()) ) with check ( owner_id = (select auth.uid()) );
