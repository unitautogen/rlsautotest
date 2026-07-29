-- seedimpossible.sql - the STABLE un-seedable negative control (took over seedfail's old role). The table
-- carries a CHECK that is a CONTRADICTION - CHECK (false) - so NO value can ever satisfy it and NO seed row
-- can ever be built, no matter how capable the value constructor becomes. It verifies the engine marks
-- those cells UNRELIABLE and fails the gate LOUDLY, never misreporting a seed failure (23514) as a policy
-- denial (42501) or a silent "- not tested". Unlike a format/length CHECK - which checkwitness can now
-- satisfy - this can never be "solved", so the guard cannot quietly turn itself off.
drop schema if exists seedimpossible cascade;
create schema seedimpossible;
grant usage on schema seedimpossible to anon, authenticated, service_role;

create table seedimpossible.blocked (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id),
  code text not null,
  data text not null,
  constraint impossible check (false)   -- a contradiction: no row can ever satisfy it -> un-seedable by construction
);
alter table seedimpossible.blocked enable row level security;
grant select, insert, update, delete on seedimpossible.blocked to authenticated, service_role;
create policy own on seedimpossible.blocked for all to authenticated
  using ( owner_id = (select auth.uid()) ) with check ( owner_id = (select auth.uid()) );