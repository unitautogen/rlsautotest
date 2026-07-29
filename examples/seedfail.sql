-- seedfail.sql - a table whose only obstacle to seeding is a FORMAT CHECK the seeder now satisfies BY
-- CONSTRUCTION (a fixed-format regex: exactly ten digits). Before the checkwitness feature the generic
-- filler could not produce a ten-digit value, so the owner policy went UNRELIABLE; now the seeder reads
-- the CHECK, builds a conforming value, and the seed probe confirms it, so the ordinary owner policy is
-- genuinely testable (green). The STABLE un-seedable negative moved to seedimpossible.sql (a contradiction
-- no constructor can ever satisfy), which keeps guarding "a seeding failure can never masquerade as a
-- policy result".
drop schema if exists seedfail cascade;
create schema seedfail;
grant usage on schema seedfail to anon, authenticated, service_role;

create table seedfail.locked (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id),
  code text not null check (code ~ '^[0-9]{10}$'),   -- ten-digit format; the seeder satisfies it by construction (green)
  data text not null
);
alter table seedfail.locked enable row level security;
grant select, insert, update, delete on seedfail.locked to authenticated, service_role;
create policy own on seedfail.locked for all to authenticated
  using ( owner_id = (select auth.uid()) ) with check ( owner_id = (select auth.uid()) );