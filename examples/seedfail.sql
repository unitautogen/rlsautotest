-- seedfail.sql — a table the seeder genuinely CANNOT populate, so its cells must come out UNRELIABLE (a
-- loud, failing test) rather than a silent "– not tested" or, worse, a seed error baked as a policy denial.
-- As of the CHECK-aware filler, a plain format/length CHECK (e.g. `code ~ '^[0-9]{10}$'`) is now SEEDABLE by
-- construction, so this fixture uses a HARDER one to keep its teeth: `code ~ '^([0-9])\1{9}$'` (ten identical
-- digits, via a back-reference). A satisfying value exists ('0000000000'), but constructing it needs a real
-- regex solver, which the construct-and-verify filler deliberately does not have — it recognizes the shape but
-- not the back-reference, returns no candidate, and the generic filler's value fails the CHECK. The probe sees
-- the arranged INSERT fail, the post-arrange invariant sees the table still empty, and the engine marks those
-- cells UNRELIABLE. A *negative* example like exotic.sql / transitions.sql: the gate MUST flag it (exit
-- non-zero). It is the regression guard for "a seeding failure can never masquerade as a policy result", now
-- pinned to a constraint beyond construct-and-verify (its solvable twin is examples/checkfmt.sql).
drop schema if exists seedfail cascade;
create schema seedfail;
grant usage on schema seedfail to anon, authenticated, service_role;

create table seedfail.locked (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id),
  code text not null check (code ~ '^([0-9])\1{9}$'),   -- ten identical digits (back-reference); a value exists but the filler can't construct it
  data text not null
);
alter table seedfail.locked enable row level security;
grant select, insert, update, delete on seedfail.locked to authenticated, service_role;
create policy own on seedfail.locked for all to authenticated
  using ( owner_id = (select auth.uid()) ) with check ( owner_id = (select auth.uid()) );
