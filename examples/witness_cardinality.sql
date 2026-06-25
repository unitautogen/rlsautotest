-- BL-12 acceptance fixture: RELATIONAL-STATE (cardinality / aggregate) gated policy.
--
-- `wcard.gated` is visible only to a caller who OWNS AT LEAST 3 `wcard.events` rows. The policy's truth
-- depends on the *number of rows* in another table it reads (a scalar COUNT subquery vs a threshold) — not on
-- any column of the row under test. There is no COUNT/aggregate handler in the engine and there never will be:
-- the relational-state floor instead SEEDS A CANDIDATE NUMBER of matching rows (cardinalities drawn from the
-- predicate's own constants, here {0,1,2,3,4}) and lets Postgres evaluate the real aggregate. The cardinality
-- that makes the gated row visible is the witness (3 events -> ✓); one that hides it is the falsifier (0 -> blocked).
-- A brand-new aggregate gate (sum/avg/min/max thresholds, multi-row conditions) is covered with zero new code.
--
-- Counterpart of the predicate-layer floors (BL-6/BL-11); the table-state analog of UnitAutogen-PG's RS6.

drop schema if exists wcard cascade;
create schema wcard;

create table wcard.events (
  id    uuid primary key default gen_random_uuid(),
  owner uuid not null
);

create table wcard.gated (
  id    uuid primary key default gen_random_uuid(),
  label text not null default 'x'
);

alter table wcard.events enable row level security;
alter table wcard.gated  enable row level security;

grant usage on schema wcard to authenticated, anon;
grant select, insert, update, delete on wcard.events to authenticated, anon;
grant select, insert, update, delete on wcard.gated  to authenticated, anon;

-- the cardinality gate: see gated rows only if you own >= 3 events
create policy gated_thresh on wcard.gated
  for select to authenticated
  using ( (select count(*) from wcard.events e where e.owner = (select auth.uid())) >= 3 );

-- own-row policy on the scope table (idiomatic; keeps the count caller-scoped)
create policy own_events on wcard.events
  for all to authenticated
  using      ( owner = (select auth.uid()) )
  with check ( owner = (select auth.uid()) );
