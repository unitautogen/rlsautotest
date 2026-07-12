-- updcheck.sql — exercises the UPDATE probe's correctness guards. To prove "identity X can UPDATE its
-- row", the probe does `UPDATE … SET <col>=<value>`; that only measures the UPDATE *grant* if the column
-- is policy-neutral and the value is constraint-valid. Three tables stress the three failure modes:
--   t1  a neutral column with a value-set CHECK  -> the SET value must satisfy the CHECK -> UPDATE GREEN
--   t2  a neutral column with a CHECK the filler can't satisfy -> the SET raises 23514 (a constraint error,
--       NOT the RLS denial 42501) -> the UPDATE cell is UNRELIABLE (loud), never a baked "denied"
--   t3  no policy-neutral column, but the policy column is plain (non-unique) -> the SELF-ASSIGNMENT
--       fallback (SET owner_id = owner_id) still proves the UPDATE permission + policy re-check -> GREEN
--   t4  nothing self-assignable either (identity PK + UNIQUE policy column) -> UPDATE is an
--       EXPLAINED "–", never silent
-- A *negative* example (like seedfail.sql): the gate MUST flag it (t2 is UNRELIABLE -> exit non-zero).
drop schema if exists updcheck cascade;
create schema updcheck;
grant usage on schema updcheck to anon, authenticated, service_role;

create table updcheck.t1 (id bigint generated always as identity primary key,
  owner_id uuid not null references auth.users(id),
  status text not null check (status in ('open','closed')));

create table updcheck.t2 (id bigint generated always as identity primary key,
  owner_id uuid not null references auth.users(id),
  code text check (code ~ '^[0-9]{4}$'));

create table updcheck.t3 (id bigint generated always as identity primary key,
  owner_id uuid not null references auth.users(id));

create table updcheck.t4 (id bigint generated always as identity primary key,
  owner_id uuid not null unique references auth.users(id));

do $$ declare t text; begin
  foreach t in array array['t1','t2','t3','t4'] loop
    execute format('alter table updcheck.%I enable row level security', t);
    execute format('grant select,insert,update,delete on updcheck.%I to authenticated, service_role', t);
    execute format('create policy own on updcheck.%I for all to authenticated using (owner_id = (select auth.uid())) with check (owner_id = (select auth.uid()))', t);
  end loop;
end $$;
