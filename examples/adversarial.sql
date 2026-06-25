-- adversarial.sql — policies the catalog classifier does NOT recognize, to exercise the per-min-term
-- solver fallback (BL-1) and the --debug-unhandled diagnostics (BL-4). The point: a novel branch must
-- not be silently dropped to NOT_TESTABLE when another branch classifies.
drop schema if exists adversarial cascade;
create schema adversarial;
grant usage on schema adversarial to anon, authenticated, service_role;

-- MIXED OR: `owner` (the classifier handles it) OR `deleted_at IS NULL` (the classifier has no NullTest
-- branch, but the general solver DOES). BL-1 must DB-verify the IS NULL branch instead of dropping it.
create table adversarial.t_nullmix (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id),
  deleted_at timestamptz,
  data text not null
);
alter table adversarial.t_nullmix enable row level security;
grant select, insert, update, delete on adversarial.t_nullmix to authenticated, service_role;
create policy own_or_live on adversarial.t_nullmix for select to authenticated
  using ( owner_id = (select auth.uid()) OR deleted_at IS NULL );

-- MIXED OR with `<>` (classifier requires `=`; solver handles `<>`).
create table adversarial.t_neqmix (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id),
  status text not null,
  data text not null
);
alter table adversarial.t_neqmix enable row level security;
grant select, insert, update, delete on adversarial.t_neqmix to authenticated, service_role;
create policy own_or_notdeleted on adversarial.t_neqmix for select to authenticated
  using ( owner_id = (select auth.uid()) OR status <> 'deleted' );

-- TRULY-NOVEL operator with no classifiable branch: pattern match. The current solver doesn't know `~`
-- either, so this stays NT today — but --debug-unhandled MUST list it (and BL-6 will solve it later).
create table adversarial.t_novelop (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id),
  email text not null,
  data text not null
);
alter table adversarial.t_novelop enable row level security;
grant select, insert, update, delete on adversarial.t_novelop to authenticated, service_role;
create policy email_pat on adversarial.t_novelop for select to authenticated
  using ( email ~ '@example\.com$' );

-- NULL-SAFE operators (BL-8): IS DISTINCT FROM = null-safe `<>`, IS NOT DISTINCT FROM = null-safe `=`.
-- The classifier has no branch for either; the solver routes them through equality (swapped for DISTINCT).
create table adversarial.t_distinct (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null,
  data text not null
);
alter table adversarial.t_distinct enable row level security;
grant select, insert, update, delete on adversarial.t_distinct to authenticated, service_role;
create policy notmine on adversarial.t_distinct for select to authenticated
  using ( owner_id is distinct from (select auth.uid()) );          -- rows NOT mine are visible

create table adversarial.t_notdistinct (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null,
  data text not null
);
alter table adversarial.t_notdistinct enable row level security;
grant select, insert, update, delete on adversarial.t_notdistinct to authenticated, service_role;
create policy mine on adversarial.t_notdistinct for select to authenticated
  using ( owner_id is not distinct from (select auth.uid()) );      -- null-safe owner

-- NOT of a compound (BL-3 De Morgan): NOT(flag_a AND flag_b) -> (NOT flag_a) OR (NOT flag_b); the per-branch
-- solver must witness each negated leaf instead of choking on the whole NOT(AND).
create table adversarial.t_notand (
  id uuid primary key default gen_random_uuid(),
  flag_a boolean not null default true,
  flag_b boolean not null default true,
  data text not null
);
alter table adversarial.t_notand enable row level security;
grant select, insert, update, delete on adversarial.t_notand to authenticated, service_role;
create policy nand on adversarial.t_notand for select to authenticated
  using ( not (flag_a and flag_b) );
