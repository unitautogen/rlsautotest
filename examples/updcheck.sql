-- updcheck.sql -- exercises the full UPDATE-probe ladder end to end; every cell resolves cleanly, so this
-- is a POSITIVE (green) fixture. To prove "identity X can UPDATE its row" the probe runs
--   UPDATE ... SET <col> = <value>
-- which only measures the UPDATE *grant* when the column is policy-neutral AND the value is constraint-valid.
-- Four tables walk the four rungs of the ladder the probe climbs:
--   t1  neutral column, value-set CHECK the filler satisfies -> SET <fresh valid value> -> UPDATE GREEN
--   t2  neutral column with a CHECK the filler CANNOT construct (a look-ahead regex) -> the fresh-value SET
--       would raise 23514 (a constraint error, NOT the RLS denial 42501), so the probe FALLS BACK to
--       SET code = DEFAULT: a no-read literal write of the value seeding left in the row (the column is
--       omitted from the seed, so it holds its default, NULL), which is constraint-valid, so no 23514, and
--       the UPDATE privilege + USING/WITH CHECK re-check are still measured -> UPDATE GREEN. Because the RHS
--       is a literal (not `code = code`), an identity holding UPDATE but not SELECT on the column is measured
--       correctly too, not reported as a false deny. (Before this fallback t2 was UNRELIABLE; the guard that
--       a genuine seeding failure still cannot masquerade as a pass now lives in examples/seedfail.sql, whose
--       NOT NULL look-ahead column blocks seeding entirely, so even SET code = DEFAULT has no row to touch.)
--   t3  no policy-neutral column, but the policy column is plain (non-unique) -> self-assign the policy
--       column (SET owner_id = owner_id) proves the UPDATE permission + policy re-check -> GREEN
--   t4  nothing self-assignable either (identity PK + UNIQUE policy column) -> UPDATE is an explained "-",
--       never silent (the report notes "no policy-neutral column")
-- A GREEN example: the report gate MUST exit 0 (every cell is a real pass or an explained dash).
drop schema if exists updcheck cascade;
create schema updcheck;
grant usage on schema updcheck to anon, authenticated, service_role;

create table updcheck.t1 (id bigint generated always as identity primary key,
  owner_id uuid not null references auth.users(id),
  status text not null check (status in ('open','closed')));

create table updcheck.t2 (id bigint generated always as identity primary key,
  owner_id uuid not null references auth.users(id),
  code text check (code ~ '^(?=.*[0-9])(?=.*[a-z]).{8,}$'));   -- look-ahead CHECK the filler can't construct -> probe falls back to SET code = DEFAULT -> GREEN

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