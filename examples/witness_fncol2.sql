-- witness_fncol2.sql — WB-2: non-invertible function-on-column witnesses (preimage construction).
-- The function maps many inputs to one output, so the solver can't seed `col := target`; instead it builds a
-- column value whose IMAGE equals the target (visible -> authorized) and one whose image differs (hidden),
-- then probes anon. DB-verified, so an un-constructible case stays honest NT. (The idempotent text fns
-- lower/upper/trim/cast are the earlier `_solve_fncol_eq` path; this fixture exercises the many-to-one ones.)
--   t_datetrunc  date_trunc('day', created_at) = <ts>   (sat = the aligned timestamp itself)
--   t_substr     substring(code, 1, 3) = 'ABC'          (sat = 'ABC' + filler)
--   t_left       left(name, 1) = 'A'                    (sat = 'A' + filler)
--   t_tochar     to_char(created_at, 'YYYY-MM') = '2026-06'  (sat = a date in that month)
drop schema if exists wf2 cascade;
create schema wf2;
grant usage on schema wf2 to anon, authenticated, service_role;

-- timestamp WITHOUT time zone so date_trunc/to_char don't depend on the session TZ (keeps the witness portable).
create table wf2.t_datetrunc (id uuid primary key default gen_random_uuid(), created_at timestamp not null, body text);
create table wf2.t_substr    (id uuid primary key default gen_random_uuid(), code text not null, body text);
create table wf2.t_left      (id uuid primary key default gen_random_uuid(), name text not null, body text);
create table wf2.t_tochar    (id uuid primary key default gen_random_uuid(), created_at timestamp not null, body text);

do $$ declare r record; begin
  for r in select tablename from pg_tables where schemaname='wf2' loop
    execute format('alter table wf2.%I enable row level security', r.tablename);
    execute format('grant select, insert, update, delete on wf2.%I to authenticated, service_role', r.tablename);
  end loop;
end $$;

create policy p on wf2.t_datetrunc for select to authenticated using ( date_trunc('day', created_at) = timestamp '2026-06-15' );
create policy p on wf2.t_substr    for select to authenticated using ( substring(code, 1, 3) = 'ABC' );
create policy p on wf2.t_left      for select to authenticated using ( left(name, 1) = 'A' );
create policy p on wf2.t_tochar    for select to authenticated using ( to_char(created_at, 'YYYY-MM') = '2026-06' );
