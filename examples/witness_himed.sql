-- witness_himed.sql — exercises the High/Medium witness builders added to the solver:
-- bare boolean column, NOT col, IS TRUE, JSONB @>, JSONB ?, BETWEEN, lower(col)=const, col::text=const,
-- and a cross-column inequality. Each predicate is row-based (no user component), so the engine should
-- SOLVE it (seed a matching row -> visible; a non-matching row -> hidden; anon denied) — no '–' / NT.
drop schema if exists wm cascade;
create schema wm;
grant usage on schema wm to anon, authenticated, service_role;

create table wm.t_bool      (id uuid primary key default gen_random_uuid(), is_active boolean not null default true,  body text);
create table wm.t_notcol    (id uuid primary key default gen_random_uuid(), archived  boolean not null default false, body text);
create table wm.t_istrue    (id uuid primary key default gen_random_uuid(), verified  boolean not null default false, body text);
create table wm.t_jsoncont  (id uuid primary key default gen_random_uuid(), meta jsonb not null default '{}'::jsonb,  body text);
create table wm.t_jsonkey   (id uuid primary key default gen_random_uuid(), meta jsonb not null default '{}'::jsonb,  body text);
create table wm.t_between    (id uuid primary key default gen_random_uuid(), score int not null default 0, body text);
create table wm.t_lower     (id uuid primary key default gen_random_uuid(), email text not null, body text);
create table wm.t_cast      (id uuid primary key default gen_random_uuid(), code int not null default 0, body text);
create table wm.t_crosscol  (id uuid primary key default gen_random_uuid(), start_n int not null default 0, end_n int not null default 0, body text);

do $$ declare r record; begin
  for r in select tablename from pg_tables where schemaname='wm' loop
    execute format('alter table wm.%I enable row level security', r.tablename);
    execute format('grant select, insert, update, delete on wm.%I to authenticated, service_role', r.tablename);
  end loop;
end $$;

create policy p on wm.t_bool      for select to authenticated using ( is_active );
create policy p on wm.t_notcol    for select to authenticated using ( not archived );
create policy p on wm.t_istrue    for select to authenticated using ( verified is true );
create policy p on wm.t_jsoncont  for select to authenticated using ( meta @> '{"role":"admin"}' );
create policy p on wm.t_jsonkey   for select to authenticated using ( meta ? 'admin' );
create policy p on wm.t_between     for select to authenticated using ( score between 10 and 20 );
create policy p on wm.t_lower     for select to authenticated using ( lower(email) = 'admin@example.com' );
create policy p on wm.t_cast      for select to authenticated using ( code::text = '5' );
create policy p on wm.t_crosscol  for select to authenticated using ( start_n < end_n );
