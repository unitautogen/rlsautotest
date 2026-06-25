-- witness_array.sql — WB-1: array overlap / containment witnesses.
-- Each policy is row-based over an array column, so the solver must SEED an array value that satisfies it
-- (visible -> authorized) and one that doesn't (hidden), then probe anon. No '-' / NT, no opaque function.
--   t_overlap     tags && array[...]            (overlap: share an element)
--   t_contains    roles @> array['admin']       (col contains all of the constant set)
--   t_containedby perms <@ array[...]           (col is a subset of the constant set)
--   t_reverse     array['admin','root'] @> roles (column on the RIGHT -> the operand-flip path: a @> col == col <@ a)
drop schema if exists wa cascade;
create schema wa;
grant usage on schema wa to anon, authenticated, service_role;

create table wa.t_overlap     (id uuid primary key default gen_random_uuid(), tags  text[] not null default '{}', body text);
create table wa.t_contains    (id uuid primary key default gen_random_uuid(), roles text[] not null default '{}', body text);
create table wa.t_containedby (id uuid primary key default gen_random_uuid(), perms text[] not null default '{}', body text);
create table wa.t_reverse     (id uuid primary key default gen_random_uuid(), roles text[] not null default '{}', body text);

do $$ declare r record; begin
  for r in select tablename from pg_tables where schemaname='wa' loop
    execute format('alter table wa.%I enable row level security', r.tablename);
    execute format('grant select, insert, update, delete on wa.%I to authenticated, service_role', r.tablename);
  end loop;
end $$;

create policy p on wa.t_overlap     for select to authenticated using ( tags && array['vip','beta'] );
create policy p on wa.t_contains    for select to authenticated using ( roles @> array['admin'] );
create policy p on wa.t_containedby for select to authenticated using ( perms <@ array['read','write','admin'] );
create policy p on wa.t_reverse     for select to authenticated using ( array['admin','root'] @> roles );
