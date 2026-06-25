-- witness_novel.sql — BL-6 construct-first DB-oracle floor: predicates NO specific solver leaf handles, proven
-- solvable with ZERO operator-specific code. The engine doesn't interpret the operator; it varies the free row
-- column over candidate values and lets Postgres evaluate the predicate (grant vs deny), then DB-verifies.
--   t_startswith  starts_with(name, 'Admin')   -- a bare boolean FUNCTION predicate (not a comparison)
--   t_modulo      (n % 2) = 0                   -- the `%` operator buried on the left side of `=`
--   t_customop    name OPERATOR(wn.~#) 'Admin'  -- a genuinely CUSTOM operator (defined below)
drop schema if exists wn cascade;
create schema wn;
grant usage on schema wn to anon, authenticated, service_role;

-- a custom prefix-match operator — the strongest proof: the engine has never seen `~#` and needs no code for it
create function wn.same3(text, text) returns boolean language sql immutable as $$ select left($1,3) = left($2,3) $$;
create operator wn.~# (leftarg = text, rightarg = text, function = wn.same3);

create table wn.t_startswith (id uuid primary key default gen_random_uuid(), name text not null, body text);
create table wn.t_modulo     (id uuid primary key default gen_random_uuid(), n int not null default 0, body text);
create table wn.t_customop   (id uuid primary key default gen_random_uuid(), name text not null, body text);

do $$ declare r record; begin
  for r in select tablename from pg_tables where schemaname='wn' loop
    execute format('alter table wn.%I enable row level security', r.tablename);
    execute format('grant select, insert, update, delete on wn.%I to authenticated, service_role', r.tablename);
  end loop;
end $$;

create policy p on wn.t_startswith for select to authenticated using ( starts_with(name, 'Admin') );
create policy p on wn.t_modulo     for select to authenticated using ( (n % 2) = 0 );
create policy p on wn.t_customop   for select to authenticated using ( name operator(wn.~#) 'Admin' );
