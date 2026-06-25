-- witness_joint.sql — BL-11: joint signature-driven DB-oracle search (completion of the construct-first floor).
-- These predicates can't be witnessed by varying ONE input: their truth needs a coordinated assignment across
-- several controllable inputs. The engine collects the full signature (row columns + JWT claim paths) and lets
-- Postgres judge a bounded cross-product of (session x row) candidates until it finds a grant and a deny.
--   t_jointfn   a OPERATOR(wj.~#) b                      -- two columns must agree (custom operator -> the solver, not a named-fn mock)
--   t_claimop   (auth.jwt()->>'dept') OPERATOR(wj.~#) tag -- a CLAIM under a custom operator (the single-column floor refuses claims)
drop schema if exists wj cascade;
create schema wj;
grant usage on schema wj to anon, authenticated, service_role;

create function wj.share2(text, text) returns boolean language sql immutable as $$ select left($1,2) = left($2,2) $$;
create operator wj.~# (leftarg = text, rightarg = text, function = wj.share2);

create table wj.t_jointfn (id uuid primary key default gen_random_uuid(), a text not null, b text not null, data text);
create table wj.t_claimop (id uuid primary key default gen_random_uuid(), tag text not null, data text);

do $$ declare r record; begin
  for r in select tablename from pg_tables where schemaname='wj' loop
    execute format('alter table wj.%I enable row level security', r.tablename);
    execute format('grant select, insert, update, delete on wj.%I to authenticated, service_role', r.tablename);
  end loop;
end $$;

create policy p on wj.t_jointfn for select to authenticated using ( a operator(wj.~#) b );
create policy p on wj.t_claimop for select to authenticated using ( (auth.jwt() ->> 'dept') operator(wj.~#) tag );
