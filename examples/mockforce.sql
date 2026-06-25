-- mockforce.sql — exercises the general "force the opaque fn to the value that makes the predicate
-- true (authorized) / false (not authorized)" fallback for opaque SCALAR functions in a comparison that
-- the named-shape paths don't catch: `fn() = const` and `fn() = fn()`. The engine can't reason into the
-- functions, so it MOCKS them to force the predicate both ways and bakes the observed grant/deny — a
-- WIRING proof (the functions' own logic stays unverified -> the report shows the "MOCKED" footgun).
-- Expected: gate exit 0 (no holes) — each table gets ✓ (mocked) / blocked / anon-denied, no NT.
drop schema if exists mockforce cascade;
create schema mockforce;
grant usage on schema mockforce to anon, authenticated, service_role;

-- two opaque context functions (read a GUC; opaque to the engine, like realtime.topic())
create or replace function mockforce.ctx()  returns text language sql stable as $$ select nullif(current_setting('mf.ctx',  true), '') $$;
create or replace function mockforce.ctx2() returns text language sql stable as $$ select nullif(current_setting('mf.ctx2', true), '') $$;

-- fn() = const  (e.g. realtime.topic() = 'room-1')
create table mockforce.t_const (
  id   bigint generated always as identity primary key,
  body text not null
);
alter table mockforce.t_const enable row level security;
grant select, insert, update, delete on mockforce.t_const to authenticated, service_role;
create policy c_all on mockforce.t_const for all to authenticated
  using ( mockforce.ctx() = 'room-1' ) with check ( mockforce.ctx() = 'room-1' );

-- fn() = fn()  (two opaque fns compared to each other)
create table mockforce.t_fnfn (
  id   bigint generated always as identity primary key,
  body text not null
);
alter table mockforce.t_fnfn enable row level security;
grant select, insert, update, delete on mockforce.t_fnfn to authenticated, service_role;
create policy f_all on mockforce.t_fnfn for all to authenticated
  using ( mockforce.ctx() = mockforce.ctx2() ) with check ( mockforce.ctx() = mockforce.ctx2() );
