-- witness_subq.sql — WB-3: non-canonical subquery witnesses (general EXISTS / IN).
-- The canonical "is the caller a member of the row's org?" EXISTS is handled by the classifier. These are the
-- shapes it CAN'T model, so the general `_solve_subquery` builder must seed them: an extra condition in the
-- subquery (role='admin'), TWO correlations, an IN-subquery with a boolean filter, and NOT EXISTS.
-- The side tables carry a self-read / read policy so the EXISTS subqueries resolve when evaluated as the
-- calling role (the canonical tenancy pattern). Side tables hold plain uuid links (no FK to the outer tables)
-- so the witness seeding order is simple. DB-verified, so anything unmodeled stays honest NT.
drop schema if exists wsq cascade;
create schema wsq;
grant usage on schema wsq to anon, authenticated, service_role;

-- side (subquery) tables
create table wsq.memberships (id uuid primary key default gen_random_uuid(), user_id uuid not null, org_id uuid not null, role text not null default 'member');
create table wsq.links       (id uuid primary key default gen_random_uuid(), a uuid not null, b uuid not null);
create table wsq.shares      (id uuid primary key default gen_random_uuid(), shared_id uuid not null, user_id uuid not null, can_read boolean not null default false);
create table wsq.blocks      (id uuid primary key default gen_random_uuid(), blocked_id uuid not null);

-- outer (tested) tables
create table wsq.t_extracond (id uuid primary key default gen_random_uuid(), org_id uuid not null, body text);
create table wsq.t_twocorr   (id uuid primary key default gen_random_uuid(), a uuid not null, b uuid not null, body text);
create table wsq.t_in_subq   (id uuid primary key default gen_random_uuid(), body text);
create table wsq.t_notexists (id uuid primary key default gen_random_uuid(), body text);

do $$ declare r record; begin
  for r in select tablename from pg_tables where schemaname='wsq' loop
    execute format('alter table wsq.%I enable row level security', r.tablename);
    execute format('grant select, insert, update, delete on wsq.%I to authenticated, service_role', r.tablename);
  end loop;
end $$;

-- side-table read policies (so the EXISTS subqueries resolve as the calling role)
create policy self on wsq.memberships for select to authenticated using ( user_id = (select auth.uid()) );
create policy self on wsq.shares      for select to authenticated using ( user_id = (select auth.uid()) );
create policy readall on wsq.links    for select to authenticated using ( true );
create policy readall on wsq.blocks   for select to authenticated using ( true );

-- the WB-3 cases under test
-- extra condition in the membership subquery: only an ADMIN member is authorized
create policy p on wsq.t_extracond for select to authenticated
  using ( exists (select 1 from wsq.memberships m where m.org_id = t_extracond.org_id and m.user_id = (select auth.uid()) and m.role = 'admin') );
-- TWO correlations, no identity (row-based link table)
create policy p on wsq.t_twocorr for select to authenticated
  using ( exists (select 1 from wsq.links l where l.a = t_twocorr.a and l.b = t_twocorr.b) );
-- IN-subquery with a boolean filter
create policy p on wsq.t_in_subq for select to authenticated
  using ( id in (select shared_id from wsq.shares s where s.user_id = (select auth.uid()) and s.can_read) );
-- NOT EXISTS: visible unless the row is blocked
create policy p on wsq.t_notexists for select to authenticated
  using ( not exists (select 1 from wsq.blocks b where b.blocked_id = t_notexists.id) );
