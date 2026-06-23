-- Reproduction of the Discord RLS bug: UPDATE policies permit status transitions
-- beyond their own WITH CHECK, because PERMISSIVE policies OR their WITH CHECK
-- clauses independently of which policy's USING matched, and the role guard lives
-- ONLY in the USING clauses.  Faithful to the reported schema; refs point at orderbug.*
-- and one realistic SELECT policy is added so staff can read the queue (the app does).

drop schema if exists orderbug cascade;
create schema orderbug;
grant usage on schema orderbug to anon, authenticated, service_role;

create type orderbug.status_item_type as enum ('Queued','In Cutting','In Packaging','In Loading','Completed');
create type orderbug.role_type        as enum ('cutter','packager','loader','manager');
create type orderbug.d_type           as enum ('mm','inch');
create type orderbug.b_type           as enum ('soft','medium','hard');
create type orderbug.quan_type        as enum ('pieces','boxes');

-- profile carries the caller's role, keyed by auth.users id (readable, no RLS)
create table orderbug.profile (
  id   uuid primary key references auth.users(id) on delete cascade,
  role orderbug.role_type not null
);
grant select on orderbug.profile to anon, authenticated, service_role;

create table orderbug.orders (
  order_number integer primary key
);
grant select, insert, update, delete on orderbug.orders to authenticated, service_role;

create table orderbug.order_items (
  order_item_id  uuid primary key,
  order_number   integer references orderbug.orders on delete cascade,
  thickness      smallint not null,
  width          smallint not null,
  length         smallint not null,
  dimension_type orderbug.d_type not null,
  block_density  decimal  not null,
  block_type     orderbug.b_type not null,
  quantity       smallint not null,
  quantity_type  orderbug.quan_type not null,
  status         orderbug.status_item_type default 'Queued'
);
alter table orderbug.order_items enable row level security;
grant select, insert, update, delete on orderbug.order_items to authenticated, service_role;

-- realistic read access so any logged-in staff member can see the queue
create policy "Staff can read order items." on orderbug.order_items
  for select to authenticated using (true);

-- ===== the five UPDATE policies, verbatim logic from the report =====
create policy "Cutter can update order item status." on orderbug.order_items for update to authenticated using (
  status = any (array['Queued'::orderbug.status_item_type, 'In Cutting'::orderbug.status_item_type])
  and (select role from orderbug.profile where id = (select auth.uid())) = 'cutter'::orderbug.role_type
) with check (status = 'In Cutting'::orderbug.status_item_type);

create policy "Packager can update order item status." on orderbug.order_items for update to authenticated using (
  status = any (array['In Cutting'::orderbug.status_item_type, 'In Packaging'::orderbug.status_item_type])
  and (select role from orderbug.profile where id = (select auth.uid())) = 'packager'::orderbug.role_type
) with check (status = 'In Packaging'::orderbug.status_item_type);

create policy "Loader can update order item status." on orderbug.order_items for update to authenticated using (
  status = any (array['In Packaging'::orderbug.status_item_type, 'In Loading'::orderbug.status_item_type])
  and (select role from orderbug.profile where id = (select auth.uid())) = 'loader'::orderbug.role_type
) with check (status = 'In Loading'::orderbug.status_item_type);

create policy "Loader complete order item." on orderbug.order_items for update to authenticated using (
  status = any (array['In Loading'::orderbug.status_item_type, 'Completed'::orderbug.status_item_type])
  and (select role from orderbug.profile where id = (select auth.uid())) = 'loader'::orderbug.role_type
) with check (status = 'Completed'::orderbug.status_item_type);

create policy "Manager can update order item." on orderbug.order_items for update to authenticated using (
  status <> all (array['In Cutting','In Packaging','In Loading','Completed']::orderbug.status_item_type[])
  and (select role from orderbug.profile where id = (select auth.uid())) = 'manager'::orderbug.role_type
);

\echo === policies installed ===
select policyname, cmd, permissive, qual is not null as has_using, with_check is not null as has_check
from pg_policies where schemaname='orderbug' and tablename='order_items' order by policyname;
