-- Stress test: a table with THREE FK parents, one of which (data_rooms) is also the membership/scope
-- table (the collision case I just fixed). The other two are plain parents (categories, auth.users).
drop schema if exists multifk cascade;
create schema multifk;
grant usage on schema multifk to anon, authenticated, service_role;

create table multifk.data_rooms (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  owner_id uuid not null references auth.users(id)
);
create table multifk.categories (
  id uuid primary key default gen_random_uuid(),
  label text not null
);
create table multifk.tasks (
  id uuid primary key default gen_random_uuid(),
  room_id uuid not null references multifk.data_rooms(id) on delete cascade,   -- scope + FK parent
  category_id uuid not null references multifk.categories(id),                  -- plain FK parent
  assignee_id uuid not null references auth.users(id),                          -- plain FK parent (same target as data_rooms.owner_id -> auth.users)
  title text not null
);
alter table multifk.tasks enable row level security;
grant select, insert, update, delete on multifk.tasks to authenticated, service_role;
grant select on multifk.data_rooms to authenticated, service_role;

create policy "room owners manage tasks" on multifk.tasks for all to authenticated
using ( exists (select 1 from multifk.data_rooms where id = tasks.room_id and owner_id = auth.uid()) );
