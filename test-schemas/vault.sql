-- Schema #1: data rooms with a UNION-ALL share-validation function + a second owner-only policy.
-- Reproduced under schema `vault` (public.* -> vault.*). Grants mirror a realistic Supabase setup:
-- authenticated can use room_documents (the protected table) and SELECT data_rooms (the inline owner
-- EXISTS in the FOR ALL policy reads it as the caller). room_shares is read only by the DEFINER function.
drop schema if exists vault cascade;
create schema vault;
grant usage on schema vault to anon, authenticated, service_role;

create table vault.data_rooms (
    id uuid primary key default gen_random_uuid(),
    name text not null,
    owner_id uuid not null references auth.users(id)
);
create table vault.room_documents (
    id uuid primary key default gen_random_uuid(),
    room_id uuid not null references vault.data_rooms(id) on delete cascade,
    title text not null,
    secret_payload text not null
);
create table vault.room_shares (
    id uuid primary key default gen_random_uuid(),
    room_id uuid not null references vault.data_rooms(id) on delete cascade,
    grantee_email text not null,
    invited_by uuid not null references auth.users(id),
    expires_at timestamp with time zone not null,
    max_view_count int default 5,
    current_view_count int default 0,
    created_at timestamp with time zone default timezone('utc'::text, now()) not null
);

create or replace function vault.validate_room_share(target_room_id uuid)
returns boolean
language sql
security definer
set search_path = ''
stable
as $$
  select exists (
    select 1 from vault.data_rooms
    where id = target_room_id
      and owner_id = (select auth.uid())
    union all
    select 1 from vault.room_shares
    where room_id = target_room_id
      and lower(grantee_email) = lower((select auth.jwt() ->> 'email'))
      and expires_at > timezone('utc'::text, now())
      and current_view_count < max_view_count
  );
$$;

alter table vault.room_documents enable row level security;
grant select, insert, update, delete on vault.room_documents to authenticated, service_role;
grant select on vault.data_rooms to authenticated, service_role;

create policy "Viewable via valid share or ownership"
on vault.room_documents for select to authenticated
using ( (select vault.validate_room_share(room_id)) );

create policy "Only owners can modify documents"
on vault.room_documents for all to authenticated
using (
  exists (
    select 1 from vault.data_rooms
    where id = room_documents.room_id and owner_id = auth.uid()
  )
);
