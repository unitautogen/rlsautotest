-- Demo: an RLS policy that LOOKS owner-scoped but isn't.
-- Intent: "a user sees only their OWN active documents."
-- Bug: the OR makes `status = 'active'` a STANDALONE grant, so every authenticated user reads
--      every active document. The fix is one word: OR -> AND.
-- Loads against a Supabase-shim DB (auth.uid()/auth.users + anon/authenticated/service_role).
drop schema if exists demo cascade;
create schema demo;
grant usage on schema demo to anon, authenticated, service_role;

create table demo.documents (
  id       uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id),
  status   text not null default 'active',   -- 'active' | 'archived'
  body     text
);
alter table demo.documents enable row level security;
grant select, insert, update, delete on demo.documents to authenticated, service_role;

-- BUGGY policy (as shipped here): owner OR active
create policy documents_select on demo.documents for select to authenticated
  using ( owner_id = (select auth.uid()) or status = 'active' );

-- THE FIX (apply to flip the matrix):
-- alter policy documents_select on demo.documents
--   using ( owner_id = (select auth.uid()) and status = 'active' );
