-- checkfmt.sql - the POSITIVE counterpart to seedfail.sql. Every non-owner column here is gated ONLY by a
-- format / length CHECK the seeder can now satisfy BY CONSTRUCTION (a regex `~` including back-references, a
-- LIKE, or a char_length range): it reads the CHECK's parse tree, builds one conforming value, and lets the
-- seed probe confirm it. So the ordinary owner policy is genuinely testable (green) instead of UNRELIABLE. The
-- construction is only a candidate - the probe still INSERTs it and observes the real outcome, so a value that
-- did not actually satisfy the CHECK would simply re-fail and the cell would stay UNRELIABLE (never a false
-- pass). seedfail.sql keeps the other side of the line: a LOOK-AHEAD regex a construct-and-verify filler still
-- cannot build. Requires the auth shim + roles (auth.uid()/auth.users + anon/authenticated/service_role).

drop schema if exists checkfmt cascade;
create schema checkfmt;
grant usage on schema checkfmt to anon, authenticated, service_role;

create table checkfmt.docs (
  id       uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id),
  code     text not null check (code ~ '^[0-9]{10}$'),                 -- fixed-format regex (10 digits)
  sku      text not null check (sku  ~ '^[A-Z]{2}-[0-9]{4}$'),         -- structured regex (AA-0000)
  slug     text not null check (slug like 'doc-%'),                    -- LIKE prefix
  note     text not null check (char_length(note) between 5 and 40),   -- length range
  serial4  text not null check (serial4 ~ '^([0-9])\1{3}$'),           -- back-reference: four identical digits (now constructable)
  data     text not null
);
alter table checkfmt.docs enable row level security;
grant select, insert, update, delete on checkfmt.docs to authenticated, service_role;
create policy own on checkfmt.docs for all to authenticated
  using ( owner_id = (select auth.uid()) ) with check ( owner_id = (select auth.uid()) );