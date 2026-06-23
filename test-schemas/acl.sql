-- Faithful reproduction of the user's complex SECURITY DEFINER RBAC function + documents policies.
-- Reproduced under schema `acl` (public.* -> acl.*) so it doesn't touch the shared public schema.
drop schema if exists acl cascade;
create schema acl;
grant usage on schema acl to anon, authenticated, service_role;

create table acl.organizations (
    id uuid primary key default gen_random_uuid(),
    name text not null,
    created_at timestamptz default now() not null
);
create table acl.projects (
    id uuid primary key default gen_random_uuid(),
    organization_id uuid not null references acl.organizations(id) on delete cascade,
    name text not null,
    created_at timestamptz default now() not null
);
create table acl.organization_members (
    id uuid primary key default gen_random_uuid(),
    organization_id uuid not null references acl.organizations(id) on delete cascade,
    user_id uuid not null references auth.users(id) on delete cascade,
    role text not null check (role in ('org_admin', 'org_member')),
    created_at timestamptz default now() not null,
    unique (organization_id, user_id)
);
create table acl.project_members (
    id uuid primary key default gen_random_uuid(),
    organization_id uuid not null references acl.organizations(id) on delete cascade,
    project_id uuid not null references acl.projects(id) on delete cascade,
    user_id uuid not null references auth.users(id) on delete cascade,
    role text not null check (role in ('viewer', 'editor', 'manager')),
    created_at timestamptz default now() not null,
    unique (project_id, user_id)
);
create table acl.documents (
    id uuid primary key default gen_random_uuid(),
    project_id uuid not null references acl.projects(id) on delete cascade,
    title text not null,
    content text,
    created_at timestamptz default now() not null
);

create or replace function acl.check_user_project_access(
    target_project_id uuid,
    required_roles text[]
)
returns boolean
language sql
security definer
set search_path = ''
stable
as $$
  select exists (
    select 1
    from acl.project_members pm
    join acl.organization_members om on om.organization_id = pm.organization_id
    where om.user_id = (select auth.uid())
      and pm.id = target_project_id
      and (
        om.role = 'org_admin'
        or pm.role = any(required_roles)
      )
  );
$$;

alter table acl.documents enable row level security;
grant select, insert, update, delete on acl.documents to authenticated, service_role;

create policy "Employees can view project documents"
on acl.documents for select to authenticated
using ( (select acl.check_user_project_access(project_id, array['viewer', 'editor', 'manager'])) );

create policy "Editors can update documents within valid project scopes"
on acl.documents for update to authenticated
using ( (select acl.check_user_project_access(project_id, array['editor', 'manager'])) )
with check ( (select acl.check_user_project_access(project_id, array['editor', 'manager'])) );

create policy "Editors can insert new project documents"
on acl.documents for insert to authenticated
with check ( (select acl.check_user_project_access(project_id, array['editor', 'manager'])) );
