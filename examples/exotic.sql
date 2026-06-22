DROP SCHEMA IF EXISTS exotic CASCADE;
CREATE SCHEMA exotic;
GRANT USAGE ON SCHEMA exotic TO anon, authenticated, service_role;

CREATE TYPE exotic.app_role AS ENUM ('admin','editor','viewer');
CREATE TYPE exotic.app_perm AS ENUM ('posts.update','posts.delete');
CREATE TABLE exotic.role_perms (role exotic.app_role, perm exotic.app_perm, primary key(role,perm));
INSERT INTO exotic.role_perms VALUES ('admin','posts.update'),('admin','posts.delete'),('editor','posts.update');
CREATE FUNCTION exotic.authorize(requested exotic.app_perm) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER AS $$
  SELECT EXISTS (SELECT 1 FROM exotic.role_perms WHERE perm = requested AND role = (auth.jwt()->>'user_role')::exotic.app_role);
$$;
CREATE TABLE exotic.posts (id bigint generated always as identity primary key, owner uuid references auth.users not null, title text);
ALTER TABLE exotic.posts ENABLE ROW LEVEL SECURITY;
GRANT SELECT,INSERT,UPDATE,DELETE ON exotic.posts TO authenticated, service_role; GRANT SELECT ON exotic.posts TO anon;
CREATE POLICY rbac_sel ON exotic.posts FOR SELECT USING (true);
CREATE POLICY rbac_upd ON exotic.posts FOR UPDATE TO authenticated USING (exotic.authorize('posts.update'));
CREATE POLICY rbac_del ON exotic.posts FOR DELETE TO authenticated USING (exotic.authorize('posts.delete'));

CREATE TABLE exotic.documents (id bigint generated always as identity primary key, org_id uuid not null, owner uuid references auth.users, title text);
ALTER TABLE exotic.documents ENABLE ROW LEVEL SECURITY;
GRANT SELECT,INSERT,UPDATE,DELETE ON exotic.documents TO authenticated, service_role;
CREATE POLICY doc_owner ON exotic.documents FOR ALL TO authenticated USING (owner = (select auth.uid())) WITH CHECK (owner = (select auth.uid()));
CREATE POLICY doc_tenant ON exotic.documents AS RESTRICTIVE FOR ALL TO authenticated USING (org_id = (auth.jwt()->'app_metadata'->>'org_id')::uuid);

CREATE TABLE exotic.projects (id bigint generated always as identity primary key, org_id uuid not null, name text);
ALTER TABLE exotic.projects ENABLE ROW LEVEL SECURITY;
GRANT SELECT,INSERT,UPDATE,DELETE ON exotic.projects TO authenticated, service_role; GRANT SELECT ON exotic.projects TO anon;
CREATE POLICY proj_member ON exotic.projects FOR SELECT TO authenticated USING (org_id::text = any (select jsonb_array_elements_text(auth.jwt()->'app_metadata'->'orgs')));

CREATE TABLE exotic.folders (id bigint generated always as identity primary key, parent_id bigint references exotic.folders(id), owner uuid references auth.users, name text);
ALTER TABLE exotic.folders ENABLE ROW LEVEL SECURITY;
GRANT SELECT,INSERT,UPDATE,DELETE ON exotic.folders TO authenticated, service_role;
CREATE POLICY folder_tree ON exotic.folders FOR SELECT TO authenticated USING (exists (with recursive tree as (select id from exotic.folders where owner = (select auth.uid()) union select f.id from exotic.folders f join tree t on f.parent_id=t.id) select 1 from tree where tree.id = folders.id));

CREATE TABLE exotic.items (id bigint generated always as identity primary key, tenant_id uuid not null, body text);
ALTER TABLE exotic.items ENABLE ROW LEVEL SECURITY;
GRANT SELECT,INSERT,UPDATE,DELETE ON exotic.items TO authenticated, service_role;
CREATE POLICY item_guc ON exotic.items FOR ALL TO authenticated USING (tenant_id = current_setting('app.tenant_id', true)::uuid) WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);