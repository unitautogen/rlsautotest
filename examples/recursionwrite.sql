-- RECURSION WRITE floor (schema rcw): MB-4. The self-referential-hierarchy floor previously ran for
-- SELECT only; a FOR ALL recursive policy left UPDATE/DELETE as untested dashes. Now the recursion
-- floor also acts on the visible tree for writes and bakes the observed pair (owning the root -> the
-- descendant is writable; a different user -> nothing; anon -> denied at the grant). INSERT stays a
-- deliberate NT: a recursive WITH CHECK can't be seeded soundly (the new row's parent must already be
-- in the tree). Mirrors examples/recursion.sql (definer read to avoid 42P17), but FOR ALL.
--   rcw.nodes  FOR ALL: act on a node iff you own it or own an ancestor of it.
-- Requires the auth shim + roles from examples/schema.sql.

DROP SCHEMA IF EXISTS rcw CASCADE;
CREATE SCHEMA rcw;
GRANT USAGE ON SCHEMA rcw TO anon, authenticated, service_role;

CREATE TABLE rcw.nodes (
  id        bigint generated always as identity primary key,
  parent_id bigint references rcw.nodes(id),
  owner     uuid references auth.users,
  name      text
);
ALTER TABLE rcw.nodes ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON rcw.nodes TO authenticated, service_role;
-- anon deliberately ungranted: writes must be blocked at the grant layer (42501).

CREATE FUNCTION rcw.all_nodes()
  RETURNS SETOF rcw.nodes
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = rcw, pg_temp
AS $$
  SELECT * FROM rcw.nodes
$$;

-- FOR ALL: you can act on a node iff you own it or own an ancestor of it.
CREATE POLICY node_tree ON rcw.nodes FOR ALL TO authenticated USING (
  id IN (
    WITH RECURSIVE tree AS (
      SELECT n.id, n.parent_id
        FROM rcw.all_nodes() n
       WHERE n.owner = (select auth.uid())
      UNION
      SELECT c.id, c.parent_id
        FROM rcw.all_nodes() c
        JOIN tree t ON c.parent_id = t.id
    )
    SELECT id FROM tree
  )
);
