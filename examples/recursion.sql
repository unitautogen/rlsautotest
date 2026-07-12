-- examples/recursion.sql
-- A VALID self-referential hierarchy RLS policy: the SAFE counterpart to exotic.folders' deliberate
-- 42P17 footgun. The policy walks the tree with WITH RECURSIVE from an owner = auth.uid() base, but
-- reads the table through a SECURITY DEFINER function so RLS is NOT re-entered (no "infinite recursion
-- detected in policy for relation nodes"). This is the canonical Supabase workaround.
--
-- Purpose in the corpus: exercise the recursion strategy (synth_recursion_emit) on a GREEN path. The
-- generator seeds an ancestor chain (a root owned by the user + a descendant under it) and probe-proves
-- that owning the root grants visibility of the descendant, a different user sees nothing, and anon is
-- blocked. Without this fixture the recursion emitter's happy path was only reachable via the broken
-- exotic.folders case (42P17), which is excluded from the CI green loop.

DROP SCHEMA IF EXISTS recursion CASCADE;
CREATE SCHEMA recursion;
GRANT USAGE ON SCHEMA recursion TO anon, authenticated, service_role;

CREATE TABLE recursion.nodes (
  id        bigint generated always as identity primary key,
  parent_id bigint references recursion.nodes(id),   -- self-referential FK: the hierarchy edge
  owner     uuid references auth.users,              -- nullable: a descendant need not be owned
  name      text
);
ALTER TABLE recursion.nodes ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON recursion.nodes TO authenticated, service_role;
-- deliberately NOT granted to anon: anon must be blocked at the grant layer (42501), proving denial.

-- SECURITY DEFINER read: returns every node with RLS bypassed. The recursive policy below reads the
-- tree through THIS function instead of the table directly, which is what stops the self-referential
-- policy from re-triggering itself (the 42P17 that exotic.folders demonstrates).
CREATE FUNCTION recursion.all_nodes()
  RETURNS SETOF recursion.nodes
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = recursion, pg_temp
AS $$
  SELECT * FROM recursion.nodes
$$;

-- You can SELECT a node iff you own it, or you own any ancestor of it (walk parent_id upward via the
-- descendants of the roots you own). auth.uid() is evaluated in the caller's context; only the table
-- read is delegated to the definer function.
CREATE POLICY node_tree ON recursion.nodes FOR SELECT TO authenticated USING (
  id IN (
    WITH RECURSIVE tree AS (
      SELECT n.id, n.parent_id
        FROM recursion.all_nodes() n
       WHERE n.owner = (select auth.uid())          -- base: the roots this user owns
      UNION
      SELECT c.id, c.parent_id
        FROM recursion.all_nodes() c
        JOIN tree t ON c.parent_id = t.id            -- step: their descendants
    )
    SELECT id FROM tree
  )
);
