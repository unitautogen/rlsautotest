# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""Bypass-surface detection (lint codes L011-L015): objects and roles that sidestep RLS.

Pure catalog analysis (no probing). Structure: the DECISION for each object is a pure function of catalog
FACTS (classify_view / classify_function / classify_role / classify_force), and a thin SQL layer gathers
those facts and calls them. That split makes every outcome unit-testable without a live database. Findings
use the same (code, severity, object, detail, message) tuple shape as lint._lint_table, so cmd_lint prints /
sorts / gates them uniformly. See BYPASS_PATHS_BACKLOG.md.
"""
from __future__ import annotations
import re

# Roles allowed to bypass RLS by design (Supabase service_role + platform / superuser plumbing). The rest -> L014.
_SANCTIONED_BYPASS = {
    "service_role", "postgres", "supabase_admin", "supabase_auth_admin", "supabase_storage_admin",
    "supabase_replication_admin", "supabase_read_only_user", "authenticator", "pgbouncer",
    "rds_superuser", "rds_ad", "rdsadmin", "dashboard_user",
}
_CLIENT_ROLES = ("anon", "authenticated")


def _worst(roles):
    """The highest-privilege reaching client role (anon outranks authenticated); drives severity."""
    return "anon" if "anon" in roles else ("authenticated" if roles else None)


def finding_type(code, message):
    """Human object type for a bypass finding, derived from its code (and message for view vs matview)."""
    if code in ("L011", "L011b"):
        return "materialized view" if "materialized view" in (message or "") else "view"
    if code in ("L012", "L013"):
        return "function"
    if code == "L014":
        return "role"
    if code == "L015":
        return "table"
    return ""


# ============================================================================================
# PURE CLASSIFIERS — decision = f(facts). No DB access; unit-tested directly.
# ============================================================================================

def classify_view(name, relkind, definer, readers, rls_tables, reads_view):
    """A view/matview finding, or None.
      definer     : runs with owner's rights (security_invoker off, or a matview)
      readers     : client roles that can SELECT it (anon-first); [] = unreachable
      rls_tables  : RLS-enabled base tables it reads directly
      reads_view  : does it read another view (an unresolved view-on-view chain)?
    A definer view is a leak ONLY if a client can read it AND it reaches an RLS table. A definer view over
    only non-RLS base tables is NOT a bypass (nothing to bypass) -> None. A client-readable definer view we
    can't resolve past an inner view -> L011b (review)."""
    if not definer or not readers:
        return None
    kind = "materialized view" if relkind == "m" else "view"
    worst = _worst(readers)
    if rls_tables:
        sev = "CRITICAL" if worst == "anon" else "HIGH"
        return ("L011", sev, name, None,
                f"{kind} runs with owner's rights (security_invoker off) and is readable by {worst}; it reads "
                f"RLS-protected {', '.join(rls_tables)}, so their RLS is bypassable through this {kind}. "
                f"Set security_invoker=on, or revoke the {worst} grant.")
    if reads_view:
        return ("L011b", "MEDIUM", name, None,
                f"{kind} runs with owner's rights and is readable by {worst}, and it reads through another view "
                f"whose RLS tables couldn't be resolved here. Review the chain; consider security_invoker=on.")
    return None   # definer, client-readable, but over only non-RLS base tables -> not a bypass


def classify_function(sig, callers, opaque, rls_hits, mutable_sp):
    """SECURITY DEFINER function findings (list; may hold L012 and/or L013).
      callers    : client roles that can EXECUTE it (anon-first); [] = unreachable
      opaque     : body can't be read (non-SQL language / dynamic SQL) -> can't prove what it touches
      rls_hits   : RLS tables its body references (best-effort)
      mutable_sp : no `SET search_path` pinned
    L012 fires when a client can call it AND (it touches an RLS table OR its body is opaque). A transparent
    SQL function that provably touches no RLS table is NOT flagged (nothing bypassed). L013 fires on ANY
    SECURITY DEFINER function with a mutable search_path (Supabase's function_search_path_mutable)."""
    out = []
    if callers:
        worst = _worst(callers)
        if rls_hits:
            sev = "CRITICAL" if worst == "anon" else "HIGH"
            out.append(("L012", sev, sig, None,
                f"SECURITY DEFINER function is EXECUTE-able by {worst}; it runs as its owner and bypasses the "
                f"caller's RLS; reads/writes RLS-protected {', '.join(sorted(set(rls_hits)))}."))
        elif opaque:
            sev = "HIGH" if worst == "anon" else "MEDIUM"
            out.append(("L012", sev, sig, None,
                f"SECURITY DEFINER function is EXECUTE-able by {worst}; it runs as its owner and bypasses the "
                f"caller's RLS, and its body is opaque (could reach RLS data). Review that it re-checks auth."))
        # else: transparent SQL function touching no RLS table -> not an RLS bypass, no L012.
    if mutable_sp:
        out.append(("L013", "HIGH" if callers else "MEDIUM", sig, None,
            "SECURITY DEFINER function has a mutable search_path (search-path injection risk). "
            "Pin it: ALTER FUNCTION ... SET search_path = ''."))
    return out


def classify_role(rolname, issuper, bypassrls, reachable, allow):
    """A role finding, or None. `allow` = sanctioned-bypass role names (service_role + platform + user allowlist).
    reachable = the role is a client role, can LOGIN, or a client can SET ROLE into it."""
    if rolname in allow:
        return None
    why = "a superuser" if issuper else "BYPASSRLS"
    return ("L014", "CRITICAL" if reachable else "HIGH", rolname, None,
        f"role is {why} and bypasses RLS but is not a sanctioned bypass role"
        + (" and is client-reachable (login / client role / SET ROLE-able by a client)" if reachable else "")
        + ". Confirm it should have this, revoke it, or pass --allow-bypass-role.")


def classify_force(relname, owner, owner_is_super, owner_login):
    """An RLS-on-but-not-FORCED table finding, or None. A superuser owner bypasses regardless of FORCE (that's
    the L014 story), so it's not an L015 here; a non-superuser owner bypasses ONLY because FORCE is off."""
    if owner_is_super:
        return None
    sev = "HIGH" if (owner in _CLIENT_ROLES or owner_login) else "MEDIUM"
    return ("L015", sev, relname, None,
        f"RLS is enabled but not FORCED and the owner ({owner}) is not a superuser, so the owner bypasses this "
        f"table's RLS. Add: ALTER TABLE ... FORCE ROW LEVEL SECURITY.")


# ============================================================================================
# SQL FACT-GATHERERS
# ============================================================================================

def _present_client_roles(cur):
    cur.execute("SELECT rolname FROM pg_roles WHERE rolname = ANY(%s)", (list(_CLIENT_ROLES),))
    return [r[0] for r in cur.fetchall()]


def _schema_usable_by(cur, schema, roles):
    out = {}
    for role in roles:
        cur.execute("SELECT has_schema_privilege(%s, %s, 'USAGE')", (role, schema))
        out[role] = bool(cur.fetchone()[0])
    return out


def _readers(cur, oid, roles, usable):
    out = []
    for role in roles:
        if not usable.get(role):
            continue
        cur.execute("SELECT has_table_privilege(%s, %s, 'SELECT')", (role, oid))
        if cur.fetchone()[0]:
            out.append(role)
    return out


def _callers(cur, oid, roles, usable):
    out = []
    for role in roles:
        if not usable.get(role):
            continue
        cur.execute("SELECT has_function_privilege(%s, %s, 'EXECUTE')", (role, oid))
        if cur.fetchone()[0]:
            out.append(role)
    return out


def _view_rls_tables(cur, view_oid):
    """RLS-enabled base tables a view reads directly (its ON SELECT rewrite rule -> pg_depend refs)."""
    cur.execute("""
        SELECT DISTINCT n.nspname || '.' || t.relname
        FROM pg_depend d
        JOIN pg_rewrite rw ON rw.oid = d.objid AND rw.ev_type = '1'
        JOIN pg_class   t  ON t.oid  = d.refobjid AND t.relkind IN ('r','p')
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE d.refclassid = 'pg_class'::regclass AND d.classid = 'pg_rewrite'::regclass
          AND rw.ev_class = %s AND t.oid <> %s AND t.relrowsecurity
        ORDER BY 1""", (view_oid, view_oid))
    return [r[0] for r in cur.fetchall()]


def _view_reads_view(cur, view_oid):
    """Does the view read another view/matview (an unresolved view-on-view chain)?"""
    cur.execute("""SELECT EXISTS(
        SELECT 1 FROM pg_depend d
        JOIN pg_rewrite rw ON rw.oid = d.objid AND rw.ev_type = '1'
        JOIN pg_class   t  ON t.oid  = d.refobjid AND t.relkind IN ('v','m')
        WHERE d.refclassid = 'pg_class'::regclass AND d.classid = 'pg_rewrite'::regclass
          AND rw.ev_class = %s AND t.oid <> %s)""", (view_oid, view_oid))
    return bool(cur.fetchone()[0])


def _client_can_setrole(cur, target, client_roles):
    if not client_roles:
        return False
    cur.execute("""SELECT EXISTS(
        SELECT 1 FROM pg_auth_members am
        JOIN pg_roles m ON m.oid = am.member
        JOIN pg_roles t ON t.oid = am.roleid
        WHERE t.rolname = %s AND m.rolname = ANY(%s))""", (target, list(client_roles)))
    return bool(cur.fetchone()[0])


def find_bypass(cur, schema, allow_roles=None):
    """Gather catalog facts for a schema and run the pure classifiers -> all bypass-surface findings."""
    allow = set(_SANCTIONED_BYPASS) | set(allow_roles or [])
    roles = _present_client_roles(cur)
    usable = _schema_usable_by(cur, schema, roles) if roles else {}
    findings = []

    # views / matviews
    cur.execute("""
        SELECT c.oid, c.relname, c.relkind,
               (c.relkind = 'm' OR NOT COALESCE(EXISTS(
                    SELECT 1 FROM unnest(c.reloptions) o
                    WHERE lower(o) IN ('security_invoker=on','security_invoker=true')), false)) AS definer
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = %s AND c.relkind IN ('v','m') ORDER BY c.relname""", (schema,))
    for oid, name, relkind, definer in cur.fetchall():
        readers = _readers(cur, oid, roles, usable) if definer else []
        rls_tables = _view_rls_tables(cur, oid) if (definer and readers) else []
        reads_view = _view_reads_view(cur, oid) if (definer and readers and not rls_tables) else False
        f = classify_view(name, relkind, definer, readers, rls_tables, reads_view)
        if f:
            findings.append(f)

    # SECURITY DEFINER functions
    cur.execute("""
        SELECT p.oid, p.proname, pg_get_function_identity_arguments(p.oid),
               (p.proconfig IS NULL OR NOT EXISTS(
                    SELECT 1 FROM unnest(p.proconfig) cfg WHERE cfg LIKE 'search\\_path=%%')) AS mutable_sp,
               l.lanname, p.prosrc
        FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace JOIN pg_language l ON l.oid = p.prolang
        WHERE n.nspname = %s AND p.prosecdef ORDER BY p.proname""", (schema,))
    secdef = cur.fetchall()
    cur.execute("""SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                   WHERE n.nspname = %s AND c.relkind = 'r' AND c.relrowsecurity""", (schema,))
    rls_names = [r[0] for r in cur.fetchall()]
    for oid, name, args, mutable_sp, lang, src in secdef:
        callers = _callers(cur, oid, roles, usable)
        hits = [t for t in rls_names if src and re.search(r'\b' + re.escape(t) + r'\b', src)]
        findings.extend(classify_function(f"{name}({args})", callers, lang != "sql", hits, mutable_sp))

    # roles that bypass RLS
    cur.execute("""SELECT rolname, rolsuper, rolbypassrls, rolcanlogin FROM pg_roles
                   WHERE (rolsuper OR rolbypassrls) AND rolname NOT LIKE 'pg\\_%%' ORDER BY rolname""")
    for rolname, issuper, bypassrls, canlogin in cur.fetchall():
        reachable = (rolname in _CLIENT_ROLES) or canlogin or _client_can_setrole(cur, rolname, roles)
        f = classify_role(rolname, issuper, bypassrls, reachable, allow)
        if f:
            findings.append(f)

    # RLS-on tables missing FORCE
    cur.execute("""SELECT c.relname, pg_get_userbyid(c.relowner), r.rolsuper, r.rolcanlogin
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_roles r ON r.oid = c.relowner
        WHERE c.relkind = 'r' AND n.nspname = %s AND c.relrowsecurity AND NOT c.relforcerowsecurity
        ORDER BY c.relname""", (schema,))
    for relname, owner, owner_super, owner_login in cur.fetchall():
        f = classify_force(relname, owner, owner_super, owner_login)
        if f:
            findings.append(f)

    return findings
