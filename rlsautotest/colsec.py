# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""Column-level security surface, by the SAME principle as the row-level leak: we do NOT judge whether a
grant is right or wrong, and we make NO assumption about which columns are "sensitive". We flag exactly ONE
thing -- a CONTRADICTION the developer did not intend:

    a column-specific GRANT expresses "scope this command to these columns"
    ...but a BROADER grant (table-wide, or inherited) lets the role act on columns OUTSIDE that list.

That is the column analogue of the cross-policy WITH CHECK leak: a restriction expressed in one place,
silently defeated by a wider grant union-ing in. When NO column-specific grant exists we say nothing -- a
bare table-wide grant is a choice, not a leak.

Postgres has column-level privileges for SELECT / INSERT / UPDATE (and REFERENCES); DELETE is whole-row, so
it has no column granularity (shown as n/a by the report). Intent (the column grant) is read from
pg_attribute.attacl via aclexplode; the EFFECTIVE set is has_column_privilege, which folds in table-wide and
inherited grants. leaked = effective - granted.

Structure mirrors bypass.py: the DECISION is a pure function of facts (cell_facts), a thin SQL layer gathers
the facts (column_security), so every outcome is unit-testable without a live database.
"""
from __future__ import annotations

# Column-grantable DML commands (DELETE is whole-row -> no column-level privilege in Postgres).
COL_CMDS = ("SELECT", "INSERT", "UPDATE")
_STD_CLIENT_ROLES = ("service_role", "authenticated", "anon")


# ============================================================================================
# PURE CLASSIFIER -- decision = f(facts). No DB access; unit-tested directly.
# ============================================================================================

def cell_facts(granted, effective):
    """The renderer-facing decision for ONE (role, command) column cell, from two pure facts:
        granted   : columns the role holds an EXPLICIT column-level grant on (its expressed scope)
        effective : columns the role can ACTUALLY act on (has_column_privilege -- table-wide/inherited folded in)
    Returns {kind, granted, leaked}:
        kind='unscoped' : no column-level grant -> no intent expressed -> stay silent (a bare table-wide
                          grant is a choice, not a leak)
        kind='scoped'   : a column grant is in force and effective == granted -> the scope holds (green;
                          `granted` is the permission given)
        kind='leak'     : a column grant is in force but effective is a strict superset of granted -> a
                          broader grant bypasses it (red; `leaked` = the columns that slipped past the scope)
    leaked preserves catalog column order."""
    S = set(granted or ())
    if not S:
        return {"kind": "unscoped", "granted": [], "leaked": []}
    leaked = [c for c in (effective or ()) if c not in S]
    if leaked:
        return {"kind": "leak", "granted": list(granted), "leaked": leaked}
    return {"kind": "scoped", "granted": list(granted), "leaked": []}


# ============================================================================================
# pgTAP ASSERTION BUILDER -- one parity assertion per column-scoped cell (pure string builders).
# ============================================================================================

def _sql_lit(s):
    """A SQL single-quoted string literal (doubles embedded quotes)."""
    return "'" + str(s).replace("'", "''") + "'"


def _cls_count_expr(schema, table, role, cmd):
    """SQL scalar (int): how many columns `role` can act on for `cmd` that lie OUTSIDE its own
    column-grant -- i.e. effective (has_column_privilege) minus column-granted (attacl). 0 means the
    column scope holds; >0 means a BROADER grant (table-wide / inherited) reaches past the column grant.
    Re-derived live from the catalog so a legitimate change to the column grant moves both sides together;
    only a grant that exceeds the column grant makes it non-zero."""
    role_oid = f"(SELECT oid FROM pg_roles WHERE rolname={_sql_lit(role)})"
    return (
        "(SELECT count(*)::int FROM pg_attribute a "
        "JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace "
        f"WHERE n.nspname={_sql_lit(schema)} AND c.relname={_sql_lit(table)} "
        "AND a.attnum>0 AND NOT a.attisdropped "
        f"AND has_column_privilege({_sql_lit(role)}, c.oid, a.attname, {_sql_lit(cmd)}) "
        f"AND NOT EXISTS (SELECT 1 FROM aclexplode(a.attacl) ae "
        f"WHERE ae.grantee={role_oid} AND ae.privilege_type={_sql_lit(cmd)}))"
    )


def cls_assertions(schema, table, cells):
    """One pgTAP assertion per (role, cmd) that HAS a column grant (a scoped or leak cell): assert the
    column scope holds -- zero columns reachable beyond the column grant. Passes for a scoped cell, FAILS
    (naming the emit-time leak) for a leak cell. It reads the SAME has_column_privilege fact the report's
    CLS cell is computed from, so the report grid and the emitted suite can never disagree. Returns
    [{role, cmd, kind, sql}]; DELETE and unscoped cells produce nothing."""
    out = []
    for role, cmds in (cells or {}).items():
        for cmd in COL_CMDS:
            cell = (cmds or {}).get(cmd) or {}
            kind = cell.get("kind")
            if kind not in ("scoped", "leak"):
                continue
            granted = cell.get("granted", [])
            gtxt = ", ".join(granted) if granted else "(none)"
            msg = (f"CLS: {role} {cmd} on {schema}.{table} is column-scoped to [{gtxt}]; "
                   f"no column beyond that grant may be reachable (a broader grant would leak it)")
            if kind == "leak":
                msg += " [emit-time leak: " + ", ".join(cell.get("leaked", [])) + "]"
            out.append({"role": role, "cmd": cmd, "kind": kind,
                        "sql": f"SELECT is( {_cls_count_expr(schema, table, role, cmd)}, 0, {_sql_lit(msg)} );"})
    return out


# ============================================================================================
# SQL FACT-GATHERER
# ============================================================================================

def _present_roles(cur, roles):
    cur.execute("SELECT rolname FROM pg_roles WHERE rolname = ANY(%s)", (list(roles),))
    have = {r[0] for r in cur.fetchall()}
    return [r for r in roles if r in have]   # preserve caller order


def _table_columns(cur, schema, table):
    cur.execute("""SELECT a.attname FROM pg_attribute a
        JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = %s AND c.relname = %s AND a.attnum > 0 AND NOT a.attisdropped
        ORDER BY a.attnum""", (schema, table))
    return [r[0] for r in cur.fetchall()]


def _granted_columns(cur, schema, table, role, cmd):
    """Columns carrying an EXPLICIT column-level grant of `cmd` to `role` -- pg_attribute.attacl via
    aclexplode. This is the developer's expressed scoping: a table-wide grant lives in pg_class.relacl and
    leaves attacl NULL, so it does NOT appear here (that is the whole point -- a bare table-wide grant
    expresses no column intent)."""
    cur.execute("""SELECT a.attname
        FROM pg_attribute a
        JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
        CROSS JOIN LATERAL aclexplode(a.attacl) ae
        WHERE n.nspname = %s AND c.relname = %s AND a.attnum > 0 AND NOT a.attisdropped
          AND a.attacl IS NOT NULL
          AND ae.privilege_type = %s
          AND ae.grantee = (SELECT oid FROM pg_roles WHERE rolname = %s)
        ORDER BY a.attnum""", (schema, table, cmd, role))
    return [r[0] for r in cur.fetchall()]


def _effective_columns(cur, schema, table, role, cmd):
    """Columns the role can ACTUALLY act on for `cmd` (has_column_privilege = the EFFECTIVE answer: a
    table-wide grant makes every column true, and inherited grants are folded in)."""
    cur.execute("""SELECT a.attname FROM pg_attribute a
        JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = %s AND c.relname = %s AND a.attnum > 0 AND NOT a.attisdropped
          AND has_column_privilege(%s, c.oid, a.attname, %s)
        ORDER BY a.attnum""", (schema, table, role, cmd))
    return [r[0] for r in cur.fetchall()]


def column_security(cur, schema, table, roles=None):
    """Gather the column-level surface for a table, by role and command:
        {"columns": [all columns in order],
         "cells":   {role: {cmd: {kind, granted, leaked}}}}   for cmd in SELECT / INSERT / UPDATE.
    `roles` defaults to the standard client roles; pass extra (custom) role names to include them."""
    want = list(roles) if roles else list(_STD_CLIENT_ROLES)
    present = _present_roles(cur, want)
    columns = _table_columns(cur, schema, table)
    cells = {}
    for role in present:
        cells[role] = {}
        for cmd in COL_CMDS:
            granted = _granted_columns(cur, schema, table, role, cmd)
            effective = _effective_columns(cur, schema, table, role, cmd)
            cells[role][cmd] = cell_facts(granted, effective)
    return {"columns": columns, "cells": cells}
