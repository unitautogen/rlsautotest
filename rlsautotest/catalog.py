# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""Postgres catalog loaders: columns, FKs, constraints, grants, RLS table discovery.

Split out of the original single-module cli.py; behavior-preserving.
"""
from __future__ import annotations
import argparse, json, re, sys
import psycopg
from pglast.parser import parse_sql_json
from .astutil import _CMDS4, _and_conjuncts, _array_consts, _colname, _const, _list_consts, _names, _t, _unwrap, _v, _where



# ---------- catalog helpers (self-contained; no external module deps) ----------
def _columns(cur, schema, table):
    cur.execute("""
        SELECT a.attname, format_type(a.atttypid, a.atttypmod),
               a.attnotnull, (a.atthasdef OR a.attidentity <> '') AS hasdef
        FROM pg_attribute a
        JOIN pg_class c ON c.oid = a.attrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname=%s AND c.relname=%s AND a.attnum>0 AND NOT a.attisdropped
        ORDER BY a.attnum""", (schema, table))
    return cur.fetchall()



def _fk_of(cur, schema, table, col):
    cur.execute("""
        SELECT nf.nspname, cf.relname, af.attname
        FROM pg_constraint k
        JOIN pg_class c   ON c.oid  = k.conrelid
        JOIN pg_namespace n  ON n.oid  = c.relnamespace
        JOIN pg_class cf  ON cf.oid = k.confrelid
        JOIN pg_namespace nf ON nf.oid = cf.relnamespace
        JOIN pg_attribute a  ON a.attrelid = k.conrelid  AND a.attnum  = k.conkey[1]
        JOIN pg_attribute af ON af.attrelid = k.confrelid AND af.attnum = k.confkey[1]
        WHERE n.nspname=%s AND c.relname=%s AND k.contype='f'
              AND array_length(k.conkey,1)=1 AND a.attname=%s
        LIMIT 1""", (schema, table, col))
    return cur.fetchone()



def _check_seed_meta(cdef):
    """One CHECK definition -> the first seedable fact in it (AST, no regex on SQL):
      ("col", value)            for  col = 'str'  /  col = ANY(ARRAY['a',...])  /  col IN ('a',...)
      or a relcheck tuple       for  a <op> b     (cross-column / column-vs-integer comparison)
    Mirrors the old regex semantics: string-valued equalities only, first match wins."""
    body = cdef or ""
    if body.upper().startswith("CHECK"):
        body = body[5:].strip()
    w = _where(body)
    if w is None:
        return None, None
    conjs = _and_conjuncts(w)
    if conjs is None:
        conjs = [w]
    rel = None
    for cj in conjs:
        if _t(cj) != "A_Expr":
            continue
        op = _names(_v(cj).get("name"))
        l, r = _v(cj).get("lexpr"), _v(cj).get("rexpr")
        if op == "=":
            for a, b in ((l, r), (r, l)):
                col = _colname(a)
                if not col:
                    continue
                bu = _unwrap(b)
                if _t(bu) == "A_Const" and "sval" in _v(bu):            # col = 'string'
                    return (col, _v(bu)["sval"].get("sval", "")), None
                vals = _array_consts(b) or _list_consts(b)              # col = ANY(ARRAY[...]) / IN (...)
                if vals and isinstance(vals[0], str):
                    return (col, vals[0]), None
        elif op in ("<", "<=", ">", ">=") and rel is None:
            a = _colname(l); b = _colname(r)
            if a is None and _const(l) is not None and str(_const(l)).lstrip("-").isdigit(): a = str(_const(l))
            if b is None and _const(r) is not None and str(_const(r)).lstrip("-").isdigit(): b = str(_const(r))
            if a and b:
                rel = (a, op, b)   # cross-column comparison (both sides resolved to columns at fill time)
    return None, rel


def _constraint_meta(cur, schema, table):
    """Per-table constraint metadata for seeding:
      checks    {col: 'literal'}            -- value-set CHECK (role/status) -> a CHECK-satisfying value
      cuniques  [[cols], ...]               -- composite UNIQUE/PK col-sets -> keep seeded rows distinct
      relchecks [(colA, op, colB), ...]     -- cross-column CHECK (lo < hi) -> fill an ordered pair
      compfks   [{cols, parent, pcols}, ...]-- composite FK -> seed the composite parent tuple"""
    cur.execute("""
        SELECT c.contype, pg_get_constraintdef(c.oid),
               (SELECT array_agg(a.attname ORDER BY k.ord) FROM unnest(c.conkey)  WITH ORDINALITY k(attnum, ord) JOIN pg_attribute a ON a.attrelid = c.conrelid  AND a.attnum = k.attnum),
               (SELECT array_agg(a.attname ORDER BY k.ord) FROM unnest(c.confkey) WITH ORDINALITY k(attnum, ord) JOIN pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = k.attnum),
               (SELECT n2.nspname || '.' || r2.relname FROM pg_class r2 JOIN pg_namespace n2 ON n2.oid = r2.relnamespace WHERE r2.oid = c.confrelid)
        FROM pg_constraint c
        JOIN pg_class r ON r.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = r.relnamespace
        WHERE n.nspname = %s AND r.relname = %s AND c.contype IN ('c', 'u', 'p', 'f')""", (schema, table))
    checks, cuniques, relchecks, compfks = {}, [], [], []
    for (contype, cdef, cols, fcols, parent) in cur.fetchall():
        if contype == 'c':
            # F6: read the CHECK definition's parse tree, not regexes over its text — a cast-wrapped
            # column ((status)::text = 'live') no longer mis-files the value under the CAST NAME
            # ("text"), which left the real column unfilled and the seed row failing its own CHECK.
            ck, rel = _check_seed_meta(cdef)
            if ck:
                checks[ck[0]] = "'" + str(ck[1]).replace("'", "''") + "'"
            elif rel:
                relchecks.append(rel)
        elif contype in ('u', 'p') and cols and len(cols) > 1:
            cuniques.append(list(cols))
        elif contype == 'f' and cols and len(cols) > 1 and parent and fcols:
            compfks.append({"cols": list(cols), "parent": parent, "pcols": list(fcols)})
    return checks, cuniques, relchecks, compfks



def _fk_by_name(cur, cname):
    """Resolve a FK constraint (by name) -> {parent: 'schema.table', cols: [...], pcols: [...]}. Composite-aware."""
    cur.execute("""SELECT (SELECT n.nspname||'.'||r.relname FROM pg_class r JOIN pg_namespace n ON n.oid=r.relnamespace WHERE r.oid=c.confrelid),
                          (SELECT array_agg(a.attname ORDER BY k.ord) FROM unnest(c.conkey)  WITH ORDINALITY k(an,ord) JOIN pg_attribute a ON a.attrelid=c.conrelid  AND a.attnum=k.an),
                          (SELECT array_agg(a.attname ORDER BY k.ord) FROM unnest(c.confkey) WITH ORDINALITY k(an,ord) JOIN pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.an)
                   FROM pg_constraint c WHERE c.conname=%s AND c.contype='f' LIMIT 1""", (cname,))
    r = cur.fetchone()
    return {"parent": r[0], "cols": list(r[1]), "pcols": list(r[2])} if r and r[0] else None



def _check_bool_udfs(cur, cname):
    """Boolean UDFs the named CHECK constraint actually calls -> [(qualified_signature, original_functiondef)].
    Resolved EXACTLY via pg_depend (the constraint's recorded dependency on the function) so a same-named
    function in a different schema is never picked by mistake; falls back to schema-aware parsing of the def.
    These can be neutralized (replaced with SELECT true) to seed past a function-delegated CHECK, then restored."""
    cur.execute("""SELECT n.nspname, p.proname, pg_get_function_identity_arguments(p.oid), pg_get_functiondef(p.oid)
                   FROM pg_constraint c
                   JOIN pg_depend d ON d.classid='pg_constraint'::regclass AND d.objid=c.oid AND d.refclassid='pg_proc'::regclass
                   JOIN pg_proc p ON p.oid=d.refobjid
                   JOIN pg_namespace n ON n.oid=p.pronamespace
                   JOIN pg_type t ON t.oid=p.prorettype
                   WHERE c.conname=%s AND c.contype='c' AND t.typname='bool' AND n.nspname NOT IN ('pg_catalog','information_schema')""", (cname,))
    out = [(f"{nsp}.{pname}({args})", fdef) for (nsp, pname, args, fdef) in cur.fetchall()]
    if out: return out
    cur.execute("SELECT pg_get_constraintdef(oid), connamespace::regnamespace::text FROM pg_constraint WHERE conname=%s AND contype='c' LIMIT 1", (cname,))
    r = cur.fetchone()
    if not r or not r[0]: return []
    cdef, conschema = r[0], r[1]
    for sch, fn in set(re.findall(r"(?:([a-zA-Z_]\w*)\.)?([a-zA-Z_]\w*)\s*\(", cdef)):
        if sch:
            cur.execute("SELECT n.nspname,p.proname,pg_get_function_identity_arguments(p.oid),pg_get_functiondef(p.oid) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_type t ON t.oid=p.prorettype WHERE n.nspname=%s AND p.proname=%s AND t.typname='bool' LIMIT 1", (sch, fn))
        else:
            cur.execute("SELECT n.nspname,p.proname,pg_get_function_identity_arguments(p.oid),pg_get_functiondef(p.oid) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_type t ON t.oid=p.prorettype WHERE p.proname=%s AND t.typname='bool' AND n.nspname=%s LIMIT 1", (fn, conschema))
        fr = cur.fetchone()
        if fr:
            nsp, pname, args, fdef = fr
            out.append((f"{nsp}.{pname}({args})", fdef))
    return out



_FK_SQL = """SELECT a.attname, nf.nspname, cf.relname, af.attname
FROM pg_constraint k
JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace
JOIN pg_class cf ON cf.oid=k.confrelid JOIN pg_namespace nf ON nf.oid=cf.relnamespace
JOIN pg_attribute a ON a.attrelid=k.conrelid AND a.attnum=k.conkey[1]
JOIN pg_attribute af ON af.attrelid=k.confrelid AND af.attnum=k.confkey[1]
WHERE n.nspname=%s AND c.relname=%s AND k.contype='f' AND array_length(k.conkey,1)=1"""



def _basejump_present(cur):
    cur.execute("SELECT to_regprocedure('tests.authenticate_as(text)') IS NOT NULL")
    return bool(cur.fetchone()[0])



def rls_tables(cur, schema):
    """Every RLS-enabled table in the schema that has at least one policy (test-generation targets)."""
    cur.execute("""SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname=%s AND c.relkind='r' AND c.relrowsecurity
          AND EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid)
        ORDER BY c.relname""", (schema,))
    return [r[0] for r in cur.fetchall()]



def all_tables(cur, schema):
    """Every base table in the schema, with (name, rls_enabled, has_policy) — for the exposure scan."""
    cur.execute("""SELECT c.relname, c.relrowsecurity,
                          EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid)
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname=%s AND c.relkind='r' ORDER BY c.relname""", (schema,))
    return [(r[0], bool(r[1]), bool(r[2])) for r in cur.fetchall()]



def _exposed(cur, schema, table):
    """True if anon/authenticated holds any table privilege (i.e. RLS-off here = readable/writable via API)."""
    cur.execute("SELECT rolname FROM pg_roles WHERE rolname IN ('anon','authenticated')")
    roles = [r[0] for r in cur.fetchall()]
    for role in roles:
        cur.execute("SELECT bool_or(has_table_privilege(%s, %s, priv)) FROM unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE']) AS priv",
                    (role, f"{schema}.{table}"))
        if cur.fetchone()[0]:
            return True
    return False



def _effective_grants(cur, schema, table):
    """Real effective table access for the client roles: schema USAGE AND the per-command table privilege.
    Reads the catalog (no mutation). A missing grant => that command is denied regardless of RLS."""
    cur.execute("SELECT rolname FROM pg_roles WHERE rolname IN ('authenticated','anon','service_role')")
    present = {r[0] for r in cur.fetchall()}
    g = {}
    for role in ("authenticated", "anon", "service_role"):
        if role not in present:
            for cmd in _CMDS4: g[(role, cmd)] = False
            continue
        cur.execute("SELECT has_schema_privilege(%s, %s, 'USAGE')", (role, schema))
        usage = bool(cur.fetchone()[0])
        for cmd in _CMDS4:
            if not usage:
                g[(role, cmd)] = False; continue
            cur.execute("SELECT has_table_privilege(%s, %s, %s)", (role, f"{schema}.{table}", cmd))
            g[(role, cmd)] = bool(cur.fetchone()[0])
    return g



def _action_table(sql):
    """Best-effort table the action runs against (FROM/INTO/UPDATE x) — used for the post-arrange invariant."""
    m = re.search(r"\b(?:from|into|update)\s+([a-zA-Z_][\w$.\"]*)", sql or "", re.I)
    return m.group(1) if m else None

