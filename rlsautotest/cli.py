#!/usr/bin/env python3
# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""testgen.rls - predicate-tree, command-aware RLS test generator.

Per RLS_ARCHITECTURE.md. For EACH command we take the applicable policies, parse
the right clause (USING for reads, WITH CHECK for INSERT) to DNF min-terms, and
derive one identity class per min-term. Emits the role-switch AAA battery with:
 - recursive ancestors-first FK seeding (multi-table / transitive chains),
 - enum-aware fills + enum-typed RBAC labels,
 - fresh-identity insert when the link column is unique/PK,
 - (SELECT auth.uid()) wrapper unwrap, auth.role()='authenticated' open gate.
Unhandled atoms -> reason-coded NOT_TESTABLE.

  python -m testgen.rls --schema <s> --table <t> [--describe] [--out f.sql]
"""
from __future__ import annotations
import argparse, json, re, sys
import psycopg
from pglast.parser import parse_sql_json


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
            m = re.search(r"\b(\w+)\s*=\s*ANY\s*\(\s*ARRAY\[\s*'([^']*)'", cdef) or re.search(r"\b(\w+)\s*=\s*'([^']*)'", cdef)
            if m:
                checks[m.group(1)] = "'" + m.group(2).replace("'", "''") + "'"
            else:
                rm = re.search(r"\(\s*(\w+)\s*(<=|>=|<|>)\s*(\w+)\s*\)", cdef)   # cross-column comparison (both sides resolved to columns at fill time)
                if rm:
                    relchecks.append((rm.group(1), rm.group(2), rm.group(3)))
        elif contype in ('u', 'p') and cols and len(cols) > 1:
            cuniques.append(list(cols))
        elif contype == 'f' and cols and len(cols) > 1 and parent and fcols:
            compfks.append({"cols": list(cols), "parent": parent, "pcols": list(fcols)})
    return checks, cuniques, relchecks, compfks


def _lit(typ):
    t = typ.lower()
    if "char" in t or "text" in t: return "'x'"
    if "uuid" in t: return "'000000ff-0000-0000-0000-0000000000ff'"
    if "bool" in t: return "false"
    if any(k in t for k in ("int", "numeric", "real", "double", "decimal")): return "1"
    if "timestamp" in t or "date" in t: return "now()"
    if "json" in t: return "'{}'"
    return "'x'"

CV = ["11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", "33333333-3333-3333-3333-333333333333"]
MV = ["a0000001-0000-0000-0000-000000000001", "a0000002-0000-0000-0000-000000000002", "a0000003-0000-0000-0000-000000000003"]
FOREIGN = "ffffffff-ffff-ffff-ffff-ffffffffffff"
NOBODY = "99999999-9999-9999-9999-999999999999"
RIVAL_SUB = "b0000000-0000-0000-0000-0000000000bb"   # a DIFFERENT authenticated user who belongs to a DIFFERENT tenant (org B)
RIVAL_ORG = "b0000000-0000-0000-0000-00000000b0b0"   # tenant B's scope value — proves "has tenancy, just not A's"
INS = "cccccccc-cccc-cccc-cccc-cccccccccccc"   # fresh value for insert-into-own-scope tests
ORDER = ["SELECT", "INSERT", "UPDATE", "DELETE"]


# ---------- AST helpers (pglast / libpg_query) — the only parser; no regex on SQL ----------
def _t(n): return next(iter(n)) if isinstance(n, dict) and n else None
def _v(n): return n[_t(n)]
def _names(lst): return ".".join(x.get("String", {}).get("sval", "") for x in (lst or []))


def _where(clause):
    try:
        tree = json.loads(parse_sql_json(f"SELECT 1 WHERE {clause}"))
        return tree["stmts"][0]["stmt"]["SelectStmt"].get("whereClause")
    except Exception:
        return None


def _unwrap(n):
    """Strip TypeCast and (SELECT expr) EXPR_SUBLINK wrappers to the inner node."""
    while isinstance(n, dict) and n:
        t = _t(n)
        if t == "TypeCast":
            n = _v(n).get("arg")
        elif t == "SubLink" and _v(n).get("subLinkType") == "EXPR_SUBLINK":
            tl = _v(n).get("subselect", {}).get("SelectStmt", {}).get("targetList", [])
            n = tl[0].get("ResTarget", {}).get("val") if tl else None
        else:
            break
    return n


def _is_func(n, fq):
    n = _unwrap(n)
    return _t(n) == "FuncCall" and _names(_v(n).get("funcname")) == fq


def _colname(n):
    n = _unwrap(n)
    if _t(n) == "ColumnRef":
        fl = _v(n).get("fields", [])
        return fl[-1].get("String", {}).get("sval") if fl else None
    return None


def _colqual(n):
    n = _unwrap(n)
    if _t(n) == "ColumnRef":
        fl = [f.get("String", {}).get("sval") for f in _v(n).get("fields", [])]
        if len(fl) >= 2: return fl[-2], fl[-1]
        if fl: return None, fl[-1]
    return None, None


def _const(n):
    n = _unwrap(n)
    if _t(n) == "A_Const":
        v = _v(n)
        if "sval" in v: return v["sval"].get("sval")
        if "ival" in v: return str(v["ival"].get("ival", 0))
        if "boolval" in v: return "true" if v["boolval"].get("boolval") else "false"
        if "fval" in v: return v["fval"].get("fval")
    return None


def _is_uuid(s):
    return bool(s) and bool(re.fullmatch(r"[0-9a-fA-F-]{36}", s))


def _jwt_keys(n):
    """auth.jwt() -> 'a' ->> 'b' chain -> ['a','b']; else None."""
    n = _unwrap(n); keys = []
    while _t(n) == "A_Expr" and _names(_v(n).get("name")) in ("->", "->>"):
        rk = _const(_v(n).get("rexpr"))
        if rk is None: return None
        keys.insert(0, rk); n = _unwrap(_v(n).get("lexpr"))
    return keys if (keys and _is_func(n, "auth.jwt")) else None


def _jwt_anywhere(n):
    """Find the first auth.jwt() claim-key chain anywhere in a node tree (handles claim-in-variable)."""
    if isinstance(n, dict):
        k = _jwt_keys(n)
        if k: return k
        for v in n.values():
            r = _jwt_anywhere(v)
            if r: return r
    elif isinstance(n, list):
        for x in n:
            r = _jwt_anywhere(x)
            if r: return r
    return None


def _eq_pairs(n):
    out = []
    if not isinstance(n, dict): return out
    if _t(n) == "BoolExpr":
        for a in _v(n).get("args", []): out += _eq_pairs(a)
    elif _t(n) == "A_Expr" and _names(_v(n).get("name")) == "=":
        out.append((_v(n).get("lexpr"), _v(n).get("rexpr")))
    return out


def _membership(subselect, testexpr):
    ss = (subselect or {}).get("SelectStmt", {})
    frm = ss.get("fromClause", [])
    if not frm or "RangeVar" not in frm[0]:
        return {"kind": "unknown", "text": "membership-subquery"}
    rv = frm[0]["RangeVar"]
    mtable = (rv.get("schemaname") + "." if rv.get("schemaname") else "") + rv.get("relname", "")
    alias = (rv.get("alias") or {}).get("aliasname") or rv.get("relname")
    muser = mscope = rowscope = None
    for (l, r) in _eq_pairs(ss.get("whereClause")):
        if _is_func(l, "auth.uid") or _is_func(r, "auth.uid"):
            _, muser = _colqual(r if _is_func(l, "auth.uid") else l)
        else:
            lq, lc = _colqual(l); rq, rc = _colqual(r)
            if lc and rc:
                if lq == alias: mscope, rowscope = lc, rc
                elif rq == alias: mscope, rowscope = rc, lc
    if testexpr is not None:
        _, rowscope = _colqual(testexpr)
        tl = ss.get("targetList", [])
        if tl: mscope = _colname(tl[0].get("ResTarget", {}).get("val"))
    if muser and mscope and rowscope:
        return {"kind": "membership", "mtable": mtable, "muser_col": muser, "mscope_col": mscope, "row_scope_col": rowscope}
    return {"kind": "unknown", "text": "membership-subquery"}


def _folder_owner(ind, uid):
    """(storage.foldername(<col>))[1] = auth.uid()[::text]  -> owner via path segment."""
    if not _is_func(uid, "auth.uid") or _t(ind) != "A_Indirection":
        return None
    arg = _v(ind).get("arg")
    if _t(arg) == "FuncCall" and _names(_v(arg).get("funcname")).split(".")[-1] == "foldername":
        fa = _v(arg).get("args", [])
        col = _colname(fa[0]) if fa else None
        if col:
            return {"kind": "folder_owner", "col": col}
    return None


def _array_consts(node):
    """ARRAY[const, const, ...] (possibly ::type-cast, or the whole array cast to type[]) -> [values] or None."""
    arr = _unwrap(node)
    if _t(arr) != "A_ArrayExpr":
        return None
    vals = []
    for el in _v(arr).get("elements", []):
        c = _const(el)
        if c is None:
            return None
        vals.append(c)
    return vals or None


def _list_consts(node):
    """IN-list (a, b, c) -> [values] or None."""
    if _t(node) != "List":
        return None
    vals = []
    for el in _v(node).get("items", []):
        c = _const(el)
        if c is None:
            return None
        vals.append(c)
    return vals or None


def _scalar_lookup(side, other):
    """(SELECT col FROM t WHERE key = auth.uid()) = const  ->  seed t(key:=uid, col:=const).
    The classic Supabase 'read my role/flag from a profile table' shape. Must inspect the RAW node
    (before _unwrap, which would collapse the EXPR_SUBLINK to its projected column). Returns atom or None."""
    if _t(side) != "SubLink":
        return None
    sv = _v(side)
    if sv.get("subLinkType") != "EXPR_SUBLINK":
        return None
    val = _const(other)
    if val is None:
        return None
    ss = (sv.get("subselect") or {}).get("SelectStmt", {})
    frm = ss.get("fromClause", [])
    if not frm or "RangeVar" not in frm[0]:
        return None
    rv = frm[0]["RangeVar"]
    ltable = (rv.get("schemaname") + "." if rv.get("schemaname") else "") + rv.get("relname", "")
    tl = ss.get("targetList", [])
    lcol = _colname(tl[0].get("ResTarget", {}).get("val")) if tl else None
    lkey = None
    for (l, r) in _eq_pairs(ss.get("whereClause")):
        if _is_func(l, "auth.uid") or _is_func(r, "auth.uid"):
            _, lkey = _colqual(r if _is_func(l, "auth.uid") else l)
    if ltable and lcol and lkey:
        return {"kind": "scalar_lookup", "ltable": ltable, "lcol": lcol, "lkey": lkey, "value": val}
    return None


def _classify_aexpr(a, cur):
    kind = a.get("kind"); op = _names(a.get("name")); L = a.get("lexpr"); R = a.get("rexpr")
    if kind == "AEXPR_OP_ANY" and op == "=":
        if _is_func(L, "auth.uid") and _colname(R): return {"kind": "array_col", "col": _colname(R)}
        if _is_func(R, "auth.uid") and _colname(L): return {"kind": "array_col", "col": _colname(L)}
        col = _colname(L) or _colname(R)
        vals = _array_consts(R) if _colname(L) else _array_consts(L)
        if col and vals: return {"kind": "col_in_set", "col": col, "values": vals}   # col = ANY(array[consts])  ==  col IN (...)
        return {"kind": "unknown", "text": "= ANY(...)"}
    if kind == "AEXPR_OP_ALL" and op in ("<>", "!="):
        col = _colname(L) or _colname(R)
        vals = _array_consts(R) if _colname(L) else _array_consts(L)
        if col and vals: return {"kind": "col_not_in_set", "col": col, "values": vals}   # col <> ALL(array[consts])  ==  col NOT IN (...)
        return {"kind": "unknown", "text": "<> ALL(...)"}
    if kind == "AEXPR_IN":
        col = _colname(L); vals = _list_consts(R)
        if col and vals:
            return {"kind": "col_in_set" if op == "=" else "col_not_in_set", "col": col, "values": vals}
        return {"kind": "unknown", "text": "IN(...)"}
    if kind != "AEXPR_OP": return {"kind": "unknown", "text": kind or "expr"}
    if op in (">", "<", ">=", "<="):
        if _is_func(R, "now") and _colname(L): return {"kind": "temporal", "col": _colname(L), "op": op}
        if _is_func(L, "now") and _colname(R):
            return {"kind": "temporal", "col": _colname(R), "op": {">": "<", "<": ">", ">=": "<=", "<=": ">="}[op]}
        return {"kind": "unknown", "text": f"cmp {op}"}
    if op != "=": return {"kind": "unknown", "text": f"op {op}"}
    fo = _folder_owner(L, R) or _folder_owner(R, L)
    if fo: return fo
    if _is_func(L, "auth.uid") or _is_func(R, "auth.uid"):
        other = R if _is_func(L, "auth.uid") else L
        if _is_uuid(_const(other)): return {"kind": "const_identity", "value": _const(other)}
        if _colname(other): return {"kind": "owner", "col": _colname(other)}
        return {"kind": "unknown", "text": "auth.uid eq"}
    if _is_func(L, "auth.role") or _is_func(R, "auth.role"):
        other = R if _is_func(L, "auth.role") else L
        return {"kind": "auth_role", "value": _const(other) or ""}
    jl, jr = _jwt_keys(L), _jwt_keys(R)
    if jl or jr:
        keys = jl or jr; other = R if jl else L
        if _colname(other): return {"kind": "tenant", "col": _colname(other), "keys": keys}
        if _const(other) is not None: return {"kind": "claim_const", "keys": keys, "value": _const(other)}
        return {"kind": "unknown", "text": "jwt eq"}
    sl = _scalar_lookup(L, R) or _scalar_lookup(R, L)   # (SELECT col FROM t WHERE key=auth.uid()) = const
    if sl: return sl
    if _colname(L) and _const(R) is not None: return {"kind": "row_const", "col": _colname(L), "value": _const(R)}
    if _colname(R) and _const(L) is not None: return {"kind": "row_const", "col": _colname(R), "value": _const(L)}
    return {"kind": "unknown", "text": "eq"}


def classify_node(n, cur=None):
    """Classify one AST leaf node into an atom dict (same shapes build_class expects)."""
    t = _t(n)
    if t == "A_Const":
        return {"kind": "_true_"} if _const(n) == "true" else {"kind": "unknown", "text": "const"}
    if t == "ColumnRef":
        return {"kind": "row_const", "col": _colname(n), "value": "true"} if _colname(n) else {"kind": "unknown", "text": "colref"}
    if t == "SubLink":
        v = _v(n); st = v.get("subLinkType")
        if st == "EXISTS_SUBLINK": return _membership(v.get("subselect"), None)
        if st == "ANY_SUBLINK": return _membership(v.get("subselect"), v.get("testexpr"))
        if st == "EXPR_SUBLINK": return classify_node(_unwrap(n), cur)
        return {"kind": "unknown", "text": st or "sublink"}
    if t == "FuncCall":
        v = _v(n); fn = _names(v.get("funcname")); args = v.get("args", [])
        if args and _const(args[0]) is not None and cur and not any(b in fn for b in ("auth.", "now")):
            info = _introspect_rbac(cur, fn, _const(args[0]))
            if info: return {"kind": "rbac", **info}
            cf = _introspect_claim_fn(cur, fn, _const(args[0]))
            if cf: return {"kind": "claim_const", **cf}
        return {"kind": "unknown", "text": f"function {fn}()"}
    if t == "A_Expr":
        return _classify_aexpr(_v(n), cur)
    return {"kind": "unknown", "text": t or "node"}


def _check_value_set(check_sql):
    """Parse a WITH CHECK predicate of the simple value-constraint shape -> (col, frozenset(values)) or None.
    Covers `col = const` and `col = ANY(array[consts])` / `col IN (...)` — the column-value space a policy permits."""
    w = _where(check_sql or "")
    if w is None:
        return None
    at = classify_node(w, None)
    if at.get("kind") == "row_const":
        return (at["col"], frozenset([at["value"]]))
    if at.get("kind") == "col_in_set":
        return (at["col"], frozenset(at["values"]))
    return None


# ---------- general witness solver (solve, don't classify) ----------
# When the named-shape catalog can't classify a predicate, derive inputs that make it TRUE and FALSE by
# reading only the OPERAND ROLES of each comparison (column / const / auth.uid / jwt-claim / GUC / subquery /
# function) and composing across AND/OR/NOT. The witness is VERIFIED against the live DB before any test is
# baked (see solve_emit), so an incomplete guess degrades to NOT_TESTABLE — never a false pass.
_WV_UID = "5ce1a000-0000-4000-8000-000000000001"

def _wv_some(typ, enums):
    """A canonical value of `typ` (for a matching pair)."""
    base = (typ or "text").split("(")[0].strip(); t = (typ or "").lower()
    if base in enums and enums[base]: return enums[base][0]
    if "uuid" in t: return "5ce1a000-0000-4000-8000-0000000000aa"
    if any(k in t for k in ("int", "serial", "numeric", "real", "double", "decimal", "money")): return "100"
    if "bool" in t: return "true"
    if "timestamp" in t: return "2020-01-01 00:00:00+00"
    if "date" in t: return "2020-01-01"
    if "time" in t: return "00:00:00"
    return "rls_a"

def _wv_other(typ, enums, avoid=None):
    """A value of `typ` distinct from `avoid` (for falsifiers / not-in-set)."""
    base = (typ or "text").split("(")[0].strip(); t = (typ or "").lower()
    if base in enums and enums[base]: return next((l for l in enums[base] if l != avoid), enums[base][0])
    if "uuid" in t:
        a = "5ce1a000-0000-4000-8000-0000000000bb"
        return a if avoid != a else "5ce1a000-0000-4000-8000-0000000000cc"
    if any(k in t for k in ("int", "serial", "numeric", "real", "double", "decimal", "money")):
        return "0" if str(avoid) != "0" else "7"
    if "bool" in t: return "false" if str(avoid).lower() == "true" else "true"
    if "timestamp" in t: a = "2021-06-15 12:00:00+00"; return a if str(avoid) != a else "2019-03-03 03:03:03+00"
    if "date" in t: a = "2021-06-15"; return a if str(avoid) != a else "2019-03-03"
    if "time" in t: a = "12:34:56"; return a if str(avoid) != a else "06:06:06"
    return "rls_x" if avoid != "rls_x" else "rls_y"

def _wv_lit(typ, raw):
    if raw is None: return "NULL"
    t = (typ or "").lower()
    if any(k in t for k in ("int", "serial", "numeric", "real", "double", "decimal", "money")) and re.fullmatch(r"-?\d+(\.\d+)?", str(raw)): return str(raw)
    if "bool" in t and str(raw).lower() in ("true", "false"): return str(raw).lower()
    if any(k in t for k in ("timestamp", "date", "time", "interval")):   # cast date/time literals to the column type
        return "'" + str(raw).replace("'", "''") + "'::" + typ
    return "'" + str(raw).replace("'", "''") + "'"

def _wv_ctx(): return {"sub": None, "claims": [], "guc": {}, "row": {}, "aux": [], "role": "authenticated"}

def _wv_merge(a, b):
    """Combine two witness contexts; None on a contradiction (e.g. a column needs two different values)."""
    if a is None or b is None: return None
    if a["sub"] is not None and b["sub"] is not None and a["sub"] != b["sub"]: return None
    out = {"sub": a["sub"] if a["sub"] is not None else b["sub"], "claims": a["claims"] + b["claims"],
           "guc": dict(a["guc"]), "row": dict(a["row"]), "aux": a["aux"] + b["aux"], "role": a["role"]}
    for c, val in b["row"].items():
        if c in out["row"] and out["row"][c] != val: return None
        out["row"][c] = val
    for k, val in b["guc"].items():
        if k in out["guc"] and out["guc"][k] != val: return None
        out["guc"][k] = val
    seen = {}
    for keys, val in out["claims"]:
        kk = tuple(keys)
        if kk in seen and seen[kk] != val: return None
        seen[kk] = val
    return out

def _side_role(node):
    """Operand role of one side of a comparison: ('col',name)/('const',v)/('uid',)/('claim',keys)/('guc',name)/(None,)."""
    if _is_func(node, "auth.uid"): return ("uid", None)
    k = _jwt_keys(node)
    if k: return ("claim", k)
    u = _unwrap(node)
    if _t(u) == "FuncCall" and _names(_v(u).get("funcname")).split(".")[-1] == "current_setting":
        a = _v(u).get("args", []); nm = _const(a[0]) if a else None
        if nm: return ("guc", nm)
    c = _colname(node)
    if c: return ("col", c)
    cv = _const(node)
    if cv is not None: return ("const", cv)
    return (None, None)

def _solve_eq(L, R, coltypes, enums):
    lr, rr = _side_role(L), _side_role(R)
    for x, y in ((lr, rr), (rr, lr)):                       # claim/GUC compared to a const (no column): e.g. an OR admin escape hatch
        if x[0] == "claim" and y[0] == "const":
            sat, fal = _wv_ctx(), _wv_ctx()
            sat["claims"].append((x[1], y[1])); fal["claims"].append((x[1], _wv_other("text", enums, y[1]))); return (sat, fal)
        if x[0] == "guc" and y[0] == "const":
            sat, fal = _wv_ctx(), _wv_ctx()
            sat["guc"][x[1]] = y[1]; fal["guc"][x[1]] = _wv_other("text", enums, y[1]); return (sat, fal)
    if rr[0] == "col" and lr[0] in ("col", "const", "uid", "claim", "guc"): lr, rr = rr, lr   # put the column on the left
    if lr[0] != "col": return None
    col = lr[1]; ct = coltypes.get(col, "text"); sat, fal = _wv_ctx(), _wv_ctx()
    if rr[0] == "const":
        sat["row"][col] = rr[1]; fal["row"][col] = _wv_other(ct, enums, rr[1]); return (sat, fal)
    if rr[0] == "uid":
        sat["sub"] = _WV_UID; sat["row"][col] = _WV_UID; fal["sub"] = _WV_UID; fal["row"][col] = _wv_other("uuid", enums, _WV_UID); return (sat, fal)
    if rr[0] == "claim":
        V = _wv_some(ct, enums); sat["claims"].append((rr[1], V)); sat["row"][col] = V
        fal["claims"].append((rr[1], V)); fal["row"][col] = _wv_other(ct, enums, V); return (sat, fal)
    if rr[0] == "guc":
        V = _wv_some(ct, enums); sat["guc"][rr[1]] = V; sat["row"][col] = V
        fal["guc"][rr[1]] = V; fal["row"][col] = _wv_other(ct, enums, V); return (sat, fal)
    if rr[0] == "col":
        V = _wv_some(ct, enums); sat["row"][col] = V; sat["row"][rr[1]] = V
        fal["row"][col] = V; fal["row"][rr[1]] = _wv_other(coltypes.get(rr[1], "text"), enums, V); return (sat, fal)
    return None

def _solve_ineq(op, L, R, coltypes, enums):
    lr, rr = _side_role(L), _side_role(R)
    if lr[0] == "col" and rr[0] in ("claim", "guc", "const"): col, inp, col_left = lr[1], rr, True
    elif rr[0] == "col" and lr[0] in ("claim", "guc", "const"): col, inp, col_left = rr[1], lr, False
    else: return None
    if not any(k in (coltypes.get(col, "") or "").lower() for k in ("int", "numeric", "real", "double", "decimal", "serial", "money")): return None
    eff = op if col_left else {">": "<", "<": ">", ">=": "<=", "<=": ">="}[op]
    hi_col = eff in (">", ">=")
    sat, fal = _wv_ctx(), _wv_ctx()
    def put(ctx, cv, iv):
        ctx["row"][col] = cv
        if inp[0] == "claim" and iv is not None: ctx["claims"].append((inp[1], iv))
        elif inp[0] == "guc" and iv is not None: ctx["guc"][inp[1]] = iv
    if inp[0] == "const":
        try: c = int(float(inp[1]))
        except Exception: return None
        pairs = {">=": (c, c - 1), ">": (c + 1, c), "<=": (c, c + 1), "<": (c - 1, c)}[eff]
        put(sat, str(pairs[0]), None); put(fal, str(pairs[1]), None); return (sat, fal)
    if hi_col: put(sat, "1000000", "1"); put(fal, "1", "1000000")
    else:      put(sat, "1", "1000000"); put(fal, "1000000", "1")
    return (sat, fal)

def _solve_leaf(node, coltypes, enums):
    t = _t(node)
    if t == "A_Const": return (_wv_ctx(), None) if _const(node) == "true" else None
    if t == "NullTest":
        v = _v(node); col = _colname(v.get("arg"))
        if not col: return None
        other = _wv_other(coltypes.get(col, "text"), enums); sat, fal = _wv_ctx(), _wv_ctx()
        if v.get("nulltesttype") == "IS_NULL": sat["row"][col] = None; fal["row"][col] = other
        else: sat["row"][col] = other; fal["row"][col] = None
        return (sat, fal)
    if t == "SubLink":
        sv = _v(node); st = sv.get("subLinkType")
        if st in ("EXISTS_SUBLINK", "ANY_SUBLINK"):
            m = _membership(sv.get("subselect"), sv.get("testexpr") if st == "ANY_SUBLINK" else None)
            if m.get("kind") == "membership":
                sat, fal = _wv_ctx(), _wv_ctx(); sat["sub"] = _WV_UID; fal["sub"] = _WV_UID
                sc = "5c09e000-0000-4000-8000-000000000001"
                sat["row"][m["row_scope_col"]] = sc
                sat["aux"].append({"table": m["mtable"], "cols": {m["muser_col"]: _WV_UID, m["mscope_col"]: sc}})
                fal["row"][m["row_scope_col"]] = "5c09e000-0000-4000-8000-0000000000ff"
                return (sat, fal)
        return None
    if t != "A_Expr": return None
    v = _v(node); kind = v.get("kind"); op = _names(v.get("name")); L = v.get("lexpr"); R = v.get("rexpr")
    sl = _scalar_lookup(L, R) or _scalar_lookup(R, L)
    if sl:
        sat, fal = _wv_ctx(), _wv_ctx(); sat["sub"] = _WV_UID; fal["sub"] = _WV_UID
        sat["aux"].append({"table": sl["ltable"], "cols": {sl["lkey"]: _WV_UID, sl["lcol"]: sl["value"]}})
        fal["aux"].append({"table": sl["ltable"], "cols": {sl["lkey"]: _WV_UID, sl["lcol"]: _wv_other("text", enums, sl["value"])}})
        return (sat, fal)
    if kind == "AEXPR_OP_ANY" and op == "=":
        col = _colname(L) or _colname(R); vals = _array_consts(R) if _colname(L) else _array_consts(L)
        if col and vals:
            base = (coltypes.get(col, "") or "").split("(")[0].strip()
            outside = next((l for l in enums.get(base, []) if l not in vals), None)
            sat, fal = _wv_ctx(), _wv_ctx(); sat["row"][col] = vals[0]
            if outside is None: return (sat, None)
            fal["row"][col] = outside; return (sat, fal)
        return None
    if kind == "AEXPR_OP_ALL" and op in ("<>", "!="):
        col = _colname(L) or _colname(R); vals = _array_consts(R) if _colname(L) else _array_consts(L)
        if col and vals:
            base = (coltypes.get(col, "") or "").split("(")[0].strip()
            outside = next((l for l in enums.get(base, []) if l not in vals), None)
            if outside is None: return None
            sat, fal = _wv_ctx(), _wv_ctx(); sat["row"][col] = outside; fal["row"][col] = vals[0]; return (sat, fal)
        return None
    if kind == "AEXPR_OP" and op == "=": return _solve_eq(L, R, coltypes, enums)
    if kind == "AEXPR_OP" and op in (">", "<", ">=", "<="): return _solve_ineq(op, L, R, coltypes, enums)
    if kind == "AEXPR_OP" and op in ("<>", "!="):
        lr, rr = _side_role(L), _side_role(R)
        if rr[0] == "col" and lr[0] == "const": lr, rr = rr, lr
        if lr[0] == "col" and rr[0] == "const":
            sat, fal = _wv_ctx(), _wv_ctx()
            sat["row"][lr[1]] = _wv_other(coltypes.get(lr[1], "text"), enums, rr[1]); fal["row"][lr[1]] = rr[1]; return (sat, fal)
        return None
    return None

def _solve_node(node, coltypes, enums):
    if _t(node) == "BoolExpr":
        bo = _v(node).get("boolop"); kids = [_solve_node(a, coltypes, enums) for a in _v(node).get("args", [])]
        if bo == "NOT_EXPR":
            k = kids[0]; return (k[1], k[0]) if (k and k[1] is not None) else None
        if bo == "AND_EXPR":
            sat = _wv_ctx()
            for k in kids:
                if not k: return None
                sat = _wv_merge(sat, k[0])
                if sat is None: return None
            fal = None
            for i, k in enumerate(kids):
                if not k or k[1] is None: continue
                cand = k[1]; ok = True
                for j, k2 in enumerate(kids):
                    if j == i: continue
                    cand = _wv_merge(cand, k2[0]) if k2 else None
                    if cand is None: ok = False; break
                if ok and cand is not None: fal = cand; break
            return (sat, fal)
        if bo == "OR_EXPR":
            sat = next((k[0] for k in kids if k), None)
            if sat is None: return None
            fal = _wv_ctx()
            for k in kids:
                if not k or k[1] is None: fal = None; break
                fal = _wv_merge(fal, k[1])
                if fal is None: break
            return (sat, fal)
        return None
    return _solve_leaf(node, coltypes, enums)

def _solve_predicate(node, coltypes, enums):
    """Entry point: a parsed predicate -> (sat_ctx, fal_ctx) or None. sat makes it true, fal makes it false."""
    if node is None: return None
    return _solve_node(node, coltypes, enums)

def _seed_one(table_fqn, fixed, fkmap, colsmap, enums):
    """INSERT stmts (FK parents first, ON CONFLICT DO NOTHING) for one row of table_fqn: `fixed` {col: literal}
    plus required NOT-NULL/no-default columns filled with type-valid values."""
    stmts = []
    def fill(t):
        base = t.split("(")[0].strip()
        return f"'{enums[base][0]}'::{base}" if (base in enums and enums[base]) else _lit(t)
    def pick(t):
        base = t.split("(")[0].strip(); tl = t.lower()
        if base in enums and enums[base]: return f"'{enums[base][0]}'::{base}"
        if "uuid" in tl: return "'000000c1-0000-0000-0000-0000000000c1'"
        if any(k in tl for k in ("int", "numeric", "real", "double", "serial", "decimal")): return "1"
        if "bool" in tl: return "false"
        return "'x'"
    def ensure(tbl, vals):
        fks = fkmap.get(tbl, {}); full = dict(vals)
        for (n, t, nn, hd) in colsmap.get(tbl, []):
            if n in full or not nn or hd: continue
            full[n] = pick(t) if n in fks else fill(t)
        for n, vv in full.items():
            if n in fks: pt, pc = fks[n]; ensure(pt, {pc: vv})
        stmts.append(f"INSERT INTO {tbl}({', '.join(full)}) VALUES ({', '.join(full.values())}) ON CONFLICT DO NOTHING")
    ensure(table_fqn, fixed)
    return stmts


def _dnf_ast(n):
    """Boolean AST -> DNF: list of min-terms, each a list of leaf nodes."""
    t = _t(n)
    if t == "BoolExpr":
        bo = _v(n).get("boolop")
        if bo == "OR_EXPR":
            out = []
            for a in _v(n).get("args", []): out += _dnf_ast(a)
            return out
        if bo == "AND_EXPR":
            partial = [[]]
            for a in _v(n).get("args", []):
                partial = [m + s for m in partial for s in _dnf_ast(a)]
            return partial
    return [[n]]


def _is_true_clause(q):
    w = _where(q or "")
    return _t(w) == "A_Const" and _const(w) == "true"


def _find_queries(obj, out=None):
    """Collect embedded SQL query strings from a parsed plpgsql tree (PLpgSQL_expr.query)."""
    if out is None: out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "query" and isinstance(v, str): out.append(v)
            else: _find_queries(v, out)
    elif isinstance(obj, list):
        for x in obj: _find_queries(x, out)
    return out


def _func_selects(cur, fn):
    """Return (SelectStmt AST nodes inside fn's body, arg names) — SQL and plpgsql, via AST."""
    parts = fn.split("."); name = parts[-1]; sch = parts[-2] if len(parts) > 1 else None
    cur.execute("""SELECT p.prosrc, l.lanname, p.proargnames, pg_get_functiondef(p.oid)
        FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE p.proname=%s AND (%s::text IS NULL OR n.nspname=%s) ORDER BY (n.nspname='public')::int LIMIT 1""", (name, sch, sch))
    row = cur.fetchone()
    if not row: return [], []
    src, lang, argnames, fdef = row
    queries = [src] if lang == "sql" else []
    if lang == "plpgsql":
        try:
            from pglast import parse_plpgsql
            queries = _find_queries(parse_plpgsql(fdef))
        except Exception:
            queries = []
    selects = []
    for qy in queries:
        cands = [qy, "SELECT " + qy]        # plpgsql exprs are bare -> also try wrapped
        if " := " in qy:                    # assignment "v := <expr>" -> parse the RHS
            cands.append("SELECT " + qy.split(" := ", 1)[1])
        for cand in cands:
            try:
                got = False
                for st in json.loads(parse_sql_json(cand)).get("stmts", []):
                    s = st.get("stmt", {}).get("SelectStmt")
                    if s: selects.append(s); got = True
                if got: break
            except Exception:
                pass
    return selects, (argnames or [])


def _introspect_rbac(cur, fn, arg):
    """RBAC fn (AST): a SELECT over a (role, permission) table where the permission column is
    compared to the fn's argument and the role column to the caller's JWT claim (inline OR via a
    variable assigned from auth.jwt())."""
    selects, argnames = _func_selects(cur, fn)
    claim = None
    for ss in selects:
        claim = claim or _jwt_anywhere(ss)
    if not claim:
        return None
    for ss in selects:
        frm = ss.get("fromClause", [])
        if not frm or "RangeVar" not in frm[0]: continue
        rv = frm[0]["RangeVar"]; relname = rv.get("relname")
        tbl = (rv.get("schemaname") + "." if rv.get("schemaname") else "") + relname
        cur.execute("SELECT a.attname FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid WHERE c.relname=%s AND a.attnum>0 AND NOT a.attisdropped", (relname,))
        tcols = {r[0] for r in cur.fetchall()}
        role_col = perm_col = None
        for (l, r) in _eq_pairs(ss.get("whereClause")):
            lc, rc = _colname(l), _colname(r)
            if lc in tcols: tcol, other = lc, rc
            elif rc in tcols: tcol, other = rc, lc
            else: continue
            if other in argnames: perm_col = tcol
            else: role_col = tcol
        if role_col and perm_col:
            role_label = "tg_role"
            cur.execute("""SELECT array_agg(e.enumlabel ORDER BY e.enumsortorder)
                FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_type ty ON ty.oid=a.atttypid
                JOIN pg_enum e ON e.enumtypid=ty.oid WHERE c.relname=%s AND a.attname=%s AND ty.typtype='e'""",
                        (relname, role_col))
            er = cur.fetchone()
            if er and er[0]: role_label = er[0][0]
            return {"fn": fn, "arg": arg, "claim": claim[-1], "rtable": tbl,
                    "role_col": role_col, "perm_col": perm_col, "role_label": role_label}
    return None


def _introspect_claim_fn(cur, fn, arg):
    """Boolean fn (AST) comparing a JWT claim to its argument (e.g. has_role) -> claim_const."""
    selects, _ = _func_selects(cur, fn)
    for ss in selects:
        if ss.get("fromClause"): continue
        exprs = [rt.get("ResTarget", {}).get("val") for rt in ss.get("targetList", [])]
        if ss.get("whereClause"): exprs.append(ss.get("whereClause"))
        for e in exprs:
            for (l, r) in _eq_pairs(e):
                jk = _jwt_keys(l) or _jwt_keys(r)
                if jk and _colname(r if _jwt_keys(l) else l):
                    return {"keys": [jk[-1]], "value": arg}
    return None


def _set_claim(c, keys, v):
    d = c
    for k in keys[:-1]:
        d = d.setdefault(k, {})
    d[keys[-1]] = v


def build_class(min_term, idx, col_dom=None):
    claims = {"sub": CV[idx % len(CV)], "role": "authenticated"}
    rowseed, aux, scalar_link, fk_val, handled, reason, has_temporal = {}, [], None, None, True, None, False
    tenant_keys = []   # JWT claim path(s) this class scopes on (for building a rival-tenant negative control)
    for at in min_term:
        k = at["kind"]
        if k == "owner":
            v = CV[idx % len(CV)]; claims["sub"] = v; rowseed[at["col"]] = f"'{v}'"; scalar_link = at["col"]; fk_val = v
        elif k == "const_identity":
            claims["sub"] = at["value"]
        elif k == "tenant":
            v = CV[idx % len(CV)]; _set_claim(claims, at["keys"], v); rowseed[at["col"]] = f"'{v}'"; scalar_link = at["col"]; fk_val = v
            tenant_keys.append(at["keys"])
        elif k == "claim_const":
            _set_claim(claims, at["keys"], at["value"])
        elif k == "row_const":
            rowseed[at["col"]] = f"'{at['value']}'"; scalar_link = at["col"]
        elif k == "membership":
            uid = MV[idx % len(MV)]; sc = CV[idx % len(CV)]; claims["sub"] = uid
            rowseed[at["row_scope_col"]] = f"'{sc}'"; scalar_link = at["row_scope_col"]; fk_val = sc
            aux.append({"table": at["mtable"], "cols": {at["muser_col"]: uid, at["mscope_col"]: sc},
                        "kind": "membership", "muser_col": at["muser_col"], "mscope_col": at["mscope_col"]})
        elif k == "array_col":
            uid = CV[idx % len(CV)]; claims["sub"] = uid; rowseed[at["col"]] = f"ARRAY['{uid}']::uuid[]"
        elif k == "temporal":
            has_temporal = True
            rowseed[at["col"]] = "now() + interval '1 day'" if at["op"].startswith(">") else "now() - interval '1 day'"
        elif k == "rbac":
            lbl = at.get("role_label", "tg_role"); claims[at["claim"]] = lbl
            aux.append({"table": at["rtable"], "cols": {at["role_col"]: lbl, at["perm_col"]: at["arg"]}, "kind": "rbac"})
        elif k == "folder_owner":
            uid = CV[idx % len(CV)]; claims["sub"] = uid; rowseed[at["col"]] = f"'{uid}/x'"; scalar_link = at["col"]
        elif k == "auth_role":
            pass
        elif k == "col_in_set":
            rowseed[at["col"]] = f"'{at['values'][0]}'"   # seed a value that satisfies the membership; no scalar_link (value constraint, not identity link)
        elif k == "col_not_in_set":
            dom = (col_dom or {}).get(at["col"])
            outside = next((x for x in (dom or []) if x not in at["values"]), None)
            if outside is None:
                handled, reason = False, f"unhandled atom: no value outside {at['values']} for {at['col']}"
            else:
                rowseed[at["col"]] = f"'{outside}'"
        elif k == "scalar_lookup":
            uid = f"a5000000-0000-4000-8000-{idx:012x}"; claims["sub"] = uid   # unique per class (avoid PK collisions in the lookup table when >len(MV) classes)
            aux.append({"table": at["ltable"], "cols": {at["lkey"]: uid, at["lcol"]: at["value"]},
                        "kind": "scalar_lookup", "role_value": at["value"]})
        else:
            handled, reason = False, f"unhandled atom: {at.get('text')}"
    return {"idx": idx, "claims": claims, "rowseed": rowseed, "aux": aux, "scalar_link": scalar_link,
            "fk_val": fk_val, "rowlinked": bool(rowseed), "handled": handled, "reason": reason,
            "has_temporal": has_temporal, "kinds": [a["kind"] for a in min_term], "tenant_keys": tenant_keys}


def _cmd_dnf(pols, cmd, clause, cur):
    apps = [p for p in pols if p[2].upper() in (cmd, "ALL")]
    perm = [p for p in apps if p[1] == "PERMISSIVE"]
    restr = [p for p in apps if p[1] == "RESTRICTIVE"]

    def eff(p):
        # INSERT is checked by WITH CHECK; but a FOR-ALL / INSERT policy that omits WITH CHECK
        # falls back to its USING (qual) for the insert check (Postgres semantics:
        # "if WITH CHECK is omitted, the USING expression is used for both"). So a USING-only
        # PERMISSIVE *or* RESTRICTIVE policy must NOT be dropped from the INSERT plan — otherwise
        # a compound (permissive owner AND restrictive tenant) INSERT is only half-synthesized.
        if cmd == "INSERT":
            return p[5] if p[5] is not None else p[4]
        return p[clause]

    dnf, srcs, seen, is_open = [], [], set(), False
    for p in perm:
        pe = eff(p)
        chk = p[5] if p[5] is not None else p[4]   # the policy's own WITH CHECK (USING fallback) — carried for the transition audit
        w = _where(pe) if pe else None
        if w is None:
            if pe: dnf.append([{"kind": "unknown", "text": "parse-fail"}]); srcs.append({"policy": p[0], "check": chk})
            continue
        for mt in _dnf_ast(w):
            atoms = [a for a in (classify_node(n, cur) for n in mt) if a.get("kind") != "_true_"]
            for a in atoms:
                if a.get("kind") == "auth_role" and a.get("value") == "authenticated": is_open = True
            if not atoms: is_open = True
            key = tuple(sorted(f"{a.get('kind')}|{a.get('col')}|{a.get('value')}|{a.get('mtable')}|{','.join(map(str, a.get('values', [])))}" for a in atoms))
            if key not in seen: seen.add(key); dnf.append(atoms); srcs.append({"policy": p[0], "check": chk, "raw": list(mt)})
    rest = []
    for p in restr:
        pe = eff(p)
        w = _where(pe) if pe else None
        if w:
            for mt in _dnf_ast(w): rest += [classify_node(n, cur) for n in mt]
    dnf = [mt + rest for mt in dnf]
    return dnf, bool(perm), is_open, srcs


def analyze(cur, schema, table):
    cur.execute("SELECT policyname, permissive, cmd, roles, qual, with_check FROM pg_policies WHERE schemaname=%s AND tablename=%s", (schema, table))
    pols = cur.fetchall()
    cur.execute("""SELECT a.attname, array_agg(e.enumlabel ORDER BY e.enumsortorder)
        FROM pg_attribute a JOIN pg_type t ON t.oid=a.atttypid JOIN pg_enum e ON e.enumtypid=t.oid
        JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname=%s AND c.relname=%s AND a.attnum>0 AND NOT a.attisdropped GROUP BY a.attname""", (schema, table))
    col_dom = {r[0]: r[1] for r in cur.fetchall()}   # column -> enum label domain (for col_not_in_set seeding)
    cmds = set()
    for p in pols:
        cmds |= ({"SELECT", "INSERT", "UPDATE", "DELETE"} if p[2].upper() == "ALL" else {p[2].upper()})
    per = {}
    for cmd in cmds:
        clause = 5 if cmd == "INSERT" else 4
        dnf, has_pol, is_open, srcs = _cmd_dnf(pols, cmd, clause, cur)
        classes = []
        for i, t in enumerate(dnf):
            cc = build_class(t, i, col_dom)
            cc["src_policy"] = srcs[i].get("policy") if i < len(srcs) else None
            cc["src_check"] = srcs[i].get("check") if i < len(srcs) else None
            cc["raw_atoms"] = srcs[i].get("raw") if i < len(srcs) else None   # raw AST conjunct nodes -> per-min-term solver fallback (BL-1)
            classes.append(cc)
        per[cmd] = {"classes": classes, "open": is_open, "has_pol": has_pol}
        if cmd == "SELECT":
            per[cmd]["anon_open"] = any(("public" in (p[3] or []) or "anon" in (p[3] or [])) and _is_true_clause(p[4])
                                        for p in pols if p[2].upper() in ("SELECT", "ALL") and p[1] == "PERMISSIVE")
    notes = []
    for p in pols:
        if p[2].upper() in ("SELECT", "ALL") and p[1] == "PERMISSIVE" and _is_true_clause(p[4]):
            notes.append(f"policy {p[0]}: SELECT USING (true) -> every {p[3]} sees ALL rows (review)")
        if p[2].upper() == "INSERT" and _is_true_clause(p[5]):
            notes.append(f"policy {p[0]}: INSERT WITH CHECK (true) -> any {p[3]} may write any row (review)")
    return pols, per, sorted(cmds, key=lambda c: ORDER.index(c) if c in ORDER else 9), notes


def _unq(v):
    return v[1:-1] if isinstance(v, str) and v.startswith("'") and v.endswith("'") else v


def _seed_plan(schema, table, per, cmds, cols, fkmap, colsmap, enums, unique_cols, checks=None, cuniques=None, relchecks=None, compfks=None):
    """Shared seeding + per-command plan computation used by BOTH the nested and flat emitters."""
    q = f"{schema}.{table}"
    checks = checks or {}; cuniques = cuniques or {}; relchecks = relchecks or {}; compfks = compfks or {}
    def chkval(tbl, col): return (checks.get(tbl) or {}).get(col)   # CHECK-satisfying literal for this column, if any
    def coltype(tbl, col): return next((t for (n, t, nn, hd) in colsmap.get(tbl, []) if n == col), None)
    def relfill(tbl, vals, fixed):   # cross-column CHECK (a op b): fill an ordered numeric/temporal pair
        for (a, op, b) in relchecks.get(tbl, []):
            ta, tb = coltype(tbl, a), coltype(tbl, b)
            if ta is None or tb is None or a in fixed or b in fixed: continue
            tl = (ta or "").lower()
            if any(k in tl for k in ("int", "numeric", "real", "double", "decimal", "serial")):
                lo, hi = "1", "2"
            elif "timestamp" in tl or "date" in tl:
                lo, hi = "now() - interval '1 day'", "now() + interval '1 day'"
            else:
                continue
            vals[a], vals[b] = (lo, hi) if op in ("<", "<=") else (hi, lo)
    all_h = [c for cmd in cmds for c in per[cmd]["classes"] if c["handled"]]
    seen_k, rowlinked = set(), []
    for c in all_h:
        if c["rowlinked"]:
            key = (tuple(sorted(c["rowseed"].items())), tuple(sorted((a["table"], tuple(sorted(a["cols"].items()))) for a in c["aux"])))
            if key not in seen_k: seen_k.add(key); rowlinked.append(c)
    any_grant = any(not c["rowlinked"] for c in all_h)
    primary = rowlinked[0] if rowlinked else None
    pkind = primary["kinds"][0] if primary and primary["kinds"] else None
    total_rows = (len(rowlinked) + 1) if rowlinked else (2 if any_grant else 0)

    def fill(t):
        base = t.split("(")[0].strip()
        return f"'{enums[base][0]}'::{base}" if base in enums else _lit(t)
    def pick(t):
        base = t.split("(")[0].strip(); tl = t.lower()
        if base in enums: return f"'{enums[base][0]}'::{base}"
        if "uuid" in tl: return "'000000c1-0000-0000-0000-0000000000c1'"
        if any(k in tl for k in ("int", "numeric", "real", "double", "serial")): return "1"
        if "bool" in tl: return "false"
        return "'x'"

    stmts, seen = [], set()
    def ensure_comp(tbl, pvals):   # seed a composite-FK parent tuple (its key cols fixed to pvals)
        ck = (tbl, tuple(sorted(pvals.items())))
        if ck in seen: return
        seen.add(ck)
        full = dict(pvals); fks = fkmap.get(tbl, {})
        for (n, t, nn, hd) in colsmap.get(tbl, []):
            if n in full or not nn or hd: continue
            full[n] = pick(t) if n in fks else (chkval(tbl, n) or fill(t))
        relfill(tbl, full, set(pvals)); anc(full, tbl)
        stmts.append(f"  INSERT INTO {tbl}({', '.join(full)}) VALUES ({', '.join(full.values())}) ON CONFLICT DO NOTHING;")
    def ensure(tbl, col, val):
        k = (tbl, col, val)
        if k in seen: return
        seen.add(k)
        fks = fkmap.get(tbl, {}); vals = {col: val}
        for (n, t, nn, hd) in colsmap.get(tbl, []):
            if n == col or not nn or hd: continue
            vals[n] = pick(t) if n in fks else (chkval(tbl, n) or fill(t))
        relfill(tbl, vals, {col})
        for n, v in vals.items():
            if n in fks: pt, pc = fks[n]; ensure(pt, pc, v)
        for cf in compfks.get(tbl, []):
            if all(c in vals for c in cf["cols"]): ensure_comp(cf["parent"], {pc: vals[lc] for lc, pc in zip(cf["cols"], cf["pcols"])})
        stmts.append(f"  INSERT INTO {tbl}({', '.join(vals)}) VALUES ({', '.join(vals.values())}) ON CONFLICT DO NOTHING;")
    def _distinct(t, salt):
        tl = t.lower(); base = t.split("(")[0].strip()
        if base in enums: return f"'{enums[base][0]}'::{base}"
        if "uuid" in tl: return f"'{salt:08x}-0000-0000-0000-000000000000'"   # distinct per salt (no-default uuid PKs need unique values)
        if "char" in tl or "text" in tl: return f"'usr{salt}'"
        if any(k in tl for k in ("int", "serial", "numeric", "real", "double")): return str(1000 + salt)
        return fill(t)
    def row_values(tbl, fixed, salt=0):
        vals = dict(fixed); fks = fkmap.get(tbl, {})
        for (n, t, nn, hd) in colsmap.get(tbl, []):
            if n in vals or not nn or hd: continue
            if n in fks: vals[n] = pick(t)
            elif tbl == q and n in unique_cols: vals[n] = _distinct(t, salt)
            else: vals[n] = chkval(tbl, n) or fill(t)
        for cu in cuniques.get(tbl, []):   # composite UNIQUE: vary one free col per salt so the combination stays distinct across seeded rows
            tgt = next((cc for cc in cu if cc not in fks and cc not in fixed), None)
            if tgt:
                tt = next((tt0 for (n0, tt0, nn0, hd0) in colsmap.get(tbl, []) if n0 == tgt), None)
                if tt: vals[tgt] = _distinct(tt, salt)
        relfill(tbl, vals, set(fixed))   # cross-column CHECK: fill an ordered pair
        return vals
    def anc(vals, tbl):
        fks = fkmap.get(tbl, {})
        for n, v in vals.items():
            if n in fks: pt, pc = fks[n]; ensure(pt, pc, v)
        for cf in compfks.get(tbl, []):   # composite FK -> seed the parent tuple
            if all(c in vals for c in cf["cols"]): ensure_comp(cf["parent"], {pc: vals[lc] for lc, pc in zip(cf["cols"], cf["pcols"])})
    def insert(tbl, vals, conflict=False):
        return f"  INSERT INTO {tbl}({', '.join(vals)}) VALUES ({', '.join(vals.values())})" + (" ON CONFLICT DO NOTHING" if conflict else "") + ";"
    def foreign_val(kind):
        if kind == "array_col": return f"ARRAY['{FOREIGN}']::uuid[]"
        if kind == "temporal": return "now() - interval '1 day'"
        if kind == "folder_owner": return f"'{FOREIGN}/x'"
        return f"'{FOREIGN}'"

    for at in {a["table"] for c in all_h for a in c["aux"]}:
        stmts.append(f"  DELETE FROM {at};")
    # Seed aux/scope rows BEFORE the main rows. When the scope table is ALSO an FK parent of the table
    # under test (e.g. a `data_rooms` that is both the membership table and room_documents.room_id's
    # parent), the membership-linking column (owner_id = the test user) must be written first; the later
    # FK-parent fill of that same row then no-ops via ON CONFLICT DO NOTHING. Otherwise the generic fill
    # wins, the "authorized" identity isn't actually authorized, and every grant test bakes a wrong "0 rows".
    aux_seen = set()
    for c in all_h:
        for a in c["aux"]:
            ak = (a["table"], tuple(sorted(a["cols"].items())))
            if ak in aux_seen: continue
            aux_seen.add(ak)
            av = {k: f"'{val}'" for k, val in a["cols"].items()}
            v = row_values(a["table"], av); anc(v, a["table"]); stmts.append(insert(a["table"], v, conflict=True))
    def _anc_tables(t0):                                 # t0 + its transitive FK-parent tables
        seen, st = set(), [t0]
        while st:
            t = st.pop()
            if t in seen: continue
            seen.add(t)
            for (pt, _pc) in fkmap.get(t, {}).values(): st.append(pt)
        return seen
    # If the table under test IS the scope parent that an aux row FK-references (e.g. orgs, with
    # memberships.org_id -> orgs.id; also rbac role tables / scalar-lookup tables that point back at q),
    # then the aux's anc() already seeded the main row's PK while satisfying that FK; the main insert
    # here would re-insert the same key and self-collide (23505), which the probe would mis-bake as a
    # denial. Make it idempotent in that case. Covers ALL aux kinds, not just membership.
    q_scope_parent = any(a.get("table") and a["table"] != q and q in _anc_tables(a["table"])
                         for c in all_h for a in c["aux"])
    for c in rowlinked:
        v = row_values(q, c["rowseed"], salt=c["idx"]); anc(v, q); stmts.append(insert(q, v, conflict=q_scope_parent))
        if c["has_temporal"]:
            tcol = [k for k in c["rowseed"] if "now()" in c["rowseed"][k]][0]
            v2 = row_values(q, {**c["rowseed"], tcol: "now() - interval '1 day'"}, salt=c["idx"] + 50); anc(v2, q); stmts.append(insert(q, v2) + "  -- expired")
    if primary:
        ov = {}
        if primary["scalar_link"]: ov[primary["scalar_link"]] = foreign_val(pkind)
        for col in primary["rowseed"]:
            if "ARRAY[" in primary["rowseed"][col]: ov[col] = foreign_val("array_col")
            elif "now()" in primary["rowseed"][col]: ov[col] = "now() + interval '1 day'"
        v = row_values(q, {**primary["rowseed"], **ov}, salt=99); anc(v, q); stmts.append(insert(q, v) + "  -- foreign")
    elif any_grant:
        for i in range(2):
            v = row_values(q, {}, salt=i); anc(v, q); stmts.append(insert(q, v))

    # ── rival tenant: the "authenticated, not authorized" negative control is a LEGITIMATE user of a
    #    DIFFERENT tenant (org B), not a no-tenant outsider — so a green block proves cross-tenant isolation
    #    (having tenancy != having A's tenancy), and a buggy policy like `org_id IS NOT NULL` is caught.
    rival_claims = {"sub": RIVAL_SUB, "role": "authenticated"}
    rival_on = False
    for c in all_h:
        for ks in c.get("tenant_keys", []):
            _set_claim(rival_claims, ks, RIVAL_ORG); rival_on = True
    def _touches(t0):                                  # t0 + its transitive FK-parent tables
        seen, st = set(), [t0]
        while st:
            t = st.pop()
            if t in seen: continue
            seen.add(t)
            for (pt, _pc) in fkmap.get(t, {}).values(): st.append(pt)
        return seen
    seen_m = set()
    for c in all_h:
        for a in c.get("aux", []):
            if a.get("kind") != "membership": continue
            mk = (a["table"], a["muser_col"], a["mscope_col"])
            if mk in seen_m: continue
            seen_m.add(mk)
            if q in _touches(a["table"]):
                continue   # seeding the rival here would insert a visible row INTO the table under test -> skip (fall back to NOBODY)
            rv = row_values(a["table"], {a["muser_col"]: f"'{RIVAL_SUB}'", a["mscope_col"]: f"'{RIVAL_ORG}'"})
            anc(rv, a["table"]); stmts.append(insert(a["table"], rv, conflict=True) + "  -- rival tenant (org B) membership")
            rival_on = True

    # INSERT-test rows: fresh value when link is unique/PK (avoids PK collision); pre-seed ancestors
    insert_plan = {}
    if "INSERT" in cmds:
        for c in [x for x in per["INSERT"]["classes"] if x["handled"]]:
            if c["rowlinked"]:
                if c["scalar_link"] in unique_cols and c["claims"].get("sub") == _unq(c["rowseed"].get(c["scalar_link"], "")):
                    iclaims = {**c["claims"], "sub": INS}; ifixed = {**c["rowseed"], c["scalar_link"]: f"'{INS}'"}
                else:
                    iclaims, ifixed = c["claims"], c["rowseed"]
                iv = row_values(q, ifixed, salt=200 + c["idx"]); anc(iv, q)
                insert_plan[c["idx"]] = (json.dumps(iclaims), iv)
            else:
                iv = row_values(q, {primary["scalar_link"]: foreign_val(pkind)} if primary and primary["scalar_link"] else {}, salt=250); anc(iv, q)
                insert_plan[c["idx"]] = (json.dumps(c["claims"]), iv)
    nobody_ins = row_values(q, primary["rowseed"], salt=300) if primary else (row_values(q, {}, salt=301) if any_grant else None)
    seed = "\n".join(stmts)
    return {"q": q, "seed": seed, "total_rows": total_rows, "insert_plan": insert_plan,
            "nobody_ins": nobody_ins, "primary": primary, "pkind": pkind, "rowlinked": rowlinked,
            "any_grant": any_grant, "fill": fill, "foreign_val": foreign_val,
            "rival": {"on": rival_on, "claims": json.dumps(rival_claims)}}


def emit(schema, table, per, cmds, cols, fkmap, colsmap, enums, unique_cols, checks=None, cuniques=None, relchecks=None, compfks=None):
    S = _seed_plan(schema, table, per, cmds, cols, fkmap, colsmap, enums, unique_cols, checks, cuniques, relchecks, compfks)
    q = S["q"]; cls = f"test_{table}"
    seed = S["seed"]; total_rows = S["total_rows"]; insert_plan = S["insert_plan"]
    nobody_ins = S["nobody_ins"]; primary = S["primary"]; pkind = S["pkind"]
    rowlinked = S["rowlinked"]; fill = S["fill"]; foreign_val = S["foreign_val"]

    out = [f"""-- GENERATED by testgen.rls (command-aware, deep-seeding) from {q}. Do not edit.
{_PGTAP_ENSURE}
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {schema} TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {schema} TO authenticated;
GRANT SELECT ON ALL TABLES IN SCHEMA {schema} TO anon;
DROP SCHEMA IF EXISTS {cls} CASCADE;
CREATE SCHEMA {cls};
CREATE FUNCTION {cls}._seed() RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  SET LOCAL ROLE service_role;
  DELETE FROM {q};
{seed}
END $$;
"""]
    n = [0]
    def fn(name, decl, actsql, cj, asserts, role="authenticated"):
        n[0] += 1
        a = "\n".join(f"  RETURN NEXT {x};" for x in asserts)
        return f"""CREATE FUNCTION {cls}.test_{n[0]:02d}_{name}() RETURNS SETOF TEXT LANGUAGE plpgsql AS $$
DECLARE runner text := current_user; {decl}
BEGIN
  PERFORM {cls}._seed();
  PERFORM set_config('request.jwt.claims', '{cj}', true);
  SET LOCAL ROLE {role};
{actsql}
  EXECUTE format('SET LOCAL ROLE %I', runner);
{a}
END $$;
"""
    cj = lambda c: json.dumps(c["claims"])
    NB = json.dumps({"sub": NOBODY, "role": "authenticated"})

    for cmd in cmds:
        pc = per[cmd]; classes = [c for c in pc["classes"] if c["handled"]]
        if cmd == "SELECT":
            for c in classes:
                exp = total_rows if not c["rowlinked"] else 1
                out.append(fn(f"select_b{c['idx']}", "k int;", f"  SELECT count(*) INTO k FROM {q};", cj(c),
                              [f"is(k, {exp}, 'SELECT branch {c['idx']}: {'sees all (open/grant)' if not c['rowlinked'] else 'sees only its own row'}')"]))
            anon_exp = total_rows if pc.get("anon_open") else 0
            out.append(fn("select_anon", "k int;", f"  SELECT count(*) INTO k FROM {q};", "",
                          [f"is(k, {anon_exp}, 'SELECT: anon sees {('all (public policy)' if pc.get('anon_open') else 'nothing')}')"], role="anon"))
            if not pc["open"] and classes:
                out.append(fn("select_nobody_denied", "k int;", f"  SELECT count(*) INTO k FROM {q};", NB, ["is(k, 0, 'SELECT: unauthorized sees nothing')"]))
        elif cmd == "INSERT":
            for c in classes:
                if c["idx"] in insert_plan:
                    icl, iv = insert_plan[c["idx"]]
                    out.append(fn(f"insert_b{c['idx']}_ok", "got text;", f"  BEGIN INSERT INTO {q}({', '.join(iv)}) VALUES ({', '.join(iv.values())}); got:='OK'; EXCEPTION WHEN others THEN got:=SQLSTATE; END;", icl,
                                  [f"is(got, 'OK', 'INSERT branch {c['idx']}: authorized may write')"]))
            if not pc["open"] and nobody_ins:
                out.append(fn("insert_nobody_denied", "got text;", f"  BEGIN INSERT INTO {q}({', '.join(nobody_ins)}) VALUES ({', '.join(nobody_ins.values())}); got:='NO ERROR'; EXCEPTION WHEN insufficient_privilege THEN got:=SQLSTATE; WHEN others THEN got:=SQLSTATE; END;", NB,
                              ["is(got, '42501', 'INSERT: unauthorized cannot write')"]))
        elif cmd == "UPDATE" and (upd := next(((nn0, tt0) for (nn0, tt0, c0, h0) in cols if nn0 not in {x for cc in rowlinked for x in cc['rowseed']} and not h0), None)):
            for c in classes:
                out.append(fn(f"update_b{c['idx']}_ok", "m int;", f"  UPDATE {q} SET {upd[0]}={fill(upd[1])}; GET DIAGNOSTICS m=ROW_COUNT;", cj(c),
                              [f"cmp_ok(m, '>=', 1, 'UPDATE branch {c['idx']}: authorized may update its rows')"]))
                if c["rowlinked"] and c["scalar_link"] and c["fk_val"] and c["scalar_link"] not in unique_cols:
                    out.append(fn(f"update_b{c['idx']}_reassign_denied", "got text;", f"  BEGIN UPDATE {q} SET {c['scalar_link']}='{FOREIGN}'; got:='NO ERROR'; EXCEPTION WHEN insufficient_privilege THEN got:=SQLSTATE; WHEN others THEN got:=SQLSTATE; END;", cj(c),
                                  [f"is(got, '42501', 'UPDATE branch {c['idx']}: cannot move row out of scope')"]))
            if classes:
                out.append(fn("update_nobody_denied", "m int;", f"  UPDATE {q} SET {upd[0]}={fill(upd[1])}; GET DIAGNOSTICS m=ROW_COUNT;", NB, ["is(m, 0, 'UPDATE: unauthorized affects 0 rows')"]))
        elif cmd == "DELETE":
            for c in classes:
                out.append(fn(f"delete_b{c['idx']}_ok", "m int;", f"  DELETE FROM {q}; GET DIAGNOSTICS m=ROW_COUNT;", cj(c),
                              [f"cmp_ok(m, '>=', 1, 'DELETE branch {c['idx']}: authorized may delete its rows')"]))
            if classes:
                out.append(fn("delete_nobody_denied", "m int;", f"  DELETE FROM {q}; GET DIAGNOSTICS m=ROW_COUNT;", NB, ["is(m, 0, 'DELETE: unauthorized affects 0 rows')"]))
    out.append(f"\nSELECT * FROM runtests('{cls}'::name);\n")
    return "".join(out)


def _qlit(s):
    return "'" + str(s).replace("'", "''") + "'"


def _mock_valid_row(schema, table, fkmap, colsmap, enums, checks=None, relchecks=None, compfks=None):
    """Build (fk_parent_insert_stmts, {col: literal}) for ONE valid row of schema.table.
    Used to seed the precondition for opaque-function-gated write tests (the mock path): when a
    table's only policies delegate to an opaque boolean fn, there's no 'handled' class and thus
    no base seed, so the engine has no row to INSERT/UPDATE/DELETE. This synthesizes one — FK
    parents seeded recursively (ON CONFLICT DO NOTHING), required (NOT NULL, no-default,
    non-identity) columns filled with type-valid literals."""
    q = f"{schema}.{table}"
    checks = checks or {}
    def _ck(tbl, col): return (checks.get(tbl) or {}).get(col)   # CHECK-satisfying literal, if any

    def _fill(t):
        base = t.split("(")[0].strip()
        return f"'{enums[base][0]}'::{base}" if (base in enums and enums[base]) else _lit(t)

    def _pick(t):
        base = t.split("(")[0].strip(); tl = t.lower()
        if base in enums and enums[base]: return f"'{enums[base][0]}'::{base}"
        if "uuid" in tl: return "'000000c1-0000-0000-0000-0000000000c1'"
        if any(k in tl for k in ("int", "numeric", "real", "double", "serial", "decimal")): return "1"
        if "bool" in tl: return "false"
        return "'x'"

    stmts, seen = [], set()

    def ensure(tbl, col, val):
        k = (tbl, col, val)
        if k in seen: return
        seen.add(k)
        fks = fkmap.get(tbl, {}); vals = {col: val}
        for (n, t, nn, hd) in colsmap.get(tbl, []):
            if n == col or not nn or hd: continue
            vals[n] = _pick(t) if n in fks else (_ck(tbl, n) or _fill(t))
        for n, v in vals.items():
            if n in fks: pt, pc = fks[n]; ensure(pt, pc, v)
        stmts.append(f"INSERT INTO {tbl}({', '.join(vals)}) VALUES ({', '.join(vals.values())}) ON CONFLICT DO NOTHING")

    fks = fkmap.get(q, {}); row = {}
    for (n, t, nn, hd) in colsmap.get(q, []):
        if not nn or hd: continue
        row[n] = _pick(t) if n in fks else (_ck(q, n) or _fill(t))
    for n, v in row.items():
        if n in fks: pt, pc = fks[n]; ensure(pt, pc, v)
    return stmts, row


def _bump_lit(typ, salt):
    t = (typ or "").lower()
    if "uuid" in t: return f"'{salt:08x}-0000-0000-0000-000000000000'"
    if any(k in t for k in ("int", "numeric", "real", "double", "serial", "decimal")): return str(1000 + salt)
    if "char" in t or "text" in t: return f"'syn{salt}'"
    return _lit(typ)


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


def _synthesize_row(conn, schema, table, fixed=None, _depth=0, budget=24):
    """PROBE-AND-REPAIR row synthesis (DB as oracle): build the recipe (ordered SQL) that makes ONE valid row
    of schema.table EXIST. Try the INSERT, read the real failure, repair, retry within a budget:
      23502 NOT NULL  -> fill the named column
      23503 FK        -> seed the parent tuple (recursively synthesize it; composite-aware)
      23514 CHECK     -> if it delegates to a boolean UDF, neutralize the fn for the insert then restore it
      23505 UNIQUE    -> vary a column
    Returns (recipe_stmts, row_values) or (None, None). Discovery runs in savepoints (rolled back); the
    returned recipe is meant to be run for real as the seeding (RLS-bypassing) role. Sound: if it can't
    build a row it returns None -> caller stays NOT_TESTABLE, never a fabricated pass."""
    if _depth > 6:
        return None, None, None
    q = f"{schema}.{table}"
    cur = conn.cursor()
    cur.execute("""SELECT a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull,
                          (a.atthasdef OR a.attidentity <> '' OR a.attgenerated <> '')
                   FROM pg_attribute a WHERE a.attrelid = format('%%I.%%I', %s::text, %s::text)::regclass
                     AND a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attnum""", (schema, table))
    coltypes, row = {}, {}
    for (n, t, nn, hd) in cur.fetchall():
        coltypes[n] = t
        if nn and not hd: row[n] = _lit(t)
    for k, v in (fixed or {}).items():
        row[k] = v
    parents, mocks, salt = [], [], [0]
    def mock_create(sig): return f"CREATE OR REPLACE FUNCTION {sig} RETURNS boolean LANGUAGE sql AS $$ SELECT true $$;"
    def ins_sql():
        base = (f"INSERT INTO {q} ({', '.join(row)}) VALUES ({', '.join(row.values())})" if row else f"INSERT INTO {q} DEFAULT VALUES")
        # parents (depth>0) are re-seeded on every per-test preseed and never deleted -> make them idempotent;
        # the top-level target row is DELETEd before each re-seed (or is the action itself), so it stays plain.
        return base + (" ON CONFLICT DO NOTHING" if _depth > 0 else "")
    for i in range(budget):
        sp = f"_syn_{_depth}_{i}"
        cur.execute(f"SAVEPOINT {sp}")
        err = None
        try:
            for prec in parents:
                for s in prec: cur.execute(s.rstrip().rstrip(";"))
            for (sig, _orig) in mocks: cur.execute(mock_create(sig).rstrip(";"))
            cur.execute(ins_sql())
        except psycopg.Error as e:
            err = e
        try: cur.execute(f"ROLLBACK TO SAVEPOINT {sp}")
        except Exception: pass
        if err is None:
            setup = [mock_create(sig) for (sig, _o) in mocks]                                   # neutralize CHECK UDFs
            for prec in parents: setup += [s if s.rstrip().endswith(";") else s + ";" for s in prec]   # seed FK/composite parents
            recipe = list(setup) + [ins_sql() + ";"] + [orig.rstrip().rstrip(";") + ";" for (sig, orig) in mocks]  # +row +restore
            return recipe, dict(row), setup
        ss = getattr(err, "sqlstate", None); diag = getattr(err, "diag", None)
        col = getattr(diag, "column_name", None) if diag else None
        cname = getattr(diag, "constraint_name", None) if diag else None
        if ss == "23502" and col:                                   # NOT NULL
            row[col] = _lit(coltypes.get(col, "text"))
        elif ss == "23503" and cname:                               # FK (single or composite)
            fk = _fk_by_name(cur, cname)
            if not fk: return None, None, None
            for lc in fk["cols"]:
                if lc not in row or row[lc] == "NULL": row[lc] = _lit(coltypes.get(lc, "text"))
            ps, t2 = _sq(fk["parent"])
            prec, _pv, _ps = _synthesize_row(conn, ps, t2, fixed={pc: row[lc] for lc, pc in zip(fk["cols"], fk["pcols"])}, _depth=_depth + 1)
            if prec is None: return None, None, None
            parents.append(prec)
        elif ss == "23514" and cname:                               # CHECK -> neutralize a delegated boolean UDF
            new = [(s, o) for (s, o) in _check_bool_udfs(cur, cname) if s not in {m for m, _ in mocks}]
            if not new: return None, None, None                     # non-function CHECK (e.g. cross-column) -> not repairable here
            mocks += new
        elif ss == "23505" and cname:                               # UNIQUE -> vary a column
            cur.execute("SELECT array_agg(a.attname) FROM pg_constraint c JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=ANY(c.conkey) WHERE c.conname=%s", (cname,))
            ur = cur.fetchone(); tgt = next((u for u in (list(ur[0]) if ur and ur[0] else []) if u in row), None)
            if not tgt: return None, None, None
            salt[0] += 1; row[tgt] = _bump_lit(coltypes.get(tgt, "text"), salt[0])
        else:
            return None, None, None
    return None, None, None


def emit_flat(schema, table, per, cmds, cols, fkmap, colsmap, enums, unique_cols, checks=None, cuniques=None, relchecks=None, compfks=None, helpers=True, grants_map=None, conn=None):
    """Native Supabase FLAT pgTAP form: begin; plan(N); inline AAA; finish(); rollback.

    helpers=True (DEFAULT): tests read natively — tests.create_supabase_user / authenticate_as /
      clear_authentication for identity, with tests.get_supabase_uid() substituted into the seed's
      owner columns. Custom-claim (tenant/RBAC) classes keep a direct set_config (no helper exists).
      Requires the tests.* helpers (basejump, or the rlsautotest offline shim emitted in 000-setup).
    helpers=False (--no-helpers): fully self-contained — inline set_config + SET LOCAL ROLE, ensures
      pgtap, no 000-hook dependency; one file runs standalone."""
    S = _seed_plan(schema, table, per, cmds, cols, fkmap, colsmap, enums, unique_cols, checks, cuniques, relchecks, compfks)
    q = S["q"]; seed = S["seed"]; total_rows = S["total_rows"]
    insert_plan = S["insert_plan"]; nobody_ins = S["nobody_ins"]; fill = S["fill"]
    rowlinked = S["rowlinked"]
    cj = lambda c: json.dumps(c["claims"])
    NB = json.dumps({"sub": NOBODY, "role": "authenticated"})

    # helper-mode: create test users whose uid IS our seed uuid, so NO substitution is needed — the seed
    # stays literal and authenticate_as('u_N') returns exactly that uuid as auth.uid(). Pure-owner classes
    # (incl. owner/folder/membership/nobody) use authenticate_as; custom-claim (tenant/RBAC) keep set_config.
    body, n, sp = [], [0], [0]
    umap = {}
    def user_for(sub):
        if sub not in umap: umap[sub] = f"u_{len(umap)}"
        return umap[sub]
    def ident(cjson, role):
        if role == "anon" or cjson == "":
            return ["SELECT tests.clear_authentication();"] if helpers else ["SELECT set_config('request.jwt.claims', '', true);", "SET LOCAL ROLE anon;"]
        if helpers:
            d = json.loads(cjson)
            if set(d) <= {"sub", "role"} and d.get("role") == "authenticated" and d.get("sub") and _is_uuid(d["sub"]):
                return [f"SELECT tests.authenticate_as('{user_for(d['sub'])}');"]
        return [f"SELECT set_config('request.jwt.claims', {_qlit(cjson)}, true);", f"SET LOCAL ROLE {role};"]
    # restore the seeded precondition after a mutating test by RE-SEEDING (not SAVEPOINT/ROLLBACK):
    # real pgTAP keeps its test counter in txn-local state, and ROLLBACK TO SAVEPOINT would unwind it
    # (-> "planned N ran M" under pg_prove). Re-seeding isolates without touching the counter; the outer
    # ROLLBACK still discards everything at the end.
    reseed = f"RESET ROLE;\nDELETE FROM {q};\n{seed}"
    def read_test(cjson, role, assertion):
        n[0] += 1; body.extend(ident(cjson, role)); body.append(assertion); body.append("RESET ROLE;")
    def mut_test(cjson, role, assertion):
        n[0] += 1; body.extend(ident(cjson, role)); body.append(assertion); body.append(reseed)
    def desc(d): return _qlit(d)
    # Real effective grants for the client roles (NOT re-granted): we PROVE actual access, never assume it.
    gmap = grants_map or {}
    def geff(role, cmd): return gmap.get((role, cmd), True)   # default True when no DB context
    # pick a plain writable column for the denial UPDATE (avoid identity/generated cols -> parse error before the ACL check)
    _wcol = next((nn0 for (nn0, tt0, c0, h0) in cols
                  if nn0 not in {x for cc in rowlinked for x in cc['rowseed']} and not h0),
                 (cols[0][0] if cols else None))
    _deny_stmt = {"SELECT": f"SELECT 1 FROM {q}",
                  "INSERT": f"INSERT INTO {q} DEFAULT VALUES",
                  "UPDATE": (f"UPDATE {q} SET {_wcol}={_wcol}" if _wcol else None),
                  "DELETE": f"DELETE FROM {q}"}
    def deny(cmd, cjson, role, who):
        """Prove an action is denied (missing grant / schema usage -> 42501)."""
        sx = _deny_stmt.get(cmd)
        if not sx: return
        a = f"SELECT throws_ok( $$ {sx} $$, '42501', NULL, {desc(cmd + ': ' + who + ' has no grant - denied')} );"
        (read_test if cmd == "SELECT" else mut_test)(cjson, role, a)

    for cmd in (cmds if conn is None else ()):   # DERIVE path (no DB) — probe path below when conn given
        pc = per[cmd]; classes = [c for c in pc["classes"] if c["handled"]]
        auth_ok = geff("authenticated", cmd); anon_ok = geff("anon", cmd)
        if cmd == "SELECT":
            if auth_ok:
                for c in classes:
                    exp = total_rows if not c["rowlinked"] else 1
                    lbl = "sees all (open/grant)" if not c["rowlinked"] else "sees only its own row"
                    read_test(cj(c), "authenticated", f"SELECT is( (SELECT count(*) FROM {q})::int,{exp}, {desc('SELECT branch ' + str(c['idx']) + ': ' + lbl)} );")
                if not pc["open"] and classes:
                    read_test(NB, "authenticated", f"SELECT is( (SELECT count(*) FROM {q})::int,0, {desc('SELECT: unauthorized sees nothing')} );")
                elif pc["open"]:
                    # public read (USING true): a non-owner authenticated user also sees all rows — assert it (not skip)
                    read_test(NB, "authenticated", f"SELECT is( (SELECT count(*) FROM {q})::int,{total_rows}, {desc('SELECT: a non-owner user also sees all rows (public read)')} );")
            else:
                deny("SELECT", NB, "authenticated", "authenticated")
            if anon_ok:
                anon_exp = total_rows if pc.get("anon_open") else 0
                read_test("", "anon", f"SELECT is( (SELECT count(*) FROM {q})::int,{anon_exp}, {desc('SELECT: anon sees ' + ('all (public policy)' if pc.get('anon_open') else 'nothing'))} );")
            else:
                deny("SELECT", "", "anon", "anon")
        elif cmd == "INSERT":
            if auth_ok:
                for c in classes:
                    if c["idx"] in insert_plan:
                        icl, iv = insert_plan[c["idx"]]
                        ins = f"INSERT INTO {q}({', '.join(iv)}) VALUES ({', '.join(iv.values())})"
                        mut_test(icl, "authenticated", f"SELECT lives_ok( $$ {ins} $$, {desc('INSERT branch ' + str(c['idx']) + ': authorized may write')} );")
                if not pc["open"] and nobody_ins:
                    ins = f"INSERT INTO {q}({', '.join(nobody_ins)}) VALUES ({', '.join(nobody_ins.values())})"
                    mut_test(NB, "authenticated", f"SELECT throws_ok( $$ {ins} $$, '42501', NULL, {desc('INSERT: unauthorized cannot write')} );")
            else:
                deny("INSERT", NB, "authenticated", "authenticated")
            if not anon_ok:
                deny("INSERT", "", "anon", "anon")                       # no grant -> denied
            elif nobody_ins:                                            # anon HAS the grant -> prove the real RLS outcome
                ins = f"INSERT INTO {q}({', '.join(nobody_ins)}) VALUES ({', '.join(nobody_ins.values())})"
                if pc.get("anon_open") or pc.get("open"):
                    mut_test("", "anon", f"SELECT lives_ok( $$ {ins} $$, {desc('INSERT: anon CAN write (policy permits anon) - REVIEW')} );")
                else:
                    mut_test("", "anon", f"SELECT throws_ok( $$ {ins} $$, '42501', NULL, {desc('INSERT: anon has grant but is blocked by RLS')} );")
        elif cmd == "UPDATE":
            upd = next(((nn0, tt0) for (nn0, tt0, c0, h0) in cols if nn0 not in {x for cc in rowlinked for x in cc['rowseed']} and not h0), None)
            if auth_ok:
                if upd:
                    for c in classes:
                        mut_test(cj(c), "authenticated", f"SELECT isnt_empty( $$ UPDATE {q} SET {upd[0]}={fill(upd[1])} RETURNING 1 $$, {desc('UPDATE branch ' + str(c['idx']) + ': authorized may update its rows')} );")
                        if c["rowlinked"] and c["scalar_link"] and c["fk_val"] and c["scalar_link"] not in unique_cols:
                            mut_test(cj(c), "authenticated", f"SELECT throws_ok( $$ UPDATE {q} SET {c['scalar_link']}='{FOREIGN}' $$, '42501', NULL, {desc('UPDATE branch ' + str(c['idx']) + ': cannot move row out of scope')} );")
                    if classes:
                        mut_test(NB, "authenticated", f"SELECT is_empty( $$ UPDATE {q} SET {upd[0]}={fill(upd[1])} RETURNING 1 $$, {desc('UPDATE: unauthorized affects 0 rows')} );")
            else:
                deny("UPDATE", NB, "authenticated", "authenticated")
            if not anon_ok:
                deny("UPDATE", "", "anon", "anon")
            elif upd:                                                   # anon HAS the grant -> prove the real RLS outcome
                if pc.get("anon_open") or pc.get("open"):
                    mut_test("", "anon", f"SELECT isnt_empty( $$ UPDATE {q} SET {upd[0]}={fill(upd[1])} RETURNING 1 $$, {desc('UPDATE: anon CAN modify rows (policy permits anon) - REVIEW')} );")
                else:
                    mut_test("", "anon", f"SELECT is_empty( $$ UPDATE {q} SET {upd[0]}={fill(upd[1])} RETURNING 1 $$, {desc('UPDATE: anon has grant but RLS blocks (0 rows)')} );")
        elif cmd == "DELETE":
            if auth_ok:
                for c in classes:
                    mut_test(cj(c), "authenticated", f"SELECT isnt_empty( $$ DELETE FROM {q} RETURNING 1 $$, {desc('DELETE branch ' + str(c['idx']) + ': authorized may delete its rows')} );")
                if classes:
                    mut_test(NB, "authenticated", f"SELECT is_empty( $$ DELETE FROM {q} RETURNING 1 $$, {desc('DELETE: unauthorized affects 0 rows')} );")
            else:
                deny("DELETE", NB, "authenticated", "authenticated")
            if not anon_ok:
                deny("DELETE", "", "anon", "anon")
            else:                                                       # anon HAS the grant -> prove the real RLS outcome
                if pc.get("anon_open") or pc.get("open"):
                    mut_test("", "anon", f"SELECT isnt_empty( $$ DELETE FROM {q} RETURNING 1 $$, {desc('DELETE: anon CAN delete rows (policy permits anon) - REVIEW')} );")
                else:
                    mut_test("", "anon", f"SELECT is_empty( $$ DELETE FROM {q} RETURNING 1 $$, {desc('DELETE: anon has grant but RLS blocks (0 rows)')} );")

    if conn is not None:   # PROBE path: observe the REAL outcome of each identity x command on the copy, then bake it
        arrange_stmts = [s for s in _split_statements(f"DELETE FROM {q};\n{seed}") if s.strip()]
        _fk_cols = set(fkmap.get(f"{schema}.{table}", {}))   # avoid FK cols: SET fk=val triggers an RI check (parent access), not the table's own UPDATE perm
        _rowseed = {x for cc in rowlinked for x in cc['rowseed']}
        # Columns referenced by ANY policy on the table (USING + WITH CHECK). SETting one of these would
        # test scope-movement or the WITH CHECK value-space, NOT the plain UPDATE grant -> exclude them so we
        # change a POLICY-NEUTRAL column. No fallback to FK/unique/policy columns (those SETs fail for reasons
        # unrelated to RLS and would mis-bake as denials); if none is neutral, upd_col stays None and UPDATE is
        # honestly "not tested - no neutral column" (surfaced as a note by the report).
        _policy_cols = set()
        try:
            _pcur = conn.cursor()
            _pcur.execute("SELECT coalesce(qual,'') || ' ' || coalesce(with_check,'') FROM pg_policies WHERE schemaname=%s AND tablename=%s", (schema, table))
            _blob = " ".join((r[0] or "") for r in _pcur.fetchall())
            _policy_cols = {nn0 for (nn0, _t, _c, _h) in cols if re.search(r'\b' + re.escape(nn0) + r'\b', _blob)}
        except Exception:
            _policy_cols = set()
        upd_col = next(((nn0, tt0) for (nn0, tt0, c0, h0) in cols
                        if not h0 and nn0 not in _fk_cols and nn0 not in unique_cols
                        and nn0 not in _rowseed and nn0 not in _policy_cols), None)
        def _upd_val(col, typ):   # a CHECK-satisfying literal for the SET when known, else a type-based fill
            return (checks.get(q) or {}).get(col) or fill(typ)
        def pident(cjson, role):
            if role == "anon" or cjson == "":
                return ["SELECT set_config('request.jwt.claims', '', true)", "SET LOCAL ROLE anon"]
            return [f"SELECT set_config('request.jwt.claims', {_qlit(cjson)}, true)", f"SET LOCAL ROLE {role}"]
        def identities(classes):
            # who-labels feed both the baked test descriptions and the report parser (_table_report).
            # 'authenticated, authorized/not authorized' = same `authenticated` role, different JWT claims.
            out = [(f"authenticated, authorized (branch {c['idx']})", cj(c), "authenticated", c) for c in classes]
            # negative control: a legitimate user of a DIFFERENT tenant when the table is tenant/membership-scoped,
            # else a generic other authenticated user (NOBODY).
            if S.get("rival", {}).get("on"):
                out.append(("authenticated, not authorized (other tenant)", S["rival"]["claims"], "authenticated", None))
            else:
                out.append(("authenticated, not authorized", NB, "authenticated", None))
            out.append(("anon", "", "anon", None))
            return out
        udfs = _policy_bool_udfs(conn, schema, table)   # opaque boolean fns the policies delegate to (mock fallback)
        def mock_one(val, assertion, write, preseed=None):
            """Replace every policy UDF with a constant `val` (FakeFunction), act, assert, restore, re-seed."""
            n[0] += 1
            body.extend(f"CREATE OR REPLACE FUNCTION {u['q']}({u['args']}) RETURNS boolean LANGUAGE sql AS $$ SELECT {val} $$;" for u in udfs)
            if preseed:                                   # seed the precondition as the privileged role (RLS bypassed)
                body.append("RESET ROLE;")
                body.extend((s.rstrip().rstrip(';') + ";") for s in preseed)
            body.append(f"SELECT set_config('request.jwt.claims', {_qlit(NB)}, true);")   # semicolon-terminated (script context)
            body.append("SET LOCAL ROLE authenticated;")
            body.append(assertion)
            body.append("RESET ROLE;")
            body.extend((u['def'].rstrip().rstrip(';') + ";") for u in udfs)   # restore the REAL functions (CREATE OR REPLACE)
            if write:
                body.append(reseed)
        def mock_emit(cmd):
            """Opaque-function-gated command: prove the policy WIRES to the function, both directions.
            (Wiring proof — the function's own logic is out of scope / tested by the function engine.)"""
            if not udfs:
                return
            fns = ", ".join(u["name"] + "()" for u in udfs)
            # Need a valid row to act on. Prefer the probe-and-repair synthesizer (handles composite FK,
            # CHECK-delegated UDFs, etc. by reacting to real INSERT errors); fall back to the static builder,
            # then to the weak count. `recipe` makes a row exist (mocks restored); `setup` is the pre-insert
            # part (parent seeds + CHECK-UDF neutralizers, left active) for when we INSERT as the action.
            recipe, srow, setup = (None, None, None)
            if not nobody_ins:
                recipe, srow, setup = _synthesize_row(conn, schema, table)
            parents, prow = ([], None)
            if recipe is None and not nobody_ins:
                parents, prow = _mock_valid_row(schema, table, fkmap, colsmap, enums, checks, relchecks, compfks)
            def _exist_pre():   # statements that leave ONE valid row in q. We keep any CHECK-UDF mocks in `setup`
                # ACTIVE (not restored) through the action so an UPDATE that touches a CHECK'd column still passes;
                # the whole battery is wrapped in BEGIN..ROLLBACK so the real function is restored at the end.
                if recipe: return [f"DELETE FROM {q}"] + setup + [f"INSERT INTO {q}({', '.join(srow)}) VALUES ({', '.join(srow.values())})"]
                if prow:    return [f"DELETE FROM {q}"] + parents + [f"INSERT INTO {q}({', '.join(prow)}) VALUES ({', '.join(prow.values())})"]
                return None
            if cmd == "SELECT":
                pre = _exist_pre()
                if pre:    # seed ONE real row, prove read-visibility both ways: mock TRUE -> visible (1), FALSE -> hidden (0)
                    mock_one("true",  f"SELECT is( (SELECT count(*) FROM {q})::int, 1, {desc('SELECT: authenticated, authorized when ' + fns + ' [mocked; wiring]')} );", True, preseed=pre)
                    mock_one("false", f"SELECT is( (SELECT count(*) FROM {q})::int, 0, {desc('SELECT: authenticated, not authorized blocked when ' + fns + '=false [mocked; wiring]')} );", True, preseed=pre)
                else:      # couldn't synthesize a row -> weaker fallback, still sound
                    mock_one("true",  f"SELECT is( (SELECT count(*) FROM {q})::int, {total_rows}, {desc('SELECT: authenticated, authorized when ' + fns + ' [mocked; wiring]')} );", False)
                    mock_one("false", f"SELECT is( (SELECT count(*) FROM {q})::int, 0, {desc('SELECT: authenticated, not authorized blocked when ' + fns + '=false [mocked; wiring]')} );", False)
                return
            if cmd == "INSERT":
                icols = srow if recipe else (nobody_ins or prow)
                pre_ins = setup if recipe else parents   # parents + CHECK-UDF neutralizers active during the action insert
                if not icols: return
                ins = f"INSERT INTO {q}({', '.join(icols)}) VALUES ({', '.join(icols.values())})"
                # mock TRUE -> WITH CHECK passes -> insert lives; mock FALSE -> WITH CHECK fails -> 42501
                mock_one("true",  f"SELECT lives_ok( $$ {ins} $$, {desc('INSERT: authenticated, authorized when ' + fns + ' [mocked; wiring]')} );", True, preseed=pre_ins)
                mock_one("false", f"SELECT throws_ok( $$ {ins} $$, '42501', NULL, {desc('INSERT: authenticated, not authorized blocked when ' + fns + '=false [mocked; wiring]')} );", True, preseed=pre_ins)
                return
            if cmd == "UPDATE":
                if not upd_col: return
                action = f"UPDATE {q} SET {upd_col[0]}={_upd_val(upd_col[0], upd_col[1])}"
            else:
                action = f"DELETE FROM {q}"
            preseed = _exist_pre() or []   # UPDATE/DELETE need a row present to affect
            mock_one("true",  f"SELECT isnt_empty( $$ {action} RETURNING 1 $$, {desc(cmd + ': authenticated, authorized when ' + fns + ' [mocked; wiring]')} );", True, preseed=preseed)
            mock_one("false", f"SELECT is_empty( $$ {action} RETURNING 1 $$, {desc(cmd + ': authenticated, not authorized blocked when ' + fns + '=false [mocked; wiring]')} );", True, preseed=preseed)
        coltypes = {nn0: tt0 for (nn0, tt0, c0, h0) in cols}
        def _spair(typ):
            t = typ.lower()
            if "uuid" in t: return ("aaaaaaaa-0000-4000-8000-00000000aaaa", "bbbbbbbb-0000-4000-8000-00000000bbbb")
            if any(k in t for k in ("int", "numeric", "double", "real", "decimal")): return ("424242", "515151")
            return ("rls_synth_a", "rls_synth_b")
        def _vlit(typ, s):
            t = typ.lower()
            return s if any(k in t for k in ("int", "numeric", "double", "real", "decimal")) else "'" + s + "'"
        def _claims_for(gate, V):
            base = {"sub": NOBODY, "role": "authenticated"}
            if gate["kind"] != "guc":
                node = [V] if gate["kind"] == "claim_array" else V
                for k in reversed(gate["path"]):
                    node = {k: node}
                base.update(node)
            return json.dumps(base)
        def synth_emit(cmd, gate):
            """Drive an opaque GUC/claim-gated command by SETTING the input (GUC / JWT claim) and SEEDING a
            matching row, then probe-verify. Returns True if handled, False to fall through (e.g. unsatisfiable FK)."""
            req, bad = _synth_required_cols(conn, schema, table, fkmap)
            if bad: return False
            ctype = coltypes.get(gate["col"], "text")
            Va, Vb = _spair(ctype)
            seedcols = {gate["col"]: _vlit(ctype, Va)}
            for rn, rt in req:
                if rn != gate["col"]: seedcols[rn] = fill(rt)
            seedrow = f"INSERT INTO {q}({', '.join(seedcols)}) VALUES ({', '.join(seedcols.values())})"
            if cmd == "UPDATE":
                # Update a NEUTRAL column (not the gated/scope column): SET gate_col would test scope-movement,
                # not the UPDATE grant. Prefer the global upd_col if it isn't the gate col, else pick any plain
                # non-gate, non-FK, non-unique column (e.g. `body` on a GUC-scoped `items`).
                wc = upd_col if (upd_col and upd_col[0] != gate["col"]) else next(
                    ((n0, t0) for (n0, t0, c0, h0) in cols if not h0 and n0 != gate["col"] and n0 not in unique_cols and n0 not in _fk_cols), None)
                if not wc: return True   # no neutral column to UPDATE without touching the gated column -> honest skip
                act = f"UPDATE {q} SET {wc[0]}={_upd_val(wc[0], wc[1])}"
            elif cmd == "DELETE": act = f"DELETE FROM {q}"
            elif cmd == "INSERT": act = seedrow
            else: act = None
            def one(who, V, role):
                guc = (gate["name"], V) if (gate["kind"] == "guc" and V is not None) else None
                claims = None if role == "anon" else _claims_for(gate, V)
                pid = ([f"SELECT set_config('{guc[0]}', '{guc[1]}', true)"] if guc else [])
                pid += (["SELECT set_config('request.jwt.claims', '', true)", "SET LOCAL ROLE anon"] if role == "anon"
                        else [f"SELECT set_config('request.jwt.claims', {_qlit(claims)}, true)", "SET LOCAL ROLE authenticated"])
                arrange = [f"DELETE FROM {q}"] + ([] if cmd == "INSERT" else [seedrow])
                if cmd == "SELECT":
                    o = _probe(conn, arrange, pid, "read", f"SELECT count(*) FROM {q}")
                    if o[2]: asrt = _unrel_fail(desc, "SELECT: " + who, o)
                    else: asrt = (f"SELECT is( (SELECT count(*) FROM {q})::int, {o[1]}, {desc('SELECT: ' + who + ' sees ' + str(o[1]) + ' row(s)')} );" if o[0] == "count"
                                  else f"SELECT throws_ok( $$ SELECT 1 FROM {q} $$, '{o[1]}', NULL, {desc('SELECT: ' + who + ' denied (' + o[1] + ')')} );")
                else:
                    o = _probe(conn, arrange, pid, "write", act)
                    if o[2]: asrt = _unrel_fail(desc, cmd + ": " + who, o)
                    elif o[0] == "err" and o[1] != "42501": asrt = _unrel_fail(desc, cmd + ": " + who, ("err", o[1], "the test action raised " + o[1] + ", a constraint/validity error (not the RLS denial 42501) — the probe's own value, not a policy result"))
                    elif o[0] == "err": asrt = f"SELECT throws_ok( $$ {act} $$, '{o[1]}', NULL, {desc(cmd + ': ' + who + ' denied (' + o[1] + ')')} );"
                    elif o[0] == "rows" and o[1] >= 1: asrt = f"SELECT isnt_empty( $$ {act} RETURNING 1 $$, {desc(cmd + ': ' + who + ' affected ' + str(o[1]) + ' row(s)')} );"
                    else: asrt = f"SELECT is_empty( $$ {act} RETURNING 1 $$, {desc(cmd + ': ' + who + ' affects 0 rows')} );"
                n[0] += 1
                body.append("RESET ROLE;")
                body.append(f"DELETE FROM {q};")
                if cmd != "INSERT": body.append(seedrow + ";")
                if guc: body.append(f"SELECT set_config('{guc[0]}', '{guc[1]}', true);")
                body.extend(["SELECT set_config('request.jwt.claims', '', true);", "SET LOCAL ROLE anon;"] if role == "anon"
                            else [f"SELECT set_config('request.jwt.claims', {_qlit(claims)}, true);", "SET LOCAL ROLE authenticated;"])
                body.append(asrt)
                body.append("RESET ROLE;")
                body.append(reseed)
            one("authenticated, authorized", Va, "authenticated")
            one("authenticated, not authorized", Vb, "authenticated")
            one("anon", Vb if gate["kind"] == "guc" else None, "anon")   # GUC: give anon a valid (mismatch) value so the ::uuid cast can't 22P02
            return True
        def synth_recursion_emit(cmd, rg):
            """Seed an ancestor chain (root owned by the user + a descendant) so a self-referential
            hierarchy policy admits the descendant; probe-verify. SELECT only."""
            if cmd != "SELECT": return False
            owner, sfk, pk = rg["owner"], rg["self_fk"], rg["pk"]
            req, _ = _synth_required_cols(conn, schema, table, fkmap)
            fkc = set(fkmap.get(f"{schema}.{table}", {}))
            extra = {}
            for rn, rt in req:
                if rn in (owner, sfk): continue
                if rn in fkc: return False   # another required FK we can't parent -> honest fall-through
                extra[rn] = fill(rt)
            xc = ("" if not extra else ", " + ", ".join(extra))
            xv = ("" if not extra else ", " + ", ".join(extra.values()))
            U, U2 = "cccccccc-0000-4000-8000-00000000cccc", "dddddddd-0000-4000-8000-00000000dddd"
            arrange = [f"DELETE FROM {q}",
                       f"INSERT INTO auth.users(id) VALUES ('{U}') ON CONFLICT DO NOTHING",
                       f"INSERT INTO {q}({owner}{xc}) VALUES ('{U}'{xv})",                                   # root owned by U
                       f"INSERT INTO {q}({sfk}{xc}) VALUES ((SELECT {pk} FROM {q} WHERE {owner}='{U}' ORDER BY {pk} LIMIT 1){xv})"]  # descendant under root
            def one(who, sub, role):
                claims = None if role == "anon" else json.dumps({"sub": sub, "role": "authenticated"})
                pidl = (["SELECT set_config('request.jwt.claims', '', true)", "SET LOCAL ROLE anon"] if role == "anon"
                        else [f"SELECT set_config('request.jwt.claims', {_qlit(claims)}, true)", "SET LOCAL ROLE authenticated"])
                o = _probe(conn, arrange, pidl, "read", f"SELECT count(*) FROM {q}")
                if o[2]: asrt = _unrel_fail(desc, "SELECT: " + who, o)
                else: asrt = (f"SELECT is( (SELECT count(*) FROM {q})::int, {o[1]}, {desc('SELECT: ' + who + ' sees ' + str(o[1]) + ' row(s) (recursive hierarchy)')} );" if o[0] == "count"
                              else f"SELECT throws_ok( $$ SELECT 1 FROM {q} $$, '{o[1]}', NULL, {desc('SELECT: ' + who + ' denied (' + o[1] + ')')} );")
                n[0] += 1
                body.append("RESET ROLE;")
                body.extend(a + ";" for a in arrange)
                body.extend(s + ";" for s in pidl)
                body.append(asrt); body.append("RESET ROLE;"); body.append(reseed)
            one("authenticated, authorized", U, "authenticated")
            one("authenticated, not authorized", U2, "authenticated")
            one("anon", None, "anon")
            return True
        def solve_emit(cmd, node=None):
            """General fallback: derive a witness for an ARBITRARY predicate, VERIFY it against the DB, and
            bake the observed grant/deny pair. With `node` given, solve THAT one predicate (per-min-term
            fallback for an unhandled branch, BL-1); otherwise iterate the table's permissive policies (the
            all-NT case). Skips opaque-fn tables (mock owns those). An unconfirmed witness bakes nothing -> NT."""
            if udfs:
                return False
            if node is not None:
                _cands = [node]
            else:
                _c = conn.cursor()
                _c.execute("SELECT qual, with_check FROM pg_policies WHERE schemaname=%s AND tablename=%s AND cmd IN (%s,'ALL') AND permissive='PERMISSIVE'", (schema, table, cmd))
                _cands = [_where(wc if (cmd == "INSERT" and wc) else qual) for (qual, wc) in _c.fetchall()]
            _req, _bad = _synth_required_cols(conn, schema, table, fkmap)
            if _bad:
                return False
            for expr_node in _cands:
                if expr_node is None:
                    continue
                plan = _solve_predicate(expr_node, coltypes, enums)
                if not plan or plan[0] is None or plan[1] is None:   # need BOTH a true and a false witness for a grant/deny pair
                    continue
                sat, fal = plan
                def ctx_sql(ctx):
                    base = {"role": ctx.get("role", "authenticated")}
                    if ctx.get("sub"): base["sub"] = ctx["sub"]
                    for keys, val in ctx["claims"]:
                        _set_claim(base, keys, val)
                    rowcols = {cc: _wv_lit(coltypes.get(cc, "text"), vv) for cc, vv in ctx["row"].items()}
                    aux = []
                    for a in ctx["aux"]:
                        aux += _seed_one(a["table"], {k: f"'{v}'" for k, v in a["cols"].items()}, fkmap, colsmap, enums)
                    return json.dumps(base), [f"SELECT set_config('{k}', '{v}', true)" for k, v in ctx["guc"].items()], rowcols, aux
                s_claims, s_gucs, s_row, s_aux = ctx_sql(sat)
                f_claims, f_gucs, f_row, f_aux = ctx_sql(fal)
                parents, base_row = _mock_valid_row(schema, table, fkmap, colsmap, enums, checks, relchecks, compfks)
                def rowins(over):
                    rr = dict(base_row); rr.update(over)
                    return f"INSERT INTO {q}({', '.join(rr)}) VALUES ({', '.join(rr.values())})"
                def idsql(claims, gucs):
                    return list(gucs) + [f"SELECT set_config('request.jwt.claims', {_qlit(claims)}, true)", "SET LOCAL ROLE authenticated"]
                if cmd == "SELECT":
                    arr_t = [f"DELETE FROM {q}"] + parents + s_aux + [rowins(s_row)]
                    arr_f = [f"DELETE FROM {q}"] + parents + f_aux + [rowins(f_row)]
                    ot = _probe(conn, arr_t, idsql(s_claims, s_gucs), "read", f"SELECT count(*) FROM {q}")
                    of = _probe(conn, arr_f, idsql(f_claims, f_gucs), "read", f"SELECT count(*) FROM {q}")
                    if ot[2] or of[2] or not (ot[0] == "count" and ot[1] >= 1 and of[0] == "count" and of[1] == 0):
                        continue   # DB didn't confirm the witness (or precondition unreliable) -> try the next policy, else stay NT
                    n[0] += 1
                    body.append("RESET ROLE;"); body.extend(s + ";" for s in arr_t); body.extend(s + ";" for s in idsql(s_claims, s_gucs))
                    body.append(f"SELECT is( (SELECT count(*) FROM {q})::int, {ot[1]}, {desc('SELECT: authenticated, authorized sees its row(s) [solver]')} );")
                    body.append("RESET ROLE;")
                    n[0] += 1
                    body.append("RESET ROLE;"); body.extend(s + ";" for s in arr_f); body.extend(s + ";" for s in idsql(f_claims, f_gucs))
                    body.append(f"SELECT is( (SELECT count(*) FROM {q})::int, 0, {desc('SELECT: authenticated, not authorized sees nothing [solver]')} );")
                    body.append("RESET ROLE;"); body.append(reseed)
                    return True
                if cmd == "INSERT":
                    act_t, act_f = rowins(s_row), rowins(f_row)
                    arr_t = [f"DELETE FROM {q}"] + parents + s_aux
                    arr_f = [f"DELETE FROM {q}"] + parents + f_aux
                else:
                    if cmd == "UPDATE":
                        if not upd_col:
                            continue
                        act_t = act_f = f"UPDATE {q} SET {upd_col[0]}={_upd_val(upd_col[0], upd_col[1])}"
                    else:
                        act_t = act_f = f"DELETE FROM {q}"
                    arr_t = [f"DELETE FROM {q}"] + parents + s_aux + [rowins(s_row)]
                    arr_f = [f"DELETE FROM {q}"] + parents + f_aux + [rowins(f_row)]
                ot = _probe(conn, arr_t, idsql(s_claims, s_gucs), "write", act_t)
                of = _probe(conn, arr_f, idsql(f_claims, f_gucs), "write", act_f)
                if ot[2] or of[2] or not ((ot[0] == "rows" and ot[1] >= 1) and (of[0] == "err" or (of[0] == "rows" and of[1] == 0))):
                    continue
                n[0] += 1
                body.append("RESET ROLE;"); body.extend(s + ";" for s in arr_t); body.extend(s + ";" for s in idsql(s_claims, s_gucs))
                body.append(f"SELECT {'lives_ok' if cmd == 'INSERT' else 'isnt_empty'}( $$ {act_t}{'' if cmd == 'INSERT' else ' RETURNING 1'} $$, {desc(cmd + ': authenticated, authorized may act [solver]')} );")
                body.append("RESET ROLE;"); body.append(reseed)
                n[0] += 1
                body.append("RESET ROLE;"); body.extend(s + ";" for s in arr_f); body.extend(s + ";" for s in idsql(f_claims, f_gucs))
                if of[0] == "err":
                    body.append(f"SELECT throws_ok( $$ {act_f} $$, '{of[1]}', NULL, {desc(cmd + ': authenticated, not authorized denied (' + of[1] + ') [solver]')} );")
                else:
                    body.append(f"SELECT is_empty( $$ {act_f} RETURNING 1 $$, {desc(cmd + ': authenticated, not authorized affects 0 rows [solver]')} );")
                body.append("RESET ROLE;"); body.append(reseed)
                return True
            return False

        _cur = conn.cursor()   # every command that HAS a policy (analyzer's cmds may omit opaque-fn ones)
        _cur.execute("SELECT DISTINCT cmd FROM pg_policies WHERE schemaname=%s AND tablename=%s", (schema, table))
        _pol = set()
        for (_cm,) in _cur.fetchall():
            _pol |= set(_CMDS4) if _cm == "ALL" else ({_cm} if _cm in _CMDS4 else set())
        for cmd in [c for c in _CMDS4 if c in (set(cmds) | _pol)]:
            _all_cls = per.get(cmd, {}).get("classes", [])
            classes = [c for c in _all_cls if c["handled"]]
            # MIXED case: a classifiable policy AND a SEPARATE opaque-function policy OR'd together (permissive).
            # The classifiable branch is probed below; without this the function branch would be left shadowed
            # (NOT_TESTABLE, untested). Mock-wire it too so the function branch is proven to grant/deny, and so
            # the report flags + highlights the mocking on those cells.
            _shadowed_fn = bool(classes) and bool(udfs) and any((not cc.get("handled")) and "function" in (cc.get("reason") or "") for cc in _all_cls)
            if not classes:
                gate = _synth_gate(conn, schema, table, cmd, coltypes)   # GUC / JWT-claim gate -> SET the input + SEED a match
                if gate and synth_emit(cmd, gate):
                    continue
                rg = _synth_recursion_gate(conn, schema, table, fkmap)   # self-referential hierarchy -> SEED an ancestor chain
                if rg and synth_recursion_emit(cmd, rg):
                    continue
                if udfs:                                                  # opaque function -> MOCK it (wiring)
                    mock_emit(cmd)
                elif solve_emit(cmd):                                      # general witness solver (DB-verified) -> last resort before NOT_TESTABLE
                    continue
            elif _shadowed_fn:                                            # mixed: also wiring-test the shadowed opaque-fn branch
                mock_emit(cmd)
            # BL-1: a classifiable branch handled this command, but OTHER min-terms carry a novel (unclassified)
            # atom (e.g. `owner=auth.uid() OR metadata @> '...'`). Solve each unhandled branch per-min-term and
            # DB-verify it, so the novel branch is no longer silently dropped to NT. (not udfs: opaque-fn branches
            # are mock-wired above, not solved.)
            if classes and not udfs:
                for _uc in [c for c in _all_cls if not c.get("handled") and c.get("raw_atoms")]:
                    _ra = _uc["raw_atoms"]
                    solve_emit(cmd, node=(_ra[0] if len(_ra) == 1 else {"BoolExpr": {"boolop": "AND_EXPR", "args": _ra}}))
            for who, cjson, role, c in identities(classes):
                if cmd == "SELECT":
                    o = _probe(conn, arrange_stmts, pident(cjson, role), "read", f"SELECT count(*) FROM {q}")
                    if o[2]:
                        _a = _unrel_fail(desc, "SELECT: " + who, o)
                    elif o[0] == "count":
                        _a = f"SELECT is( (SELECT count(*) FROM {q})::int, {o[1]}, {desc('SELECT: ' + who + ' sees ' + str(o[1]) + ' row(s)')} );"
                    else:
                        _a = f"SELECT throws_ok( $$ SELECT 1 FROM {q} $$, '{o[1]}', NULL, {desc('SELECT: ' + who + ' denied (' + o[1] + ')')} );"
                    read_test(cjson, role, _a)
                    continue
                if cmd == "INSERT":
                    icols = insert_plan[c["idx"]][1] if (c is not None and c["idx"] in insert_plan) else nobody_ins
                    if not icols: continue
                    action = f"INSERT INTO {q}({', '.join(icols)}) VALUES ({', '.join(icols.values())})"
                elif cmd == "UPDATE":
                    if not upd_col: continue
                    # SET <plain non-FK col> = <literal>: needs ONLY the UPDATE privilege (a literal RHS
                    # avoids the SELECT-on-read requirement of `col=col`), and a non-FK col avoids an RI
                    # false-denial. upd_col already excludes FK/identity/handled cols.
                    action = f"UPDATE {q} SET {upd_col[0]}={_upd_val(upd_col[0], upd_col[1])}"
                else:
                    action = f"DELETE FROM {q}"
                o = _probe(conn, arrange_stmts, pident(cjson, role), "write", action)
                if o[2]:
                    mut_test(cjson, role, _unrel_fail(desc, cmd + ": " + who, o))
                elif o[0] == "err" and o[1] != "42501":
                    # the action raised a NON-RLS error (RLS denial is always 42501). e.g. a CHECK (23514),
                    # FK (23503), NOT NULL (23502) or cast (22xxx) from our own SET/INSERT value -> the probe's
                    # action was malformed, not a policy denial. Mark UNRELIABLE; never bake it as "denied".
                    mut_test(cjson, role, _unrel_fail(desc, cmd + ": " + who, ("err", o[1], "the test action raised " + o[1] + ", a constraint/validity error (not the RLS denial 42501) — the probe's own value, not a policy result")))
                elif o[0] == "err":
                    mut_test(cjson, role, f"SELECT throws_ok( $$ {action} $$, '{o[1]}', NULL, {desc(cmd + ': ' + who + ' denied (' + o[1] + ')')} );")
                elif o[0] == "rows" and o[1] >= 1:
                    mut_test(cjson, role, f"SELECT isnt_empty( $$ {action} RETURNING 1 $$, {desc(cmd + ': ' + who + ' affected ' + str(o[1]) + ' row(s)')} );")
                else:
                    mut_test(cjson, role, f"SELECT is_empty( $$ {action} RETURNING 1 $$, {desc(cmd + ': ' + who + ' affects 0 rows')} );")
                # TRANSITION AUDIT (cross-policy WITH CHECK leak): an authorized identity that CAN update
                # should only be able to write the column-values ITS OWN policy's WITH CHECK permits. Postgres
                # OR-combines every permissive policy's WITH CHECK independently of which USING matched, so an
                # identity can often write a value only a DIFFERENT policy intended. Enumerate the (enum) domain,
                # observe which forbidden values are actually accepted, and bake a failing assertion for each.
                if cmd == "UPDATE" and c is not None and c.get("src_check"):   # run the value-space audit regardless of the neutral-column probe (which can fail when the combined WITH CHECK excludes the seeded status)
                    _vc = _check_value_set(c["src_check"])
                    if _vc:
                        _vcol, _allowed = _vc
                        _ctype = coltypes.get(_vcol)
                        _dom = (enums.get(_ctype) or enums.get((_ctype or "").split(".")[-1])) if _ctype else None
                        if _dom and _vcol != (upd_col[0] if upd_col else None):
                            for _V in _dom:
                                if _V in _allowed:
                                    continue
                                _tact = f"UPDATE {q} SET {_vcol}='{_V}'::{_ctype}"
                                _ov = _probe(conn, arrange_stmts, pident(cjson, role), "write", _tact)
                                if _ov[0] == "rows" and _ov[1] >= 1 and not _ov[2]:   # accepted a value its own policy forbids -> leak (skip if precondition was unreliable)
                                    mut_test(cjson, role, f"SELECT throws_ok( $$ {_tact} $$, '42501', NULL, {desc('UPDATE: ' + who + ' can set ' + _vcol + '=' + _V + ', but policy [' + str(c.get('src_policy')) + '] WITH CHECK permits only {' + ', '.join(sorted(_allowed)) + '} -- cross-policy WITH CHECK leak [transition-leak]')} );")

    body_text = "\n".join(body)
    if helpers:
        creates = "\n".join(
            f"INSERT INTO auth.users (id, email, raw_user_meta_data, raw_app_meta_data, created_at, updated_at) "
            f"VALUES ('{sub}', concat('{sub}', '@test.com'), jsonb_build_object('test_identifier', '{nm}'), '{{}}'::jsonb, now(), now()) ON CONFLICT (id) DO NOTHING;"
            for sub, nm in umap.items())
        header = f"""-- GENERATED by rlsautotest (flat, helper-mode) from {q}.
-- {_TAGLINE} {_TAGLINE2}
-- Native pgTAP using the tests.* helpers (basejump or the rlsautotest offline shim in 000-setup-tests-hooks.sql).
-- Test users are created with fixed uids (= the seed uuids) so authenticate_as() lines up with the seed.
{_PGTAP_ENSURE}
BEGIN;
SELECT plan({n[0]});
-- Arrange: create test users (fixed uids), then seed as the privileged (RLS-bypassing) connection role.
-- NOTE: grants are NOT re-granted — tests run against the database's real grants so a missing grant is proven, not masked.
{creates}
DELETE FROM {q};
{seed}
"""
    else:
        header = f"""-- GENERATED by rlsautotest (flat, self-contained / --no-helpers) from {q}.
-- {_TAGLINE} {_TAGLINE2}
-- Native pgTAP. Runs standalone via `supabase test db`, pg_prove, or psql. No 000-hook needed.
{_PGTAP_ENSURE}
BEGIN;
SELECT plan({n[0]});
-- Arrange: seed as the privileged (RLS-bypassing) connection role.
-- NOTE: grants are NOT re-granted — tests run against the database's real grants so a missing grant is proven, not masked.
DELETE FROM {q};
{seed}
"""
    return header + "\n" + body_text + "\n\nSELECT * FROM finish();\nROLLBACK;\n"


def coverage(per, cmds):
    o = c = 0
    for cmd in cmds:
        for cl in per[cmd]["classes"]:
            for _ in ("authorized", "unauthorized"):
                o += 1
                if cl["handled"]: c += 1
    return c, o


def _sq(name):
    return name.split(".", 1) if "." in name else ("public", name)


_FK_SQL = """SELECT a.attname, nf.nspname, cf.relname, af.attname
FROM pg_constraint k
JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace
JOIN pg_class cf ON cf.oid=k.confrelid JOIN pg_namespace nf ON nf.oid=cf.relnamespace
JOIN pg_attribute a ON a.attrelid=k.conrelid AND a.attnum=k.conkey[1]
JOIN pg_attribute af ON af.attrelid=k.confrelid AND af.attnum=k.confkey[1]
WHERE n.nspname=%s AND c.relname=%s AND k.contype='f' AND array_length(k.conkey,1)=1"""


_SHIM = r"""-- rlsautotest offline shim: basejump-API-compatible tests.* helpers, no database.dev / network.
-- Emitted only when basejump's supabase_test_helpers are NOT already installed.
CREATE SCHEMA IF NOT EXISTS tests;
GRANT USAGE ON SCHEMA tests TO anon, authenticated, service_role;
CREATE OR REPLACE FUNCTION tests.create_supabase_user(identifier text, email text DEFAULT NULL, phone text DEFAULT NULL, metadata jsonb DEFAULT NULL)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = auth, pg_temp AS $fn$
DECLARE user_id uuid;
BEGIN
  user_id := gen_random_uuid();
  INSERT INTO auth.users (id, email, phone, raw_user_meta_data, raw_app_meta_data, created_at, updated_at)
  VALUES (user_id, coalesce(email, concat(user_id, '@test.com')), phone,
          jsonb_build_object('test_identifier', identifier) || coalesce(metadata, '{}'::jsonb), '{}'::jsonb, now(), now());
  RETURN user_id;
END $fn$;
CREATE OR REPLACE FUNCTION tests.get_supabase_uid(identifier text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = auth, pg_temp AS $fn$
DECLARE u uuid;
BEGIN
  SELECT id INTO u FROM auth.users WHERE raw_user_meta_data ->> 'test_identifier' = identifier LIMIT 1;
  IF u IS NULL THEN RAISE EXCEPTION 'User with identifier % not found', identifier; END IF;
  RETURN u;
END $fn$;
CREATE OR REPLACE FUNCTION tests.get_supabase_user(identifier text)
RETURNS json LANGUAGE plpgsql SECURITY DEFINER SET search_path = auth, pg_temp AS $fn$
DECLARE j json;
BEGIN
  SELECT json_build_object('id', id, 'email', email, 'phone', phone,
         'raw_user_meta_data', raw_user_meta_data, 'raw_app_meta_data', raw_app_meta_data) INTO j
  FROM auth.users WHERE raw_user_meta_data ->> 'test_identifier' = identifier LIMIT 1;
  IF j IS NULL OR j -> 'id' IS NULL THEN RAISE EXCEPTION 'User with identifier % not found', identifier; END IF;
  RETURN j;
END $fn$;
CREATE OR REPLACE FUNCTION tests.authenticate_as(identifier text) RETURNS void LANGUAGE plpgsql AS $fn$
DECLARE u json;
BEGIN
  u := tests.get_supabase_user(identifier);
  PERFORM set_config('role', 'authenticated', true);
  PERFORM set_config('request.jwt.claims', json_build_object('sub', u ->> 'id', 'role', 'authenticated', 'email', u ->> 'email',
          'phone', u ->> 'phone', 'user_metadata', u -> 'raw_user_meta_data', 'app_metadata', u -> 'raw_app_meta_data')::text, true);
END $fn$;
CREATE OR REPLACE FUNCTION tests.authenticate_as_service_role() RETURNS void LANGUAGE plpgsql AS $fn$
BEGIN PERFORM set_config('role', 'service_role', true); PERFORM set_config('request.jwt.claims', null, true); END $fn$;
CREATE OR REPLACE FUNCTION tests.clear_authentication() RETURNS void LANGUAGE plpgsql AS $fn$
BEGIN PERFORM set_config('role', 'anon', true); PERFORM set_config('request.jwt.claims', null, true); END $fn$;
"""


_PGTAP_ENSURE = r"""-- Make pgTAP available with ZERO setup: use the real extension if installed; otherwise load a minimal,
-- TAP-compatible shim. The shim is created ONLY when pgTAP is absent, so a real install (e.g. on Supabase)
-- is always preferred and never shadowed. Numbering uses a sequence so it survives SAVEPOINT rollbacks.
DO $rlsa$
BEGIN
  BEGIN CREATE EXTENSION IF NOT EXISTS pgtap; EXCEPTION WHEN OTHERS THEN NULL; END;
  IF to_regprocedure('plan(integer)') IS NULL THEN
    EXECUTE $b$ CREATE OR REPLACE FUNCTION public._rlsa_num() RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER AS $q$ BEGIN RETURN nextval('__rlsa_tapno'); END $q$ $b$;
    EXECUTE $b$ CREATE OR REPLACE FUNCTION public._rlsa_ok(boolean, text) RETURNS text LANGUAGE sql AS $q$ SELECT (CASE WHEN $1 THEN 'ok ' ELSE 'not ok ' END) || public._rlsa_num() || ' - ' || coalesce($2,'') $q$ $b$;
    EXECUTE $b$ CREATE OR REPLACE FUNCTION public.plan(integer) RETURNS text LANGUAGE plpgsql SECURITY DEFINER AS $q$ BEGIN EXECUTE 'DROP SEQUENCE IF EXISTS pg_temp.__rlsa_tapno'; EXECUTE 'CREATE TEMP SEQUENCE __rlsa_tapno'; RETURN '1..'||$1; END $q$ $b$;
    EXECUTE $b$ CREATE OR REPLACE FUNCTION public.finish() RETURNS SETOF text LANGUAGE plpgsql AS $q$ BEGIN RETURN; END $q$ $b$;
    EXECUTE $b$ CREATE OR REPLACE FUNCTION public.is(anyelement, anyelement, text) RETURNS text LANGUAGE sql AS $q$ SELECT public._rlsa_ok($1 IS NOT DISTINCT FROM $2, $3) $q$ $b$;
    EXECUTE $b$ CREATE OR REPLACE FUNCTION public.lives_ok(text, text) RETURNS text LANGUAGE plpgsql AS $q$ BEGIN EXECUTE $1; RETURN public._rlsa_ok(true, $2); EXCEPTION WHEN OTHERS THEN RETURN public._rlsa_ok(false, $2); END $q$ $b$;
    EXECUTE $b$ CREATE OR REPLACE FUNCTION public.throws_ok(text, text, text, text) RETURNS text LANGUAGE plpgsql AS $q$ BEGIN EXECUTE $1; RETURN public._rlsa_ok(false, $4); EXCEPTION WHEN OTHERS THEN RETURN public._rlsa_ok(SQLSTATE = $2, $4); END $q$ $b$;
    EXECUTE $b$ CREATE OR REPLACE FUNCTION public.is_empty(text, text) RETURNS text LANGUAGE plpgsql AS $q$ DECLARE r record; f boolean := false; BEGIN FOR r IN EXECUTE $1 LOOP f := true; EXIT; END LOOP; RETURN public._rlsa_ok(NOT f, $2); END $q$ $b$;
    EXECUTE $b$ CREATE OR REPLACE FUNCTION public.isnt_empty(text, text) RETURNS text LANGUAGE plpgsql AS $q$ DECLARE r record; f boolean := false; BEGIN FOR r IN EXECUTE $1 LOOP f := true; EXIT; END LOOP; RETURN public._rlsa_ok(f, $2); END $q$ $b$;
    EXECUTE $b$ CREATE OR REPLACE FUNCTION public.fail(text) RETURNS text LANGUAGE sql AS $q$ SELECT public._rlsa_ok(false, $1) $q$ $b$;
  END IF;
END
$rlsa$;"""


def _basejump_present(cur):
    cur.execute("SELECT to_regprocedure('tests.authenticate_as(text)') IS NOT NULL")
    return bool(cur.fetchone()[0])


_HOOK_SELFTEST = (
    "\n-- Make this setup hook a VALID, trivially-passing pgTAP test. Runners that execute every .sql\n"
    "-- file in the folder (pg_prove, `supabase test db`) would otherwise report 'No plan found in TAP\n"
    "-- output' for a hook that emits no assertions and fail the whole run. The setup above runs OUTSIDE\n"
    "-- any transaction so it persists for the test files that follow; only this one assertion is the test.\n"
    "SELECT plan(1);\n"
    "SELECT is(1, 1, 'rlsautotest setup hook loaded');\n"
    "SELECT * FROM finish();\n")


def setup_hook_sql(basejump_present):
    """000-setup-tests-hooks.sql content: pgtap + (offline shim iff basejump absent) + a self-test pass."""
    head = ("-- GENERATED by rlsautotest. Pre-test hook (runs first, alphabetically).\n"
            f"-- {_TAGLINE} {_TAGLINE2}\n" + _PGTAP_ENSURE + "\n")
    if basejump_present:
        return head + "-- basejump supabase_test_helpers detected; using them.\n" + _HOOK_SELFTEST
    return head + "\n" + _SHIM + _HOOK_SELFTEST


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


def _unrel_fail(desc_fn, label, o):
    """A loud, never-passing pgTAP line for a test whose precondition could not be established. We still
    PROBED (the observation is shown in the message), but a failed precondition must never masquerade as a
    pass -- so this asserts failure and is tagged UNRELIABLE for the report + CI gate to pick up."""
    obs = (str(o[0]) + "=" + str(o[1])) if o[0] != "err" else ("error " + str(o[1]))
    return "SELECT fail( " + desc_fn("UNRELIABLE - " + label + ": " + str(o[2]) + " [probe observed " + obs + "]; precondition not established - investigate seeding") + " );"


def _probe(conn, arrange, ident_sqls, kind, action_sql):
    """Run ONE identity x command at generation time and OBSERVE the real outcome (arrange -> become
    identity -> act), then roll everything back. Returns a 3-tuple (kind, val, unreliable):
      kind/val : ('count', n) read · ('rows', n) write · ('err', sqlstate) denial/error AT ACT TIME
      unreliable: None, or a reason string when the test's PRECONDITION could not be established.

    Two design points that keep probe-and-bake honest:
      * Each arrange statement runs in its OWN savepoint, so a BENIGN seed error (e.g. a redundant
        duplicate insert) does not abort the probe -- we still proceed to the action and bake what we
        actually observe, rather than screaming at the first hiccup.
      * Post-arrange INVARIANT: if we intended to seed the acted-on table but it ends up empty, the
        precondition failed -> `unreliable` is set. The caller then bakes a LOUD, failing test that
        shows the observation but is never a silent pass -- a real seeding failure can no longer be
        mis-baked as a policy denial."""
    cur = conn.cursor()
    cur.execute("SAVEPOINT _rlsa_probe")
    def _done(kind, val, unreliable):
        try: cur.execute("ROLLBACK TO SAVEPOINT _rlsa_probe"); cur.execute("RELEASE SAVEPOINT _rlsa_probe")
        except Exception: pass
        return (kind, val, unreliable)
    try: cur.execute("RESET ROLE")
    except Exception: pass
    seed_err = None
    for s in arrange:                                            # per-statement isolation: tolerate benign seed errors
        if not s.strip(): continue
        cur.execute("SAVEPOINT _rlsa_seed")
        try:
            cur.execute(s); cur.execute("RELEASE SAVEPOINT _rlsa_seed")
        except Exception as e:
            seed_err = seed_err or (getattr(e, "sqlstate", None) or "XX000")
            try: cur.execute("ROLLBACK TO SAVEPOINT _rlsa_seed")
            except Exception: pass
    unreliable = None                                            # post-arrange invariant
    tgt = _action_table(action_sql)
    if tgt and any(re.search(r"insert\s+into\s+" + re.escape(tgt), s or "", re.I) for s in arrange):
        try:
            cur.execute(f"SELECT count(*) FROM {tgt}")
            if int(cur.fetchone()[0]) == 0:
                unreliable = "seeded 0 rows in " + tgt + (f" (seed error {seed_err})" if seed_err else "")
        except Exception as e:
            unreliable = "precondition check failed (" + (getattr(e, "sqlstate", None) or "XX000") + ")"
    try:
        for s in ident_sqls: cur.execute(s)
    except Exception as e:
        ss = getattr(e, "sqlstate", None) or "XX000"
        return _done("err", ss, unreliable or ("identity setup failed (" + ss + ")"))
    try:
        if kind == "read":
            cur.execute(action_sql); return _done("count", int(cur.fetchone()[0]), unreliable)
        cur.execute(action_sql); return _done("rows", cur.rowcount, unreliable)
    except Exception as e:
        return _done("err", getattr(e, "sqlstate", None) or "XX000", unreliable)


def _policy_bool_udfs(conn, schema, table):
    """User-defined boolean functions referenced by this table's policies — candidates to MOCK when the
    policy delegates the decision to an opaque function we can't drive via real inputs (RBAC etc.)."""
    cur = conn.cursor()
    cur.execute("SELECT coalesce(qual,'')||' '||coalesce(with_check,'') FROM pg_policies WHERE schemaname=%s AND tablename=%s", (schema, table))
    blob = " ".join((r[0] or "") for r in cur.fetchall())
    if not blob.strip():
        return []
    cur.execute("""SELECT n.nspname, p.proname, pg_get_function_identity_arguments(p.oid), pg_get_functiondef(p.oid)
        FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_type t ON t.oid=p.prorettype
        WHERE t.typname='bool' AND n.nspname NOT IN ('pg_catalog','information_schema','auth')""")
    out = []
    for nsp, name, args, fdef in cur.fetchall():
        qual = re.search(r'\b' + re.escape(nsp) + r'\.' + re.escape(name) + r'\s*\(', blob)   # schema.fn(
        bare = re.search(r'(?<![\w.])' + re.escape(name) + r'\s*\(', blob)                    # fn( not preceded by a dot
        if qual or bare:
            out.append({"name": name, "q": f'"{nsp}"."{name}"', "args": args, "def": fdef})
    return out


def _synth_required_cols(conn, schema, table, fkmap):
    """NOT NULL, no-default, non-identity/generated columns (must be filled to insert a row).
    Returns (cols list of (name,type), False). The second value used to bail when a required col was a FK,
    but the seeders (_mock_valid_row / _seed_one) now seed FK parents (transitively, ON CONFLICT) and the
    probe VERIFIES the seed, so a required FK is no longer a reason to skip the solver — if seeding still
    fails, the probe's arrange-error path leaves it NT (never a false pass). Kept as a 2-tuple for callers."""
    cur = conn.cursor()
    cur.execute("""SELECT a.attname, format_type(a.atttypid,a.atttypmod)
        FROM pg_attribute a
        WHERE a.attrelid = format('%%I.%%I', %s::text, %s::text)::regclass AND a.attnum>0 AND NOT a.attisdropped
          AND a.attnotnull AND a.attidentity='' AND a.attgenerated=''
          AND NOT EXISTS (SELECT 1 FROM pg_attrdef d WHERE d.adrelid=a.attrelid AND d.adnum=a.attnum)""", (schema, table))
    req = [(r[0], r[1]) for r in cur.fetchall()]
    return req, False


def _synth_gate(conn, schema, table, cmd, coltypes):
    """If the (single) policy for cmd gates on `col = <session GUC / JWT claim>` or `col = ANY(<array claim>)`,
    return a plan to synthesize a matching identity. Probe-verified downstream, so a wrong guess is harmless."""
    fld = "with_check" if cmd == "INSERT" else "qual"
    cur = conn.cursor()
    cur.execute(f"SELECT {fld} FROM pg_policies WHERE schemaname=%s AND tablename=%s AND cmd IN (%s,'ALL')", (schema, table, cmd))
    exprs = [r[0] for r in cur.fetchall() if r[0]]
    if len(exprs) != 1:
        return None
    e = exprs[0]
    m = re.search(r'\(?\s*([a-z_][a-z0-9_]*)\s*\)?\s*=\s*\(*\s*current_setting\(\s*\'([^\']+)\'', e, re.I)
    if m and m.group(1) in coltypes:
        return {"col": m.group(1), "kind": "guc", "name": m.group(2)}
    if "auth.jwt()" in e:
        col = re.search(r'\(?\s*([a-z_][a-z0-9_]*)\s*\)?\s*(?:::\s*\w+)?\s*(?:=|IN\b)', e, re.I)   # tolerate (col)::text = / IN (...)
        keys = re.findall(r"'([^']+)'::text", e)
        if col and col.group(1) in coltypes and keys:
            arr = ("jsonb_array_elements" in e) or re.search(r'=\s*ANY', e, re.I)
            return {"col": col.group(1), "kind": "claim_array" if arr else "claim_scalar", "path": keys}
    return None


def _synth_recursion_gate(conn, schema, table, fkmap):
    """A SELECT policy that walks a self-referential hierarchy (WITH RECURSIVE over this table) from an
    owner=auth.uid() base. Returns {owner, self_fk, pk} to seed an ancestor chain, or None."""
    fks = fkmap.get(f"{schema}.{table}", {})
    self_fk = pk = None
    for col, (parent, pcol) in fks.items():
        if parent in (f"{schema}.{table}", table):
            self_fk, pk = col, pcol; break
    if not self_fk:
        return None
    cur = conn.cursor()
    cur.execute("SELECT qual FROM pg_policies WHERE schemaname=%s AND tablename=%s AND cmd IN ('SELECT','ALL')", (schema, table))
    for (qy,) in cur.fetchall():
        if not qy or "recursive" not in qy.lower() or "auth.uid()" not in qy.lower():
            continue
        m = re.search(r'([a-z_][a-z0-9_]*)\s*=\s*\(*\s*(?:SELECT\s+)?auth\.uid\(\)', qy, re.I) \
            or re.search(r'auth\.uid\(\)\s*\)*\s*=\s*([a-z_][a-z0-9_]*)', qy, re.I)
        if m:
            return {"owner": m.group(1), "self_fk": self_fk, "pk": pk}
    return None


def _load_ctx(cur, schema, table):
    pols, per, cmds, notes = analyze(cur, schema, table)
    cols = _columns(cur, schema, table)
    fkmap, colsmap = {}, {}
    def load(tbl):
        if tbl in colsmap: return
        s2, t2 = _sq(tbl); colsmap[tbl] = _columns(cur, s2, t2)
        cur.execute(_FK_SQL, (s2, t2))
        fks = {col: (f"{ps}.{pt}", pc) for (col, ps, pt, pc) in cur.fetchall()}
        fkmap[tbl] = fks
        for parent, _pc in fks.values(): load(parent)
    load(f"{schema}.{table}")
    for cmd in cmds:
        for c in per[cmd]["classes"]:
            for au in c["aux"]: load(au["table"])
    cur.execute("SELECT n.nspname, t.typname, array_agg(e.enumlabel ORDER BY e.enumsortorder) FROM pg_type t JOIN pg_enum e ON e.enumtypid=t.oid JOIN pg_namespace n ON n.oid=t.typnamespace GROUP BY 1, 2")
    enums = {}
    for nsp, tn, labels in cur.fetchall():
        enums[tn] = labels; enums[f"{nsp}.{tn}"] = labels   # key by both bare and schema-qualified name (format_type may qualify)
    cur.execute("""SELECT a.attname FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace
        JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=ANY(i.indkey)
        WHERE n.nspname=%s AND c.relname=%s AND i.indisunique AND array_length(i.indkey,1)=1""", (schema, table))
    unique_cols = {r[0] for r in cur.fetchall()}
    for tbl in list(colsmap):   # load composite-FK parents (single-col parents are already loaded by load())
        s2, t2 = _sq(tbl)
        for cf in _constraint_meta(cur, s2, t2)[3]:
            load(cf["parent"])
    checks, cuniques, relchecks, compfks = {}, {}, {}, {}   # per-table constraint metadata for seeding
    for tbl in list(colsmap):
        s2, t2 = _sq(tbl); ck, cu, rc, cf = _constraint_meta(cur, s2, t2)
        if ck: checks[tbl] = ck
        if cu: cuniques[tbl] = cu
        if rc: relchecks[tbl] = rc
        if cf: compfks[tbl] = cf
    cov, tot = coverage(per, cmds)
    grants = _effective_grants(cur, schema, table)
    return dict(per=per, cmds=cmds, notes=notes, cols=cols, fkmap=fkmap, colsmap=colsmap,
                enums=enums, unique_cols=unique_cols, cov=cov, tot=tot, grants=grants,
                checks=checks, cuniques=cuniques, relchecks=relchecks, compfks=compfks)


def _emit_both(schema, table, ctx, helpers, conn=None):
    nt = "".join(f"-- FOOTGUN NOTE: {x}\n" for x in ctx["notes"])
    args = (schema, table, ctx["per"], ctx["cmds"], ctx["cols"], ctx["fkmap"], ctx["colsmap"], ctx["enums"], ctx["unique_cols"], ctx["checks"], ctx["cuniques"], ctx["relchecks"], ctx["compfks"])
    return nt + emit_flat(*args, helpers=helpers, grants_map=ctx.get("grants"), conn=conn), nt + emit(*args)


_CMDS4 = ["SELECT", "INSERT", "UPDATE", "DELETE"]


def _split_statements(sql):
    """Split a SQL script on top-level ';', respecting $tag$...$tag$ dollar-quoted bodies,
    '...' string literals, and -- line comments (each can contain a ';' that must NOT split).
    psycopg3 execute() runs only one statement at a time."""
    out, buf, i, n, tag = [], [], 0, len(sql), None
    while i < n:
        if tag:
            if sql.startswith(tag, i): buf.append(tag); i += len(tag); tag = None; continue
            buf.append(sql[i]); i += 1; continue
        ch = sql[i]
        if ch == "-" and i + 1 < n and sql[i + 1] == "-":          # -- line comment
            j = sql.find("\n", i); j = n if j == -1 else j
            buf.append(sql[i:j]); i = j; continue
        if ch == "'":                                               # '...' string literal ('' = escaped quote)
            j = i + 1
            while j < n:
                if sql[j] == "'":
                    if j + 1 < n and sql[j + 1] == "'": j += 2; continue
                    j += 1; break
                j += 1
            buf.append(sql[i:j]); i = j; continue
        m = re.match(r"\$[a-zA-Z0-9_]*\$", sql[i:])
        if m:
            tag = m.group(0); buf.append(tag); i += len(tag); continue
        if ch == ";": out.append("".join(buf)); buf = []; i += 1; continue
        buf.append(ch); i += 1
    if "".join(buf).strip(): out.append("".join(buf))
    return [s for s in out if s.strip()]


_REPORT_SKIP = re.compile(r"^\s*(BEGIN|COMMIT|ROLLBACK)\s*;?\s*$|FROM\s+finish\s*\(", re.I)
_DENY_WORDS = ("unauthorized", "anon", "nothing", "cannot", "affects 0", "out of scope")

# Attribution / funnel — rlsautotest is the free PostgreSQL member of the UnitAutogen family.
_HOME = "https://github.com/unitautogen"
_TAGLINE = "rlsautotest is part of UnitAutogen — automated unit-test generation for your database."
_TAGLINE2 = "Need it for SQL Server (tSQLt), Oracle, or Azure? " + _HOME


def _table_report(cur, conn, schema, table, helpers):
    """Run the SELF-CONTAINED flat battery (robust: seeds as the connection role, no service_role /
    shim dependency) statement-by-statement, collect each pgTAP assertion's returned line, and parse
    its descriptive label into a grant/deny matrix. Rolled back so nothing persists."""
    ctx = _load_ctx(cur, schema, table)
    flat = _emit_both(schema, table, ctx, helpers=False, conn=conn)[0]
    taplines = []
    try:
        for st in _split_statements(flat):
            if not st.strip() or _REPORT_SKIP.match(st):
                continue
            cur.execute("SAVEPOINT _rlsa_rep")   # per-statement isolation: a failing SEED must not abort the
            try:                                  # whole battery -> the UNRELIABLE fail() assertions still run
                cur.execute(st)
                if cur.description:
                    for r in cur.fetchall():
                        v = r[0]
                        if isinstance(v, str) and (v.startswith("ok") or v.startswith("not ok")):
                            taplines.append(v)
                cur.execute("RELEASE SAVEPOINT _rlsa_rep")
            except Exception:
                try: cur.execute("ROLLBACK TO SAVEPOINT _rlsa_rep")
                except Exception: pass
    except Exception:
        pass
    finally:
        conn.rollback()
    cells = {}
    idgrid = {}   # cmd -> { identity -> {"exp": <should-be-able>, "pass": <test passed>} }
    leak_msgs = []   # cross-policy WITH CHECK transition leaks (baked as failing throws_ok lines)
    unreliable_msgs = []   # tests whose precondition (seed) could not be established -> not trustworthy
    unreliable_cells = set()
    for ln in taplines:
        first = ln.strip().split("\n", 1)[0]   # a FAILING pgTAP test returns 'not ok' + '#'-diagnostic lines; parse the 'not ok' line only
        m = re.match(r"(ok|not ok)\b.*?-\s*(.*)$", first)
        if not m: continue
        passed = m.group(1) == "ok"; label = m.group(2)
        if "UNRELIABLE" in label:                              # precondition (seed) failed -> not a grant/deny cell; flag it
            unreliable_msgs.append(label)
            _lowu = label.lower()
            _cmdu = next((c for c in _CMDS4 if c in label.upper()), None)
            _idu = ("anon" if "anon" in _lowu else "other" if any(k in _lowu for k in ("not authoriz", "other user", "non-owner", "unauthorized")) else "authorized")
            if _cmdu: unreliable_cells.add((_cmdu, _idu))
            continue
        if "[transition-leak]" in label:                       # value-space leak; tracked separately, not a per-command cell
            if not passed: leak_msgs.append(label.replace(" [transition-leak]", ""))
            continue
        cmd = next((c for c in _CMDS4 if label.upper().startswith(c)), None)
        if not cmd: continue
        low = label.lower()
        side = "deny" if any(k in low for k in _DENY_WORDS) else "grant"
        d = cells.setdefault(cmd, {}); d[side] = d.get(side, True) and passed
        # per-identity classification (for the access matrix)
        if "out of scope" in low:        # sub-deny on an authorized row; not a primary cell
            continue
        # identity from the label
        if "anon" in low:
            ident = "anon"
        elif any(k in low for k in ("not authoriz", "other user", "non-owner", "unauthorized")):
            ident = "other"   # authenticated but NOT authorized by the policy
        else:
            ident = "authorized"
        # can/blocked from the observed outcome (probe labels) or the derived wording (fallback)
        if any(k in low for k in ("denied", " 0 row", "sees nothing", "blocks", "blocked", "cannot")):
            exp = False
        elif any(k in low for k in ("sees all", "public", "permits", "row(s)", "may ", " can ")):
            exp = True
        else:
            exp = True
        g = idgrid.setdefault(cmd, {}).setdefault(ident, {"exp": exp, "pass": True})
        g["exp"] = exp; g["pass"] = g["pass"] and passed
    cur.execute("SELECT c.relrowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s AND c.relname=%s", (schema, table))
    r = cur.fetchone(); rls_on = bool(r and r[0])
    cur.execute("SELECT cmd FROM pg_policies WHERE schemaname=%s AND tablename=%s", (schema, table))
    pol = set()
    for (cmd,) in cur.fetchall():
        pol |= set(_CMDS4) if cmd == "ALL" else {cmd}
    notes = list(ctx["notes"])
    if any("[mocked" in ln for ln in taplines):
        notes.append("opaque policy function(s) were MOCKED to prove the policy delegates correctly (wiring) — the function's own logic is NOT verified here; test it separately")
    if any("42P17" in ln or "infinite recursion" in ln.lower() for ln in taplines):
        notes.append("BROKEN POLICY: a policy queries its own table (self-referential) -> Postgres raises 'infinite recursion detected in policy' -> the table is UNREADABLE by everyone. Use a SECURITY DEFINER helper function instead.")
    if leak_msgs:
        notes.append("SECURITY HOLE - cross-policy WITH CHECK leak (Postgres OR-combines every permissive policy's WITH CHECK, so an authorized identity can write a value only a DIFFERENT policy intended): " + "; ".join(sorted(set(leak_msgs))))
    if unreliable_msgs:
        notes.append("UNRELIABLE TEST(S) - the test precondition (seed) could not be established for some identity/command, so the result is NOT trustworthy and the suite fails loudly rather than asserting a possibly-wrong outcome (investigate seeding): " + "; ".join(sorted(set(s.replace("UNRELIABLE - ", "") for s in unreliable_msgs))))
    if "UPDATE" in pol and not idgrid.get("UPDATE", {}).get("authorized") and ("UPDATE", "authorized") not in unreliable_cells:
        notes.append("UPDATE not fully tested - no policy-neutral column to modify (every column is PK / FK / unique or referenced by a policy), so the plain UPDATE grant could not be probed by SETting a harmless column. The '-' for UPDATE is a coverage gap, not a pass; review manually.")
    return {"table": table, "rls_enabled": rls_on, "policied": sorted(pol),
            "cells": cells, "idgrid": idgrid, "footguns": notes, "coverage": [ctx["cov"], ctx["tot"]],
            "transition_leaks": leak_msgs, "unreliable": sorted(set(unreliable_msgs)), "unreliable_cells": unreliable_cells}


def emit_rls_guard(cur, schema):
    """Schema-wide guard suite: every table reachable by anon/authenticated MUST have RLS enabled.
    Emitted as 010-rls-enabled.test.sql so a table shipped without RLS becomes a FAILING test —
    closes the 'no policy => no test => CI green' hole. Returns SQL, or None if nothing reachable."""
    reach = [t for (t, _rls, _pol) in all_tables(cur, schema) if _exposed(cur, schema, t)]
    if not reach:
        return None
    lines = ["-- GENERATED by rlsautotest. Schema-wide guard: every table reachable by anon/authenticated must have RLS enabled.",
             f"-- {_TAGLINE} {_TAGLINE2}",
             "-- A table granted to anon/authenticated but with RLS OFF fails here (it would otherwise pass CI silently).",
             _PGTAP_ENSURE, "BEGIN;", f"SELECT plan({len(reach)});"]
    for t in reach:
        lit = f"'\"{schema}\".\"{t}\"'::regclass"
        lines.append(f"SELECT is( (SELECT relrowsecurity FROM pg_class WHERE oid = {lit}), true, "
                     f"'{schema}.{t}: RLS must be enabled (table is reachable by anon/authenticated)' );")
    lines += ["SELECT * FROM finish();", "ROLLBACK;", ""]
    return "\n".join(lines)


# identities shown as rows in each table's access grid (key, display label)
# Rows in each table's access grid: (internal key, display label).
# NOTE: 'authorized' and 'other' are NOT Postgres roles — both connect as the `authenticated`
# role and differ only by JWT identity/claims. Only service_role / authenticated / anon are real
# DB roles. Labels say so explicitly so the grid isn't misread as a per-role matrix.
_ID_ROWS = [("service_role", "service_role"), ("authorized", "authenticated, authorized"),
            ("other", "authenticated, not authorized"), ("anon", "anon")]


def _id_cell(rep, ident, cmd):
    """One identity x command cell -> (glyph, css-class, title).
    glyph: ✓ can · blocked ✗ should-be-allowed-but-blocked.  class 'danger' = can-but-shouldn't (hole)."""
    rls_on = rep["rls_enabled"]; policied = rep.get("policied", []); exposed = rep.get("exposed")
    if ident == "service_role":
        # service_role bypasses RLS, but BYPASSRLS does NOT grant table privileges — it still needs the GRANT.
        # Show ✓ only when it actually holds the grant; otherwise even the service key is denied.
        g = rep.get("grants")
        if g is not None and not g.get(("service_role", cmd), True):
            return ("·", "none", f"service_role has no {cmd} grant on this table — even the service key is denied (grant it if your backend needs it)")
        return ("✓", "svc", "service_role bypasses RLS — full, unfiltered access")
    if not rls_on:
        # RLS off -> access is governed PURELY by GRANTs. A command is an unfiltered hole ONLY if the role
        # actually holds that command's privilege; a missing grant blocks it. Use the per-command grant map
        # (both authenticated identities are the SAME `authenticated` role) rather than a blanket flag.
        role = "anon" if ident == "anon" else "authenticated"
        g = rep.get("grants")
        if g is not None:
            if g.get((role, cmd)):
                return ("✓", "danger", f"RLS off and {role} holds the {cmd} grant — every row is {('readable' if cmd=='SELECT' else 'writable')} unfiltered (no policy constrains it)")
            return ("·", "none", f"RLS off, but {role} has no {cmd} grant — blocked for this command")
        # fallback (no grant map): the old table-level heuristic
        if ident == "anon":
            return ("✓", "danger", "RLS off — anon can read every row") if (exposed and cmd == "SELECT") else ("·", "none", "anon has no grant for this command")
        return ("✓", "danger", "RLS off — any authenticated user has unfiltered access") if exposed else ("·", "none", "RLS off, but no client grant — unreachable via the API")
    if cmd not in policied:
        return ("·", "none", "no policy for this command (implicit deny)")
    if (cmd, ident) in rep.get("unreliable_cells", set()):
        return ("‼", "unrel", "UNRELIABLE — the test precondition (seed) could not be established, so this result is NOT trustworthy (the suite fails loudly here; see notes)")
    g = rep.get("idgrid", {}).get(cmd, {}).get(ident)
    if not g:
        if ident == "anon" and cmd != "SELECT":
            return ("·", "none", "anon has no write grant")
        return ("–", "na", "not tested")
    exp, passed = g["exp"], g["pass"]
    observed_can = exp if passed else (not exp)
    if passed:
        return ("✓", "pass", "can — enforced as declared") if observed_can else ("·", "none", "blocked — enforced as declared")
    if observed_can:
        return ("✓", "danger", "SHOULD be blocked but CAN act — security hole")
    return ("✗", "fail", "SHOULD be allowed but is blocked — policy too strict")


def _table_status(r):
    if not r["rls_enabled"]:
        return ("⛔ RLS OFF — exposed", "danger") if r.get("exposed") else ("⚠ RLS OFF (no client grant)", "warn")
    return ("RLS on", "on")


def render_report_text(reps):
    out = []
    exposed = [r["table"] for r in reps if not r["rls_enabled"] and r.get("exposed")]
    if exposed:
        out.append("⛔ EXPOSED — RLS OFF and readable/writable by anon/authenticated: " + ", ".join(exposed))
        out.append("")
    for r in reps:
        st, _ = _table_status(r)
        out.append(f"{r['table']}  [{st}]")
        out.append(f"  {'identity':<31}" + "".join(f"{c:<9}" for c in _CMDS4))
        for key, lbl in _ID_ROWS:
            line = f"  {lbl:<31}"
            for c in _CMDS4:
                g, cls, _ = _id_cell(r, key, c)
                glyph = g + ("!" if cls == "danger" else "")   # ! = behaves wrong (hole)
                line += f"{glyph:<9}"
            out.append(line)
        for fn in r["footguns"]:
            out.append(f"    ! footgun: {fn}")
        out.append("")
    out.append("legend: ✓ can · blocked/none ✗ should-be-allowed-but-blocked  ✓! = should be blocked but CAN (security hole)  ‼ UNRELIABLE (seed/precondition failed — not trustworthy)  – not tested")
    out.append("service_role bypasses RLS by design (always full access).")
    out.append("note: 'authenticated, authorized' and 'authenticated, not authorized' are the SAME Postgres role (authenticated) under different JWT identities/claims — NOT separate DB roles. Only service_role, authenticated and anon are real Postgres roles; 'authorized' vs 'not authorized' is the policy outcome for that identity.")
    out.append("")
    out.append(_TAGLINE + " " + _TAGLINE2)
    return "\n".join(out)


def render_report_html(reps, schema):
    import html as _h
    esc = _h.escape
    exposed = [r["table"] for r in reps if not r["rls_enabled"] and r.get("exposed")]
    offsafe = [r["table"] for r in reps if not r["rls_enabled"] and not r.get("exposed")]
    def has_hole(r):
        return any(_id_cell(r, k, c)[1] in ("danger", "fail", "unrel") for k, _ in _ID_ROWS for c in _CMDS4)
    holes = [r["table"] for r in reps if has_hole(r)]
    ok_tables = [r for r in reps if r["rls_enabled"] and not has_hole(r)]
    # order: tables with holes/exposure first, then the rest
    order = sorted(reps, key=lambda r: (not has_hole(r), r["table"]))
    blocks = []
    for r in order:
        st, stcls = _table_status(r)
        grid_rows = []
        for key, lbl in _ID_ROWS:
            tds = []
            for c in _CMDS4:
                g, cls, title = _id_cell(r, key, c)
                tds.append(f'<td class="c {cls}" title="{esc(title)}">{g}</td>')
            note = ' <span class="rolenote">bypasses RLS</span>' if key == "service_role" else ""
            grid_rows.append(f'<tr><td class="idn">{esc(lbl)}{note}</td>{"".join(tds)}</tr>')
        flags = "".join(f'<li>{esc(f)}</li>' for f in r.get("footguns", []))
        flags_html = f'<ul class="flags">{flags}</ul>' if flags else ""
        blocks.append(
            f'<section class="tbl"><h2>{esc(r["table"])} <span class="chip {stcls}">{esc(st)}</span></h2>'
            f'<table class="grid"><thead><tr><th>identity</th>'
            + "".join(f"<th>{c}</th>" for c in _CMDS4) + "</tr></thead><tbody>"
            + "".join(grid_rows) + f"</tbody></table>{flags_html}</section>")
    banner = ""
    if exposed:
        banner += f'<div class="ban danger"><b>⛔ Exposed</b> — RLS is OFF and these tables are readable/writable by anon/authenticated: {esc(", ".join(exposed))}</div>'
    if offsafe:
        banner += f'<div class="ban warn"><b>⚠ RLS off</b> (no client grant, but unprotected): {esc(", ".join(offsafe))}</div>'
    summary = (f'{len(reps)} table(s) &middot; '
               f'<span class="kpi {"bad" if exposed else "good"}">{len(exposed)} exposed</span> &middot; '
               f'<span class="kpi {"bad" if holes else "good"}">{len(holes)} with problems</span> &middot; '
               f'<span class="kpi good">{len(ok_tables)} enforced as declared</span>')
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>rlsautotest — RLS report ({esc(schema)})</title>
<style>
 body{{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;color:#1a1a1a}}
 h1{{font-size:1.4rem;margin:0 0 .25rem}} .sub{{color:#666;margin:0 0 1rem}}
 .summary{{margin:.5rem 0 1rem}} .kpi{{font-weight:600}} .good{{color:#15803d}} .bad{{color:#b91c1c}}
 .ban{{padding:.6rem .8rem;border-radius:6px;margin:.4rem 0}}
 .ban.danger{{background:#fee2e2;border:1px solid #fca5a5;color:#7f1d1d}} .ban.warn{{background:#fef3c7;border:1px solid #fcd34d;color:#92400e}}
 section.tbl{{margin:1.5rem 0}}
 section.tbl h2{{font-size:1.05rem;margin:0 0 .4rem}}
 .chip{{font-size:.72rem;font-weight:600;padding:.1rem .5rem;border-radius:999px;vertical-align:middle}}
 .chip.on{{background:#e0f2fe;color:#075985}} .chip.danger{{background:#fee2e2;color:#b91c1c}} .chip.warn{{background:#fef3c7;color:#92400e}}
 table.grid{{border-collapse:collapse;min-width:32rem}}
 .grid th,.grid td{{border:1px solid #e5e7eb;padding:.4rem .7rem}}
 .grid th{{background:#f9fafb;font-weight:600;text-align:center}} .grid th:first-child{{text-align:left}}
 td.idn{{font-weight:600;white-space:nowrap}} .rolenote{{font-weight:400;color:#888;font-size:.78rem}}
 td.c{{text-align:center;font-size:1.05rem}}
 .pass{{background:#dcfce7;color:#15803d}} .none{{color:#94a3b8}} .na{{color:#94a3b8}}
 .svc{{background:#f1f5f9;color:#475569}}
 .danger{{background:#dc2626;color:#fff;font-weight:700}} .fail{{background:#fee2e2;color:#b91c1c;font-weight:700}}
 .unrel{{background:#fde68a;color:#92400e;font-weight:700}}
 ul.flags{{margin:.4rem 0 0;padding-left:1.1rem;color:#92400e;font-size:.85rem}}
 .legend{{color:#666;font-size:.85rem;margin-top:1.5rem;max-width:48rem}}
 .footer{{color:#888;font-size:.8rem;margin-top:1.2rem;border-top:1px solid #eee;padding-top:.6rem}}
</style></head><body>
<h1>RLS access report</h1>
<p class="sub">schema <code>{esc(schema)}</code> &middot; generated by <a href="{_HOME}">rlsautotest</a></p>
<div class="summary">{summary}</div>
{banner}
{"".join(blocks)}
<p class="legend"><b>Each row is an identity, each column a command.</b>
 <span class="c pass">✓</span> can &middot; <span class="c none">·</span> blocked &middot;
 <span class="c danger">✓</span> can but <b>should be blocked</b> (security hole) &middot;
 <span class="c fail">✗</span> should be allowed but is blocked &middot;
 <span class="c unrel">‼</span> UNRELIABLE — seed/precondition failed, result not trustworthy &middot; – not tested.
 <b>service_role</b> bypasses RLS by design. “Enforced as declared” means the database behaves the way your
 policies say — not that the policies are what you intended.</p>
<p class="legend"><b>About the identities:</b> <code>authenticated, authorized</code> and
 <code>authenticated, not authorized</code> are the <b>same Postgres role</b> (<code>authenticated</code>)
 under different JWT identities/claims — they are <b>not</b> separate database roles. Only
 <code>service_role</code>, <code>authenticated</code> and <code>anon</code> are real Postgres roles;
 “authorized” vs “not authorized” is simply whether that identity passes the table’s policies.</p>
<p class="footer">{esc(_TAGLINE)} <a href="{_HOME}">Need it for SQL Server (tSQLt), Oracle, or Azure?</a></p>
</body></html>
"""


# ══════════════════════════════════════════════════════════════════════════════
# SUBCOMMAND HANDLERS  (lint · snapshot · diff · users · coverage · init)
# ══════════════════════════════════════════════════════════════════════════════

_SEV_ORDER = {"INFO": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
_SEV_ICON  = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "INFO": "🔵"}


# ── lint ─────────────────────────────────────────────────────────────────────
def _lint_table(cur, schema, table):
    """Static analysis of one table's RLS policies — no test execution."""
    cur.execute("""SELECT c.relrowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                   WHERE n.nspname=%s AND c.relname=%s""", (schema, table))
    row = cur.fetchone()
    if not row:
        return []
    rls_on = bool(row[0])
    cur.execute("""SELECT policyname, permissive, roles, cmd, qual, with_check
                   FROM pg_policies WHERE schemaname=%s AND tablename=%s ORDER BY policyname""",
                (schema, table))
    policies = cur.fetchall()
    findings = []

    if not rls_on and policies:
        findings.append(("L008", "MEDIUM", table, None, "RLS disabled but policies exist — policies are dead (never evaluated)"))
        return findings

    if not policies:
        if rls_on:
            findings.append(("L004", "HIGH", table, None,
                              "RLS enabled but no policies — all access implicitly denied for every role"))
        return findings

    # derive which commands have at least one policy
    expanded = set()
    for (_, _, _, cmd, _, _) in policies:
        c = (cmd or "ALL").upper()
        expanded |= ({"SELECT","INSERT","UPDATE","DELETE"} if c == "ALL" else {c})
    if "DELETE" not in expanded:
        findings.append(("L010", "INFO", table, None,
                          "No DELETE policy — implicit deny for DELETE (add one or document intent)"))

    for (pname, permissive, roles, cmd, qual, with_check) in policies:
        cmd_eff = (cmd or "ALL").upper()
        q = (qual or "").strip()
        wc = (with_check or "").strip()
        role_list = list(roles or [])

        # L001: USING(true) on a permissive policy
        if q.lower() in ("true", "(true)") and permissive == "PERMISSIVE":
            anon_in = not role_list or "anon" in role_list
            findings.append(("L001", "CRITICAL" if anon_in else "HIGH", table, pname,
                              "USING(true) — permissive open read; " +
                              ("anon + authenticated" if anon_in else "authenticated") +
                              " users can read ALL rows"))

        # L002: WITH CHECK(true) on a permissive policy
        if wc.lower() in ("true", "(true)") and permissive == "PERMISSIVE":
            findings.append(("L002", "CRITICAL", table, pname,
                              "WITH CHECK(true) — permissive open write; authorized users can write any row"))

        # L003: UPDATE/ALL with USING but no WITH CHECK
        if cmd_eff in ("UPDATE", "ALL") and q and not wc:
            findings.append(("L003", "HIGH", table, pname,
                              "UPDATE policy has USING but no WITH CHECK — rows can be moved out of authorized scope"))

        # L009: USING ≠ WITH CHECK on UPDATE (asymmetric scope)
        if cmd_eff in ("UPDATE", "ALL") and q and wc and q.lower() != wc.lower():
            findings.append(("L009", "INFO", table, pname,
                              f"USING ≠ WITH CHECK: read scope ({q[:60]!r}) differs from write scope ({wc[:60]!r})"))

        # L005: opaque user-defined function in policy (not auth.* / pg_catalog)
        both = f"{q} {wc}"
        udfs = re.findall(r'\b(?!auth\.|pgsodium\.|extensions\.|pg_catalog\.)([a-z_]\w*\.[a-z_]\w*)\s*\(', both, re.I)
        udfs = [u for u in udfs if not u.startswith(("storage.", "public."))]
        if udfs:
            findings.append(("L005", "HIGH", table, pname,
                              f"Policy calls user-defined function(s): {udfs} — logic is opaque and won't be auto-tested by rlsautotest"))

        # L007: permissive policy grants anon full SELECT with no real restriction
        if permissive == "PERMISSIVE" and "anon" in role_list and cmd_eff in ("SELECT","ALL"):
            if q.lower() in ("true", "(true)"):
                findings.append(("L007", "MEDIUM", table, pname,
                                  "Permissive policy grants anon full SELECT — verify public read is intentional"))

        # L006: self-referential policy → infinite recursion risk
        full_table = f"{schema}.{table}"
        if re.search(rf'\b{re.escape(table)}\b', both, re.I) or full_table.lower() in both.lower():
            findings.append(("L006", "HIGH", table, pname,
                              f"Policy references its own table ({table}) in the predicate — "
                              f"risk of infinite recursion; use a SECURITY DEFINER helper fn instead"))

    return findings


def cmd_lint():
    """rlsautotest lint — static analysis of RLS policy expressions (no test execution)."""
    ap = argparse.ArgumentParser(prog="rlsautotest lint",
                                 description="Static analysis of RLS policy expressions.")
    ap.add_argument("--schema", required=True)
    ap.add_argument("--table", help="analyze one table; omit for all tables in the schema")
    ap.add_argument("--db-url", help="Postgres connection string (else PG* env)")
    ap.add_argument("--json", metavar="FILE", help="write findings as JSON")
    ap.add_argument("--min-severity", choices=["INFO","MEDIUM","HIGH","CRITICAL"], default="INFO",
                    help="minimum severity to report (default: INFO)")
    a = ap.parse_args(sys.argv[2:])
    try: sys.stdout.reconfigure(encoding="utf-8")
    except Exception: pass

    with psycopg.connect(a.db_url or "") as conn, conn.cursor() as cur:
        if a.table:
            tables = [a.table]
        else:
            cur.execute("""SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                           WHERE n.nspname=%s AND c.relkind='r' ORDER BY c.relname""", (a.schema,))
            tables = [r[0] for r in cur.fetchall()]
        all_findings = []
        for t in tables:
            all_findings.extend(_lint_table(cur, a.schema, t))

    min_sev = _SEV_ORDER[a.min_severity]
    filtered = [(rid, sev, tbl, pol, msg) for (rid, sev, tbl, pol, msg) in all_findings
                if _SEV_ORDER.get(sev, 0) >= min_sev]
    filtered.sort(key=lambda x: (-_SEV_ORDER.get(x[1], 0), x[2], x[3] or ""))

    if a.json:
        data = [{"rule": r, "severity": s, "table": t, "policy": p, "message": m}
                for (r, s, t, p, m) in filtered]
        open(a.json, "w", encoding="utf-8").write(json.dumps(data, indent=2))

    if not filtered:
        print(f"✅  No issues found in {a.schema} schema (min-severity={a.min_severity})")
        return
    print(f"\nrlsautotest lint — {a.schema}  [{len(filtered)} finding(s)]\n")
    cur_table = None
    for (rid, sev, tbl, pol, msg) in filtered:
        if tbl != cur_table:
            print(f"  {a.schema}.{tbl}")
            cur_table = tbl
        pol_tag = f"  [{pol}]" if pol else ""
        print(f"    {_SEV_ICON.get(sev,'·')} {rid} {sev}{pol_tag}: {msg}")
    print()
    n_crit = sum(1 for (_, s, *_) in filtered if s == "CRITICAL")
    n_high = sum(1 for (_, s, *_) in filtered if s == "HIGH")
    if n_crit or n_high:
        sys.exit(1)


# ── snapshot ─────────────────────────────────────────────────────────────────
def cmd_snapshot():
    """rlsautotest snapshot — save current RLS policy state to a JSON file."""
    import datetime, os
    ap = argparse.ArgumentParser(prog="rlsautotest snapshot",
                                 description="Save current RLS policy state for later diff.")
    ap.add_argument("--schema", required=True)
    ap.add_argument("--db-url", help="Postgres connection string (else PG* env)")
    ap.add_argument("--out", default=".rlsautotest/snapshot.json",
                    help="output path (default: .rlsautotest/snapshot.json)")
    a = ap.parse_args(sys.argv[2:])

    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with psycopg.connect(a.db_url or "") as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT schemaname, tablename, policyname, permissive, roles::text, cmd, qual, with_check
            FROM pg_policies WHERE schemaname=%s ORDER BY tablename, policyname""", (a.schema,))
        pol_rows = cur.fetchall()
        cur.execute("""SELECT c.relname, c.relrowsecurity
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname=%s AND c.relkind='r' ORDER BY c.relname""", (a.schema,))
        table_rows = cur.fetchall()

    snapshot = {
        "schema": a.schema,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "tables": {r[0]: {"rls_enabled": bool(r[1])} for r in table_rows},
        "policies": [{"schema": r[0], "table": r[1], "name": r[2], "permissive": r[3],
                       "roles": r[4], "cmd": r[5], "qual": r[6], "with_check": r[7]}
                      for r in pol_rows],
    }
    open(a.out, "w", encoding="utf-8").write(json.dumps(snapshot, indent=2))
    print(f"Snapshot saved: {os.path.abspath(a.out)}")
    print(f"  {len(snapshot['policies'])} policies across {len(table_rows)} tables  "
          f"(timestamp: {snapshot['timestamp']})")


# ── diff ─────────────────────────────────────────────────────────────────────
def cmd_diff():
    """rlsautotest diff — compare current RLS policies vs a saved snapshot."""
    ap = argparse.ArgumentParser(prog="rlsautotest diff",
                                 description="Compare current RLS policies vs saved snapshot.")
    ap.add_argument("--schema", required=True)
    ap.add_argument("--db-url", help="Postgres connection string (else PG* env)")
    ap.add_argument("--snapshot", default=".rlsautotest/snapshot.json",
                    help="snapshot file (default: .rlsautotest/snapshot.json)")
    ap.add_argument("--json", metavar="FILE", help="write diff output as JSON")
    a = ap.parse_args(sys.argv[2:])
    try: sys.stdout.reconfigure(encoding="utf-8")
    except Exception: pass

    try:
        saved = json.loads(open(a.snapshot, encoding="utf-8").read())
    except FileNotFoundError:
        print(f"No snapshot at {a.snapshot}. Run first:\n"
              f"  rlsautotest snapshot --schema {a.schema}", file=sys.stderr)
        sys.exit(2)

    with psycopg.connect(a.db_url or "") as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT tablename, policyname, permissive, roles::text, cmd, qual, with_check
            FROM pg_policies WHERE schemaname=%s ORDER BY tablename, policyname""", (a.schema,))
        curr_pols = {(r[0], r[1]): {"table": r[0], "name": r[1], "permissive": r[2],
                                      "roles": r[3], "cmd": r[4], "qual": r[5], "with_check": r[6]}
                     for r in cur.fetchall()}
        cur.execute("""SELECT c.relname, c.relrowsecurity
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname=%s AND c.relkind='r' ORDER BY c.relname""", (a.schema,))
        curr_tables = {r[0]: bool(r[1]) for r in cur.fetchall()}

    def _sig(p): return (p.get("permissive"), p.get("roles"), p.get("cmd"),
                          p.get("qual"), p.get("with_check"))

    saved_pols = {(p["table"], p["name"]): p for p in saved.get("policies", [])}
    added   = [curr_pols[k] for k in curr_pols if k not in saved_pols]
    removed = [saved_pols[k] for k in saved_pols if k not in curr_pols]
    changed = []
    for k in curr_pols:
        if k in saved_pols and _sig(curr_pols[k]) != _sig(saved_pols[k]):
            changed.append({"table": k[0], "name": k[1],
                             "before": saved_pols[k], "after": curr_pols[k]})

    saved_tables = {t: v.get("rls_enabled") for t, v in saved.get("tables", {}).items()}
    rls_changes = [{"table": t, "before": saved_tables[t], "after": cur_rls}
                   for t, cur_rls in curr_tables.items()
                   if t in saved_tables and bool(saved_tables[t]) != bool(cur_rls)]

    result = {"added": added, "removed": removed, "changed": changed, "rls_changes": rls_changes,
              "snapshot_timestamp": saved.get("timestamp", "?")}
    if a.json:
        open(a.json, "w", encoding="utf-8").write(json.dumps(result, indent=2))

    total = len(added) + len(removed) + len(changed) + len(rls_changes)
    if total == 0:
        print(f"✅  No policy changes since snapshot ({saved.get('timestamp','?')})")
        return

    print(f"\nrlsautotest diff — {a.schema}  vs  {a.snapshot}  ({saved.get('timestamp','?')})\n")
    for p in added:
        print(f"  ✅ ADDED    {p['table']}.{p['name']}  cmd={p['cmd']}  permissive={p['permissive']}")
    for p in removed:
        print(f"  🗑  REMOVED  {p['table']}.{p['name']}  cmd={p['cmd']}")
    for c in changed:
        print(f"  ✏  CHANGED  {c['table']}.{c['name']}")
        b, af = c["before"], c["after"]
        for field in ("permissive", "roles", "cmd", "qual", "with_check"):
            bv, av = b.get(field), af.get(field)
            if bv != av:
                print(f"       {field}: {bv!r}  →  {av!r}")
    for r in rls_changes:
        icon = "🔒" if r["after"] else "🔓"
        state = "ENABLED" if r["after"] else "DISABLED"
        print(f"  {icon} RLS {state}  {r['table']}")
    print()
    # Exit 1 if any security-reducing change (policy removed, RLS disabled, or USING/WITH CHECK widened)
    security_reduced = bool(removed or [r for r in rls_changes if not r["after"]])
    if security_reduced:
        print("⚠  Security-reducing changes detected (exit 1 — CI gate; pass --no-fail to suppress)")
        sys.exit(1)


# ── users ─────────────────────────────────────────────────────────────────────
def cmd_users():
    """rlsautotest users — list users from auth.users for testing context."""
    ap = argparse.ArgumentParser(prog="rlsautotest users",
                                 description="List users from auth.users for --as-user testing.")
    ap.add_argument("--db-url", help="Postgres connection string (else PG* env)")
    ap.add_argument("--limit", type=int, default=25, help="max rows (default: 25)")
    ap.add_argument("--json", metavar="FILE", help="write as JSON")
    a = ap.parse_args(sys.argv[2:])
    try: sys.stdout.reconfigure(encoding="utf-8")
    except Exception: pass

    with psycopg.connect(a.db_url or "") as conn, conn.cursor() as cur:
        try:
            cur.execute("""SELECT id, email, phone, role, created_at,
                                  raw_app_meta_data::text, raw_user_meta_data::text
                           FROM auth.users ORDER BY created_at DESC LIMIT %s""", (a.limit,))
            rows = cur.fetchall()
        except Exception as e:
            if "auth" in str(e).lower() or "does not exist" in str(e).lower():
                print("auth.users not found. Is this a Supabase database? (auth schema required)", file=sys.stderr)
                sys.exit(2)
            raise

    if not rows:
        print("No users in auth.users. Add users via Supabase Dashboard → Authentication.")
        return
    if a.json:
        data = [{"id": str(r[0]), "email": r[1], "phone": r[2], "role": r[3],
                 "created_at": str(r[4]), "app_metadata": r[5], "user_metadata": r[6]}
                for r in rows]
        open(a.json, "w", encoding="utf-8").write(json.dumps(data, indent=2))

    print(f"\nrlsautotest users — {len(rows)} user(s)\n")
    print(f"  {'ID':<38}  {'EMAIL / PHONE':<30}  {'ROLE':<15}  CREATED")
    print("  " + "─" * 95)
    for (uid, email, phone, role, created, _app, _meta) in rows:
        ident = email or phone or "—"
        print(f"  {str(uid):<38}  {ident:<30}  {(role or '—'):<15}  {str(created)[:19]}")
    print(f"\nTest from a real user's perspective:\n"
          f"  rlsautotest --schema <s> --report --as-user <email>\n")


# ── coverage ─────────────────────────────────────────────────────────────────
def cmd_coverage():
    """rlsautotest coverage — RLS policy obligation-surface coverage report."""
    ap = argparse.ArgumentParser(prog="rlsautotest coverage",
                                 description="Report what fraction of RLS obligations are covered by the generated battery.")
    ap.add_argument("--schema", required=True)
    ap.add_argument("--table", help="one table only")
    ap.add_argument("--db-url", help="Postgres connection string (else PG* env)")
    ap.add_argument("--json", metavar="FILE", help="write as JSON")
    a = ap.parse_args(sys.argv[2:])
    try: sys.stdout.reconfigure(encoding="utf-8")
    except Exception: pass

    CMDS = ("SELECT", "INSERT", "UPDATE", "DELETE")
    def _expand(c):
        return set(CMDS) if (c or "ALL").upper() == "ALL" else {(c or "").upper()}
    # The obligations our battery asserts (authorized + unauthorized per policied command)
    BATTERY_OBL = {(c, p)
                   for c in CMDS
                   for p in ("authorized", "unauthorized")}

    with psycopg.connect(a.db_url or "") as conn, conn.cursor() as cur:
        cur.execute("""SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                       WHERE n.nspname=%s AND c.relkind='r' AND c.relrowsecurity ORDER BY c.relname""",
                    (a.schema,))
        rls_tables_all = [r[0] for r in cur.fetchall()]
        if a.table:
            rls_tables_all = [t for t in rls_tables_all if t == a.table]
        rows_out = []
        for t in rls_tables_all:
            cur.execute("SELECT cmd FROM pg_policies WHERE schemaname=%s AND tablename=%s", (a.schema, t))
            cmds = set()
            for (c,) in cur.fetchall():
                cmds |= _expand(c)
            cmds &= set(CMDS)
            obligations = {(c, p) for c in cmds for p in ("authorized", "unauthorized")}
            covered = obligations & BATTERY_OBL
            uncovered = sorted(obligations - covered)
            pct = round(len(covered) / len(obligations) * 100, 1) if obligations else 0.0
            rows_out.append({"table": t, "policy_commands": sorted(cmds),
                              "obligations": len(obligations), "covered": len(covered),
                              "coverage": pct,
                              "uncovered": [f"{c}/{p}" for (c, p) in uncovered]})

    if a.json:
        open(a.json, "w", encoding="utf-8").write(json.dumps(rows_out, indent=2))
    if not rows_out:
        print(f"No RLS-enabled tables in schema {a.schema}.", file=sys.stderr); sys.exit(2)

    tot_o = sum(r["obligations"] for r in rows_out)
    tot_c = sum(r["covered"] for r in rows_out)
    overall = round(tot_c / tot_o * 100, 1) if tot_o else 0.0
    print(f"\nrlsautotest coverage — {a.schema}  [{overall:.1f}% overall]\n")
    print(f"  {'TABLE':<30}  {'COV%':>6}  {'COVERED':>8}  UNCOVERED")
    print("  " + "─" * 75)
    for r in rows_out:
        filled = int(r["coverage"] // 10)
        bar = "█" * filled + "░" * (10 - filled)
        unc = ", ".join(r["uncovered"]) or "—"
        print(f"  {r['table']:<30}  {r['coverage']:>5.1f}%  {r['covered']:>2}/{r['obligations']:<2}  {bar}  {unc}")
    print(f"\n  Overall: {tot_c}/{tot_o} obligations covered ({overall:.1f}%)")
    print(f"\n  Tip: 'rlsautotest --schema {a.schema} --report' executes the battery and shows the identity matrix.\n")


# ── init ─────────────────────────────────────────────────────────────────────
def cmd_init():
    """rlsautotest init — discover tables and RLS/policy status in a schema."""
    ap = argparse.ArgumentParser(prog="rlsautotest init",
                                 description="Discover tables, RLS status, and grants in a schema.")
    ap.add_argument("--schema", required=True)
    ap.add_argument("--db-url", help="Postgres connection string (else PG* env)")
    ap.add_argument("--json", metavar="FILE", help="write as JSON")
    a = ap.parse_args(sys.argv[2:])
    try: sys.stdout.reconfigure(encoding="utf-8")
    except Exception: pass

    with psycopg.connect(a.db_url or "") as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT c.relname,
                   c.relrowsecurity,
                   COUNT(DISTINCT p.policyname)                                                AS policy_count,
                   COUNT(DISTINCT CASE WHEN a.grantee='authenticated' THEN a.privilege_type END) AS auth_grants,
                   COUNT(DISTINCT CASE WHEN a.grantee='anon'          THEN a.privilege_type END) AS anon_grants
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            LEFT JOIN pg_policies p
                   ON p.schemaname = n.nspname AND p.tablename = c.relname
            LEFT JOIN information_schema.role_table_grants a
                   ON a.table_schema = n.nspname AND a.table_name = c.relname
                  AND a.grantee IN ('authenticated','anon')
            WHERE n.nspname=%s AND c.relkind='r'
            GROUP BY c.relname, c.relrowsecurity
            ORDER BY c.relname""", (a.schema,))
        rows = cur.fetchall()

    if not rows:
        print(f"No tables found in schema {a.schema}.", file=sys.stderr); sys.exit(2)
    if a.json:
        data = [{"table": r[0], "rls_enabled": bool(r[1]), "policy_count": int(r[2]),
                 "auth_grants": int(r[3]), "anon_grants": int(r[4])} for r in rows]
        open(a.json, "w", encoding="utf-8").write(json.dumps(data, indent=2))

    print(f"\nrlsautotest init — {a.schema}  [{len(rows)} table(s)]\n")
    print(f"  {'TABLE':<32}  {'RLS':<5}  {'POLICIES':>9}  {'AUTH':>5}  {'ANON':>5}  STATUS")
    print("  " + "─" * 72)
    n_exposed = 0
    for (name, rls_on, pol_cnt, auth_g, anon_g) in rows:
        icon = "🔒" if rls_on else "🔓"
        status_parts = []
        if not rls_on and (auth_g or anon_g):
            status_parts.append("⚠ EXPOSED")
            n_exposed += 1
        elif rls_on and pol_cnt == 0:
            status_parts.append("no policies (implicit deny)")
        elif rls_on:
            status_parts.append("protected")
        else:
            status_parts.append("RLS off (internal?)")
        print(f"  {name:<32}  {icon} {'ON' if rls_on else 'OFF':<3}  {int(pol_cnt):>5} pol  "
              f"{int(auth_g):>5}g  {int(anon_g):>5}g  {', '.join(status_parts)}")
    n_rls = sum(1 for r in rows if r[1])
    print(f"\n  Summary: {n_rls}/{len(rows)} tables RLS-enabled"
          + (f"  ⚠ {n_exposed} exposed (RLS off + client grant)" if n_exposed else " ✅"))
    print(f"\n  Next steps:")
    print(f"    rlsautotest lint     --schema {a.schema}              # static analysis")
    print(f"    rlsautotest snapshot --schema {a.schema}              # save policy baseline")
    print(f"    rlsautotest --schema {a.schema} --html rls-report.html  # full probe report")
    print()


# ── as-user probe ─────────────────────────────────────────────────────────────
def _as_user_report(conn, cur, schema, table, user_id, app_meta, user_meta):
    """Quick per-command probe as a specific auth.users identity."""
    claims = json.dumps({"sub": str(user_id), "role": "authenticated",
                          "app_metadata": app_meta or {}, "user_metadata": user_meta or {}})
    CMDS4 = ["SELECT", "INSERT", "UPDATE", "DELETE"]
    results = {}
    for cmd in CMDS4:
        sp = f"_asuser_{cmd.lower()}"
        try:
            if cmd == "SELECT":
                action = f"SELECT count(*) FROM {schema}.{table}"
            elif cmd == "INSERT":
                cur.execute(f"SELECT attname, format_type(atttypid,atttypmod) FROM pg_attribute a "
                            f"JOIN pg_class c ON c.oid=a.attrelid "
                            f"JOIN pg_namespace n ON n.oid=c.relnamespace "
                            f"WHERE n.nspname=%s AND c.relname=%s AND a.attnum>0 AND NOT a.attisdropped "
                            f"LIMIT 1", (schema, table))
                col_row = cur.fetchone()
                if not col_row:
                    results[cmd] = "–"
                    continue
                col, typ = col_row
                action = f"INSERT INTO {schema}.{table}({col}) VALUES (NULL::text::{typ}) RETURNING 1"
            elif cmd == "UPDATE":
                cur.execute(f"SELECT attname FROM pg_attribute a "
                            f"JOIN pg_class c ON c.oid=a.attrelid "
                            f"JOIN pg_namespace n ON n.oid=c.relnamespace "
                            f"WHERE n.nspname=%s AND c.relname=%s AND a.attnum>0 AND NOT a.attisdropped "
                            f"AND format_type(a.atttypid,a.atttypmod) IN ('text','varchar','character varying') "
                            f"LIMIT 1", (schema, table))
                col_row = cur.fetchone()
                if not col_row:
                    results[cmd] = "–"
                    continue
                action = f"UPDATE {schema}.{table} SET {col_row[0]}={col_row[0]} RETURNING 1"
            else:  # DELETE
                action = f"DELETE FROM {schema}.{table} RETURNING 1"

            cur.execute("SAVEPOINT " + sp)
            cur.execute("SELECT set_config('request.jwt.claims', %s, true)", (claims,))
            cur.execute("SET LOCAL ROLE authenticated")
            try:
                cur.execute(action)
                if cmd == "SELECT":
                    n = (cur.fetchone() or [0])[0]
                    results[cmd] = f"✓ ({n} row{'s' if n != 1 else ''})"
                else:
                    rows_affected = cur.rowcount
                    results[cmd] = f"✓ ({rows_affected} row{'s' if rows_affected != 1 else ''})"
            except Exception as e:
                sqlstate = getattr(e, "sqlstate", None) or str(e)[:8]
                results[cmd] = f"✗ blocked ({sqlstate})"
            finally:
                cur.execute("ROLLBACK TO SAVEPOINT " + sp)
                cur.execute("RELEASE SAVEPOINT " + sp)
                cur.execute("RESET ROLE")
        except Exception:
            results[cmd] = "–"
    return results


# ══════════════════════════════════════════════════════════════════════════════
# DISPATCH TABLE for subcommands
# ══════════════════════════════════════════════════════════════════════════════
_SUBCMDS = {
    "lint": cmd_lint,
    "snapshot": cmd_snapshot,
    "diff": cmd_diff,
    "users": cmd_users,
    "coverage": cmd_coverage,
    "init": cmd_init,
}


def main():
    import os, pathlib
    # ── subcommand dispatch (lint / snapshot / diff / users / coverage / init) ──
    if len(sys.argv) > 1 and sys.argv[1] in _SUBCMDS:
        return _SUBCMDS[sys.argv[1]]()

    ap = argparse.ArgumentParser(prog="rlsautotest", description="Generate native pgTAP RLS tests for Supabase/Postgres.")
    ap.add_argument("--schema", required=True)
    ap.add_argument("--table", help="single table; omit (with --emit) to do every RLS table in the schema")
    ap.add_argument("--emit", metavar="DIR", help="write the Supabase suite layout under DIR: native pgTAP into DIR/tests/database/rls/, nested debug into DIR/.rlsautotest/debug/")
    ap.add_argument("--label", help="emit into a named subfolder rls/<label>/ — give each database its own label when generating for several")
    ap.add_argument("--out", help="single-table: write nested (debug) pgTAP here")
    ap.add_argument("--flat", help="single-table: write native flat pgTAP here")
    ap.add_argument("--setup", help="single-table: write 000-setup-tests-hooks.sql here")
    ap.add_argument("--describe", action="store_true")
    ap.add_argument("--debug-unhandled", action="store_true", help="read-only: list every policy branch the CLASSIFIER couldn't recognize (table, command, policy, shape) across the schema — to triage parsing gaps")
    ap.add_argument("--no-helpers", action="store_true", help="emit fully self-contained tests (no tests.* helpers / no 000-hook)")
    ap.add_argument("--db-url", help="Postgres connection string (else uses PG* env)")
    ap.add_argument("--report", action="store_true", help="run the suite and print the grant/deny coverage matrix")
    ap.add_argument("--report-json", help="write the matrix as JSON to this path")
    ap.add_argument("--html", help="run the suite and write an HTML report to this path (the single-command routine)")
    ap.add_argument("--no-fail", action="store_true", help="with --report/--html: do NOT exit non-zero on problems (default: exit 1 if any table is exposed or any check fails — for CI gating)")
    ap.add_argument("--quiet", action="store_true", help="with --report/--html: only show tables with issues (suppress clean tables)")
    ap.add_argument("--parallel", type=int, default=1, metavar="N",
                    help="run N tables in parallel for --report/--html (default: 1 = sequential)")
    ap.add_argument("--as-user", metavar="EMAIL",
                    help="after --report: show what a specific auth.users identity can/cannot do")
    a = ap.parse_args()
    try: sys.stdout.reconfigure(encoding="utf-8")   # render matrix glyphs on Windows too
    except Exception: pass
    helpers = not a.no_helpers
    if a.report or a.html or a.emit:
        sys.stderr.write(
            "\nWARNING: rlsautotest runs statements against the database in --db-url to probe\n"
            "each policy -- it seeds rows and executes SELECT/INSERT/UPDATE/DELETE. Each probe is\n"
            "wrapped in a transaction and rolled back (nothing is committed), but the statements DO\n"
            "run (table locks, triggers, sequences fire). Point --db-url at a DISPOSABLE COPY of\n"
            "your database, NEVER production.\n\n"
        )
    report_gate = 0   # exit code for the report/emit paths (1 if CI-gating problems found)
    with psycopg.connect(a.db_url or "") as conn, conn.cursor() as cur:
        if a.debug_unhandled:   # read-only triage: which policy branches does the classifier drop to NOT_TESTABLE?
            tabs2 = [a.table] if a.table else rls_tables(cur, a.schema)
            rows_out = []
            for t in sorted(tabs2):
                try:
                    _pols, _per, _cmds2, _notes = analyze(cur, a.schema, t)
                except Exception as e:
                    print(f"  {a.schema}.{t}: analyze error: {e}"); continue
                for cmd in _cmds2:
                    for c in _per[cmd]["classes"]:
                        if not c.get("handled"):
                            rows_out.append((t, cmd, c.get("src_policy") or "?", c.get("reason") or "?"))
            if not rows_out:
                print(f"No unclassified policy branches in schema {a.schema} — every branch is handled by the classifier.")
            else:
                print(f"Unclassified policy branches in schema {a.schema} ({len(rows_out)}):\n")
                for (t, cmd, pol, reason) in rows_out:
                    print(f"  {a.schema}.{t}  {cmd:<6}  policy [{pol}]  ->  {reason}")
                print("\nNote: these are the CLASSIFIER's gaps. The per-min-term solver (BL-1) may still emit a")
                print("DB-verified grant/deny for them at --report/--emit time; run --report to see which stay '-'.")
            return
        if a.report or a.html:
            if a.table:
                cur.execute("""SELECT c.relrowsecurity, EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid)
                    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s AND c.relname=%s""",
                            (a.schema, a.table))
                row = cur.fetchone()
                tabs = [(a.table, bool(row[0]), bool(row[1]))] if row else []
            else:
                tabs = all_tables(cur, a.schema)
            # ── parallel or sequential table probing ──────────────────────────
            def _probe_one(t_tuple):
                t, rls_on, has_pol = t_tuple
                if rls_on and has_pol:
                    rep = _table_report(cur, conn, a.schema, t, helpers)
                else:
                    fg = []
                    if rls_on and not has_pol:   # RLS on, zero policies = deny-all to client roles (safe if intentional, else unintentionally inaccessible)
                        fg.append("RLS is ENABLED but NO POLICY is defined -> every client role (anon/authenticated) is denied ALL access. Safe if intentional (deny-all); otherwise the table is unintentionally inaccessible -> add a policy.")
                    rep = {"table": t, "rls_enabled": rls_on, "policied": [], "cells": {}, "footguns": fg, "coverage": [0, 0]}
                rep["has_policy"] = has_pol
                rep["exposed"] = (not rls_on) and _exposed(cur, a.schema, t)
                rep["grants"] = _effective_grants(cur, a.schema, t)   # per-command grants for ALL roles (incl service_role) — every cell is grant-gated
                return rep

            n_parallel = max(1, getattr(a, "parallel", 1))
            if n_parallel > 1:
                from concurrent.futures import ThreadPoolExecutor
                with ThreadPoolExecutor(max_workers=n_parallel) as _ex:
                    reps = list(_ex.map(_probe_one, tabs))
            else:
                reps = [_probe_one(t) for t in tabs]

            # ── --quiet: suppress tables with no issues ───────────────────────
            if getattr(a, "quiet", False):
                def _has_issues(r):
                    if r.get("exposed"): return True
                    if r.get("footguns"): return True
                    if any(_id_cell(r, k, c)[1] in ("danger", "fail") for k, _ in _ID_ROWS for c in _CMDS4):
                        return True
                    return False
                reps_display = [r for r in reps if _has_issues(r)]
                if not reps_display:
                    print(f"✅  All {len(reps)} table(s) clean — no issues found.")
                    if not a.no_fail:
                        sys.exit(0)
            else:
                reps_display = reps

            if a.report_json:
                open(a.report_json, "w", encoding="utf-8").write(json.dumps(reps, indent=2))
            if a.html:
                open(a.html, "w", encoding="utf-8").write(render_report_html(reps_display, a.schema))
                _abs = os.path.abspath(a.html)
                print(f"HTML report for {len(reps_display)} table(s) written to:\n  {_abs}")
                try:    # clickable file:// URL in most terminals
                    print(f"  {pathlib.Path(_abs).as_uri()}")
                except Exception: pass
                print(f"\n{_TAGLINE} {_TAGLINE2}")
            if a.report or not a.html:
                print(render_report_text(reps_display))
            # CI gate: fail on any exposed table (RLS off + reachable), any failing/leaking check, or a broken policy
            exposed_any = [r["table"] for r in reps if r.get("exposed")]
            holes_any = [r["table"] for r in reps
                         if any(_id_cell(r, k, c)[1] in ("danger", "fail") for k, _ in _ID_ROWS for c in _CMDS4)]
            broken_any = [r["table"] for r in reps if any("BROKEN POLICY" in f for f in r.get("footguns", []))]
            leak_any = [r["table"] for r in reps if r.get("transition_leaks")]
            unreliable_any = [r["table"] for r in reps if r.get("unreliable")]
            if exposed_any or holes_any or broken_any or leak_any or unreliable_any:
                bits = []
                if exposed_any: bits.append(f"{len(exposed_any)} exposed table(s): {', '.join(exposed_any)}")
                if holes_any:   bits.append(f"{len(holes_any)} table(s) with policy holes/failures: {', '.join(holes_any)}")
                if broken_any:  bits.append(f"{len(broken_any)} broken/unreadable table(s): {', '.join(broken_any)}")
                if leak_any:    bits.append(f"{len(leak_any)} table(s) with cross-policy WITH CHECK leaks: {', '.join(leak_any)}")
                if unreliable_any: bits.append(f"{len(unreliable_any)} table(s) with UNRELIABLE tests (seed/precondition failed): {', '.join(unreliable_any)}")
                print("\nFAIL: " + "; ".join(bits) + ("" if a.no_fail else "  (exit 1 — CI gate; pass --no-fail to suppress)"))
                report_gate = 0 if a.no_fail else 1
            # ── --as-user: probe from a real auth.users identity ──────────────
            if getattr(a, "as_user", None):
                try:
                    cur.execute("SELECT id, raw_app_meta_data, raw_user_meta_data FROM auth.users WHERE email=%s",
                                (a.as_user,))
                    u_row = cur.fetchone()
                    if not u_row:
                        print(f"\n⚠  --as-user: no auth.users row with email={a.as_user!r}. "
                              f"Run 'rlsautotest users' to see available identities.")
                    else:
                        u_id, app_meta_raw, user_meta_raw = u_row
                        app_meta = json.loads(app_meta_raw) if app_meta_raw else {}
                        user_meta = json.loads(user_meta_raw) if user_meta_raw else {}
                        print(f"\n── as-user: {a.as_user} ({u_id}) ─────────────────────────────")
                        print(f"  {'TABLE':<32}  {'SELECT':>12}  {'INSERT':>12}  {'UPDATE':>12}  {'DELETE':>12}")
                        print("  " + "─" * 74)
                        probe_tabs = [a.table] if a.table else [r["table"] for r in reps if r.get("rls_enabled")]
                        for t in probe_tabs:
                            res = _as_user_report(conn, cur, a.schema, t, u_id, app_meta, user_meta)
                            row_cells = [res.get(c, "–") for c in ["SELECT", "INSERT", "UPDATE", "DELETE"]]
                            print(f"  {t:<32}  {row_cells[0]:>12}  {row_cells[1]:>12}  {row_cells[2]:>12}  {row_cells[3]:>12}")
                        print()
                except Exception as e:
                    if "auth" in str(e).lower() or "does not exist" in str(e).lower():
                        print(f"\n⚠  --as-user requires auth.users (Supabase): {e}")
                    else:
                        raise

            if not a.emit:        # if --emit was also given, fall through and write the test files too
                sys.exit(report_gate)
        if a.emit:
            tdir = os.path.join(a.emit, "tests", "database", "rls", *( [a.label] if a.label else [] ))
            ddir = os.path.join(a.emit, ".rlsautotest", "debug", *( [a.label] if a.label else [] ))
            os.makedirs(tdir, exist_ok=True); os.makedirs(ddir, exist_ok=True)
            if helpers:
                hookpath = os.path.join(tdir, "000-setup-tests-hooks.sql")
                if not os.path.exists(hookpath):   # non-destructive: never clobber an existing hook
                    open(hookpath, "w", encoding="utf-8").write(setup_hook_sql(_basejump_present(cur)))
            guard = emit_rls_guard(cur, a.schema)   # schema-wide "RLS must be enabled" guard
            if guard:
                open(os.path.join(tdir, "010-rls-enabled.test.sql"), "w", encoding="utf-8").write(guard)
            tables = [a.table] if a.table else rls_tables(cur, a.schema)
            for i, t in enumerate(sorted(tables), start=1):
                ctx = _load_ctx(cur, a.schema, t)
                flat, nested = _emit_both(a.schema, t, ctx, helpers, conn=conn)
                num = f"{100 + i:03d}"
                open(os.path.join(tdir, f"{num}-rls-{t}.test.sql"), "w", encoding="utf-8").write(flat)
                open(os.path.join(ddir, f"{t}.debug.sql"), "w", encoding="utf-8").write(nested)
                print(f"  {a.schema}.{t}: coverage={ctx['cov']}/{ctx['tot']} -> {num}-rls-{t}.test.sql")
            print(f"emitted {len(tables)} test file(s) into:\n  {os.path.abspath(tdir)}")
            if guard:
                print("  + 010-rls-enabled.test.sql (guard: fails if a reachable table has RLS off)")
            print(f"run them with:\n  pg_prove -d \"<your copy>\" {os.path.join(tdir, '*.sql')}")
            print(f"\n{_TAGLINE} {_TAGLINE2}")
            sys.exit(report_gate)
        if not a.table:
            ap.error("--table is required unless --emit is used")
        ctx = _load_ctx(cur, a.schema, a.table)
        if a.describe:
            print(f"\n{a.schema}.{a.table}  commands={ctx['cmds']}  unique={sorted(ctx['unique_cols'])}")
            for cmd in ctx["cmds"]:
                pc = ctx["per"][cmd]
                d = [("GRANT" if not c["rowlinked"] else "+".join(c["kinds"])) + ("" if c["handled"] else f"(NT:{c['reason']})") for c in pc["classes"]]
                print(f"  {cmd}: open={pc['open']} classes=[{', '.join(d) or 'none'}]")
            for x in ctx["notes"]: print(f"  NOTE: {x}")
            print(f"  coverage: {ctx['cov']}/{ctx['tot']}")
            return
        flat, nested = _emit_both(a.schema, a.table, ctx, helpers, conn=conn)
        hook = setup_hook_sql(_basejump_present(cur)) if (a.setup and helpers) else None
    if a.out: open(a.out, "w", encoding="utf-8").write(nested)
    if a.flat: open(a.flat, "w", encoding="utf-8").write(flat)
    if a.setup and hook: open(a.setup, "w", encoding="utf-8").write(hook)
    print(f"cmds={ctx['cmds']} coverage={ctx['cov']}/{ctx['tot']} helpers={helpers} -> out={a.out} flat={a.flat} setup={a.setup if (a.setup and hook) else None}")


if __name__ == "__main__":
    main()
