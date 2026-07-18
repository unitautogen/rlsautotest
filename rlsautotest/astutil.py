# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""AST + small text helpers over pglast parse trees (the only SQL parser in the package).

Split out of the original single-module cli.py; behavior-preserving.
"""
from __future__ import annotations
import json
import re
from pglast.parser import parse_sql_json

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



def _and_conjuncts(n):
    """Flatten an AND-tree of WHERE conjuncts to a list of leaves. OR anywhere -> None (can't soundly falsify a
    disjunction in a subquery). A NOT node is kept as a single leaf (classified downstream by `_bool_extra`)."""
    if not isinstance(n, dict):
        return []
    if _t(n) == "BoolExpr":
        op = _v(n).get("boolop")
        if op == "AND_EXPR":
            out = []
            for a in _v(n).get("args", []):
                sub = _and_conjuncts(a)
                if sub is None:
                    return None
                out += sub
            return out
        if op == "OR_EXPR":
            return None
        return [n]   # NOT_EXPR -> a single leaf
    return [n]



def _bool_extra(c, alias):
    """A boolean subquery-WHERE conjunct on a single subquery column -> (col, 'true'|'false'); else None.
    Covers a bare boolean column (`can_read`), `NOT col`, and `col IS TRUE|FALSE`."""
    if _t(c) == "ColumnRef":
        q, col = _colqual(c)
        if col and q in (alias, None):
            return (col, "true")
    if _t(c) == "BoolExpr" and _v(c).get("boolop") == "NOT_EXPR":
        a = _v(c).get("args", [])
        if a and _t(a[0]) == "ColumnRef":
            q, col = _colqual(a[0])
            if col and q in (alias, None):
                return (col, "false")
    if _t(c) == "BooleanTest":
        v = _v(c); col = _colname(v.get("arg")); bt = v.get("booltesttype")
        if col and bt in ("IS_TRUE", "IS_FALSE"):
            return (col, "true" if bt == "IS_TRUE" else "false")
    return None



def _subquery_sig(subselect, testexpr=None):
    """F2 (= BL-5): the ONE reader of a policy subquery's shape, consumed by the classifier
    (_membership), the general subquery witness (_solve_subquery) and the relational-state demand
    extractor (_subquery_tables) — a new subquery nuance is taught HERE, once. Returns None when
    there is no single base table or the WHERE contains OR; otherwise a signature dict where
    `unmodeled` marks any conjunct outside the modeled grammar (each consumer decides how strict
    to be):
      mtable, alias            the (qualified) base table and its alias
      uid                      subq column compared to auth.uid() (the identity correlation)
      corr [(subq, outer)]     column = column correlations (testexpr/IN first, then WHERE order)
      extras {subq col: lit}   equality-to-constant and bare-boolean conditions
      fns [{mcol, node}]       subq column = <opaque fn()/sublink> conjuncts (mock candidates)
      agg [cols]               the aggregated column when the target is sum/avg/min/max
      target_col               the first target column (the IN-subquery's yielded column)
    """
    ss = (subselect or {}).get("SelectStmt", {})
    frm = ss.get("fromClause", [])
    if not frm or len(frm) != 1 or "RangeVar" not in frm[0]:
        return None
    rv = frm[0]["RangeVar"]
    mtable = (rv.get("schemaname") + "." if rv.get("schemaname") else "") + rv.get("relname", "")
    if not mtable:
        return None
    alias = (rv.get("alias") or {}).get("aliasname") or rv.get("relname")
    conj = _and_conjuncts(ss.get("whereClause")) if ss.get("whereClause") is not None else []
    if conj is None:                                   # OR in the WHERE -> not an AND-only shape
        return None
    sig = {"mtable": mtable, "alias": alias, "uid": None, "corr": [], "extras": {}, "fns": [],
           "agg": [], "target_col": None, "unmodeled": False}
    tl = ss.get("targetList", [])
    if tl:
        tval = tl[0].get("ResTarget", {}).get("val")
        sig["target_col"] = _colname(tval)
        if _t(tval) == "FuncCall":                     # sum/avg/min/max -> note the aggregated column
            fn = _names(_v(tval).get("funcname")).split(".")[-1].lower()
            fa = _v(tval).get("args", [])
            ac = _colname(fa[0]) if fa else None
            if fn in ("sum", "avg", "min", "max") and ac:
                sig["agg"].append(ac)
    if testexpr is not None:                           # outer IN (SELECT target FROM ...) correlation, FIRST
        _, rowc = _colqual(testexpr)
        if rowc and sig["target_col"]:
            sig["corr"].append((sig["target_col"], rowc))
        else:
            sig["unmodeled"] = True
    for c in conj:
        if _t(c) == "A_Expr" and _names(_v(c).get("name")) == "=":
            l, r = _v(c).get("lexpr"), _v(c).get("rexpr")
            if _is_func(l, "auth.uid") or _is_func(r, "auth.uid"):
                _, sig["uid"] = _colqual(r if _is_func(l, "auth.uid") else l); continue
            lq, lc = _colqual(l); rq, rc = _colqual(r)
            if lc and rc:                              # column = column -> correlation (one side is the subq alias)
                if lq == alias and rq != alias: sig["corr"].append((lc, rc)); continue
                if rq == alias and lq != alias: sig["corr"].append((rc, lc)); continue
                sig["unmodeled"] = True; continue
            if lq == alias and lc and _t(r) in ("FuncCall", "SubLink"): sig["fns"].append({"mcol": lc, "node": r}); continue
            if rq == alias and rc and _t(l) in ("FuncCall", "SubLink"): sig["fns"].append({"mcol": rc, "node": l}); continue
            sc = lc if (lq in (alias, None) and lc) else (rc if (rq in (alias, None) and rc) else None)
            cv = _const(r) if sc == lc else _const(l)
            if sc and cv is not None: sig["extras"][sc] = cv; continue
            sig["unmodeled"] = True; continue
        bx = _bool_extra(c, alias)                     # bare bool / NOT col / IS TRUE|FALSE
        if bx:
            sig["extras"][bx[0]] = bx[1]; continue
        sig["unmodeled"] = True
    return sig


def extract_signature(node, coltypes):
    """F2 (= BL-5): the full CONTROLLABLE input signature of a predicate — everything the engine can
    set to drive it: the table's own columns, the JWT claim paths, the predicate's constants (witness
    candidates), and the shape of every subquery it reads. One walk; classifier-independent."""
    subs = []
    def walk(n):
        if isinstance(n, dict):
            if _t(n) == "SubLink":
                sv = _v(n)
                sg = _subquery_sig(sv.get("subselect"),
                                   sv.get("testexpr") if sv.get("subLinkType") == "ANY_SUBLINK" else None)
                if sg is not None:
                    subs.append(sg)
                return
            for v in n.values(): walk(v)
        elif isinstance(n, list):
            for x in n: walk(x)
    walk(node)
    return {"row_cols": _expr_cols(node, coltypes), "claim_paths": _claim_paths(node),
            "consts": _expr_consts(node), "subqueries": subs}


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


# ---- BL-5/BL-6: input-space discovery + construct-first DB-oracle floor ----
# Instead of interpreting a (possibly novel) operator, collect the predicate's INPUT operands (BL-5) and let
# Postgres evaluate it over candidate column values (BL-6): a brand-new operator/function becomes solvable with
# ZERO operator-specific code. Pure AST collectors here; the DB-oracle search lives in emit_flat (needs a conn).
def _expr_cols(node, coltypes):
    """Every ColumnRef in `node` that is a real column of the table (present in coltypes), in encounter order."""
    out = []
    def walk(n):
        if isinstance(n, dict):
            if _t(n) == "ColumnRef":
                c = _colname(n)
                if c and c in coltypes and c not in out: out.append(c)
            for v in n.values(): walk(v)
        elif isinstance(n, list):
            for x in n: walk(x)
    walk(node); return out


def _expr_consts(node):
    """Every literal constant in `node` (its value strings), in encounter order — candidate column values for
    pattern/prefix/containment operators (e.g. the `'Admin'` in `starts_with(name,'Admin')`)."""
    out = []
    def walk(n):
        if isinstance(n, dict):
            if _t(n) == "A_Const":
                c = _const(n)
                if c is not None and c not in out: out.append(c)
            for v in n.values(): walk(v)
        elif isinstance(n, list):
            for x in n: walk(x)
    walk(node); return out


def _claim_paths(node):
    """Every distinct `auth.jwt() -> … ->> 'k'` claim key-path referenced in `node` (for the joint search to vary
    the session, not just the row). A matched claim ref is a leaf — don't recurse into it."""
    out = []
    def walk(n):
        if isinstance(n, dict):
            k = _jwt_keys(n)
            if k:
                if k not in out: out.append(k)
                return
            for v in n.values(): walk(v)
        elif isinstance(n, list):
            for x in n: walk(x)
    walk(node); return out



def _not(a):
    """Wrap a node in a synthetic `NOT (...)` BoolExpr (for De Morgan pushdown)."""
    return {"BoolExpr": {"boolop": "NOT_EXPR", "args": [a]}}



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



def _qlit(s):
    return "'" + str(s).replace("'", "''") + "'"


_IDENT_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789_")

def _qi(name):
    """Conditionally quote a SQL identifier (quote_ident semantics, pattern-only). A bare lowercase-simple
    identifier passes through UNCHANGED (so emitted SQL for lowercase schemas stays byte-identical); a
    mixed-case / special-char name (e.g. EF-Core "TenantId", "Accounts") gets double-quoted. No keyword list
    on purpose: quoting only on character shape guarantees zero drift for existing lowercase corpora."""
    s = str(name)
    if s and s[0] in "abcdefghijklmnopqrstuvwxyz_" and all(c in _IDENT_CHARS for c in s):
        return s
    return '"' + s.replace('"', '""') + '"'

def _qt(schema, table=None):
    """Quote a (possibly schema-qualified) table reference, each part conditionally.
    `_qt('s', 't')` or `_qt('s.t')`; a bare unqualified name is quoted as one identifier."""
    if table is None:
        s = str(schema)
        schema, dot, table = s.partition(".")
        if not dot:
            return _qi(schema)
    return _qi(schema) + "." + _qi(table)



def _sq(name):
    return name.split(".", 1) if "." in name else ("public", name)



_CMDS4 = ORDER   # F10: single authoritative command universe (was a duplicate of ORDER at module top)



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


# Attribution / funnel — rlsautotest is the free PostgreSQL member of the UnitAutogen family.
_HOME = "https://github.com/unitautogen"

_TAGLINE = "rlsautotest is part of UnitAutogen — automated unit-test generation for your database."

_TAGLINE2 = "Need it for SQL Server (tSQLt), Oracle, or Azure? " + _HOME

