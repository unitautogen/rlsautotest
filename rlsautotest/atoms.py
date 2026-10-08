# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""Predicate classification: policy clause -> boolean AST -> DNF min-terms -> labeled atoms / identity classes.

Split out of the original single-module cli.py; behavior-preserving.
"""
from __future__ import annotations
import json
import threading
from pglast.parser import parse_sql_json
from .structs import Atom, IdentityClass
from .astutil import ORDER, _array_consts, _colname, _colqual, _const, _eq_pairs, _find_queries, _is_func, _is_true_clause, _is_uuid, _jwt_anywhere, _jwt_keys, _list_consts, _names, _not, _t, _unwrap, _v, _where, _subquery_sig
from .values import CV, FUTURE_EXP, MV



def _membership(subselect, testexpr):
    """Recognize the CANONICAL membership subquery only: a single base table, an `auth.uid()` identity, exactly
    ONE correlation (subq col = outer col), optional opaque-fn conjuncts to mock, and NOTHING else. Anything
    richer (an extra `role='admin'`/`can_read` condition, a second correlation, OR in the WHERE) returns
    'unknown' so the branch falls to the general `_solve_subquery` witness builder, which seeds those too.
    F2: a thin labeler over the shared `_subquery_sig` reader — the shape grammar lives there, once."""
    sig = _subquery_sig(subselect, testexpr)
    if (sig is not None and sig["uid"] and len(sig["corr"]) == 1
            and not sig["extras"] and not sig["unmodeled"] and not sig.get("joins")
            and not sig.get("or_split")):
        mscope, rowscope = sig["corr"][0]
        if mscope and rowscope:
            return Atom(kind="membership", mtable=sig["mtable"], muser_col=sig["uid"],
                    mscope_col=mscope, row_scope_col=rowscope, mock_fns=sig["fns"])
    return Atom(kind="unknown", text="membership-subquery")



def _folder_owner(ind, uid):
    """(storage.foldername(<col>))[1] = auth.uid()[::text]  -> owner via path segment."""
    if not _is_func(uid, "auth.uid") or _t(ind) != "A_Indirection":
        return None
    arg = _v(ind).get("arg")
    if _t(arg) == "FuncCall" and _names(_v(arg).get("funcname")).split(".")[-1] == "foldername":
        fa = _v(arg).get("args", [])
        col = _colname(fa[0]) if fa else None
        if col:
            return Atom(kind="folder_owner", col=col)
    return None



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
        return Atom(kind="scalar_lookup", ltable=ltable, lcol=lcol, lkey=lkey, value=val)
    return None



def _guc_name(n):
    """`current_setting('name'[, missing_ok])` (casts unwrapped) -> 'name', else None. A non-constant
    setting name cannot be driven, so it stays None (the branch falls to the general paths)."""
    u = _unwrap(n)
    if _t(u) == "FuncCall" and _names(_v(u).get("funcname")).split(".")[-1] == "current_setting":
        args = _v(u).get("args", [])
        return _const(args[0]) if args else None
    return None


def _is_session_user(n):
    """The SESSION_USER keyword (parsed as SQLValueFunction SVFOP_SESSION_USER)."""
    u = _unwrap(n)
    return _t(u) == "SQLValueFunction" and _v(u).get("op") == "SVFOP_SESSION_USER"


_ANALYZE_CTX = threading.local()   # the schema analyze() is classifying, per worker thread (tables run in parallel)


def _session_roles(cur):
    """Two roles that can act as DISTINCT session users for a `col = SESSION_USER` policy.

    The probe runs `SET LOCAL SESSION AUTHORIZATION <r>` (session_user := r) and then the usual
    `SET LOCAL ROLE authenticated`, so the acting privileges are the same `authenticated` role every other
    identity uses and only the session identity differs. That needs: a superuser connection (only a
    superuser session may change session authorization), and roles that are not superuser / BYPASSRLS
    (either would skip the policy) and can SET ROLE authenticated. Roles that can also become a BYPASSRLS
    role (an `authenticator`-style switchboard login) are excluded. Roles are cluster-wide, so a role
    created for ANOTHER database or schema is eligible too; candidates holding a DIRECT grant on the schema
    under test (its ACL, not inherited) are preferred, then name order, so the choice is deterministic and
    favours the schema's own roles. Returns (roles, reason): roles is the first two, reason explains a
    shortfall."""
    if cur is None:
        return [], "no database connection to discover session roles"
    cur.execute("SELECT rolsuper FROM pg_roles WHERE rolname = session_user")
    r = cur.fetchone()
    if not r or not r[0]:
        return [], ("SESSION_USER owner check needs a superuser connection: only a superuser session can "
                    "SET SESSION AUTHORIZATION to act as two distinct session users")
    cur.execute("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated')")
    if not cur.fetchone()[0]:
        return [], "SESSION_USER owner check needs the 'authenticated' client role to act through"
    cur.execute("""SELECT r.rolname FROM pg_roles r
        WHERE NOT r.rolsuper AND NOT r.rolbypassrls AND left(r.rolname, 3) <> 'pg_'
          AND r.rolname NOT IN ('authenticated', 'anon', 'anonymous', 'service_role')
          AND CASE WHEN current_setting('server_version_num')::int >= 160000
                   THEN pg_has_role(r.oid, 'authenticated', 'SET')
                   ELSE pg_has_role(r.oid, 'authenticated', 'MEMBER') END
          AND NOT EXISTS (SELECT 1 FROM pg_roles b
                          WHERE b.rolbypassrls AND b.oid <> r.oid AND pg_has_role(r.oid, b.oid, 'MEMBER'))
        ORDER BY EXISTS (SELECT 1 FROM pg_namespace n, aclexplode(n.nspacl) a
                         WHERE n.nspname = %s AND a.grantee = r.oid) DESC, r.rolname
        LIMIT 2""", (getattr(_ANALYZE_CTX, "schema", None),))
    roles = [x[0] for x in cur.fetchall()]
    if len(roles) < 2:
        return roles, ("SESSION_USER owner check needs two non-superuser, non-BYPASSRLS roles that can "
                       f"SET ROLE authenticated, to act as two distinct session users; found {len(roles)}")
    return roles, None


def _classify_aexpr(a, cur):
    kind = a.get("kind"); op = _names(a.get("name")); L = a.get("lexpr"); R = a.get("rexpr")
    if kind == "AEXPR_OP_ANY" and op == "=":
        if _is_func(L, "auth.uid") and _colname(R): return Atom(kind="array_col", col=_colname(R))
        if _is_func(R, "auth.uid") and _colname(L): return Atom(kind="array_col", col=_colname(L))
        col = _colname(L) or _colname(R)
        vals = _array_consts(R) if _colname(L) else _array_consts(L)
        if col and vals: return Atom(kind="col_in_set", col=col, values=vals)   # col = ANY(array[consts])  ==  col IN (...)
        return Atom(kind="unknown", text="= ANY(...)")
    if kind == "AEXPR_OP_ALL" and op in ("<>", "!="):
        col = _colname(L) or _colname(R)
        vals = _array_consts(R) if _colname(L) else _array_consts(L)
        if col and vals: return Atom(kind="col_not_in_set", col=col, values=vals)   # col <> ALL(array[consts])  ==  col NOT IN (...)
        return Atom(kind="unknown", text="<> ALL(...)")
    if kind == "AEXPR_IN":
        col = _colname(L); vals = _list_consts(R)
        if col and vals:
            return Atom(kind="col_in_set" if op == "=" else "col_not_in_set", col=col, values=vals)
        return Atom(kind="unknown", text="IN(...)")
    if kind != "AEXPR_OP": return Atom(kind="unknown", text=kind or "expr")
    if op in (">", "<", ">=", "<="):
        if _is_func(R, "now") and _colname(L): return Atom(kind="temporal", col=_colname(L), op=op)
        if _is_func(L, "now") and _colname(R):
            return Atom(kind="temporal", col=_colname(R), op={">": "<", "<": ">", ">=": "<=", "<=": ">="}[op])
        return Atom(kind="unknown", text=f"cmp {op}")
    if op != "=": return Atom(kind="unknown", text=f"op {op}")
    fo = _folder_owner(L, R) or _folder_owner(R, L)
    if fo: return fo
    if _is_func(L, "auth.uid") or _is_func(R, "auth.uid"):
        other = R if _is_func(L, "auth.uid") else L
        if _is_uuid(_const(other)): return Atom(kind="const_identity", value=_const(other))
        if _colname(other): return Atom(kind="owner", col=_colname(other))
        return Atom(kind="unknown", text="auth.uid eq")
    if _is_func(L, "auth.role") or _is_func(R, "auth.role"):
        other = R if _is_func(L, "auth.role") else L
        return Atom(kind="auth_role", value=_const(other) or "")
    jl, jr = _jwt_keys(L), _jwt_keys(R)
    if jl or jr:
        keys = jl or jr; other = R if jl else L
        if _colname(other): return Atom(kind="tenant", col=_colname(other), keys=keys)
        if _const(other) is not None: return Atom(kind="claim_const", keys=keys, value=_const(other))
        return Atom(kind="unknown", text="jwt eq")
    # col = current_setting('x'): the row belongs to whoever has the session GUC set to its value.
    gl, gr = _guc_name(L), _guc_name(R)
    if (gl or gr) and _colname(R if gl else L):
        return Atom(kind="guc_owner", col=_colname(R if gl else L), keys=[gl or gr])
    # col = SESSION_USER: the row belongs to the login (session) role.
    if (_is_session_user(L) or _is_session_user(R)) and _colname(R if _is_session_user(L) else L):
        roles, why = _session_roles(cur)
        if why:
            return Atom(kind="unknown", text=why)
        return Atom(kind="session_owner", col=_colname(R if _is_session_user(L) else L), values=roles)
    sl = _scalar_lookup(L, R) or _scalar_lookup(R, L)   # (SELECT col FROM t WHERE key=auth.uid()) = const
    if sl: return sl
    if _colname(L) and _const(R) is not None: return Atom(kind="row_const", col=_colname(L), value=_const(R))
    if _colname(R) and _const(L) is not None: return Atom(kind="row_const", col=_colname(R), value=_const(L))
    return Atom(kind="unknown", text="eq")



def classify_node(n, cur=None):
    """Classify one AST leaf node into an atom dict (same shapes build_class expects)."""
    t = _t(n)
    if t == "A_Const":
        return Atom(kind="_true_") if _const(n) == "true" else Atom(kind="unknown", text="const")
    if t == "ColumnRef":
        return Atom(kind="row_const", col=_colname(n), value="true") if _colname(n) else Atom(kind="unknown", text="colref")
    if t == "SubLink":
        v = _v(n); st = v.get("subLinkType")
        if st == "EXISTS_SUBLINK": return _membership(v.get("subselect"), None)
        if st == "ANY_SUBLINK": return _membership(v.get("subselect"), v.get("testexpr"))
        if st == "EXPR_SUBLINK": return classify_node(_unwrap(n), cur)
        return Atom(kind="unknown", text=st or "sublink")
    if t == "FuncCall":
        v = _v(n); fn = _names(v.get("funcname")); args = v.get("args", [])
        # Introspect a const-arg fn (has_role('editor'), authorize('perm')) OR a ZERO-arg fn
        # (is_admin()) whose body is a transparent claim check. A fn with a non-const argument
        # stays opaque (the mock wiring path owns it). Probe-and-bake keeps a wrong guess sound.
        if (not args or _const(args[0]) is not None) and cur and not any(b in fn for b in ("auth.", "now")):
            _a0 = _const(args[0]) if args else None
            info = _introspect_rbac(cur, fn, _a0)
            if info: return Atom(kind="rbac", **info)
            cf = _introspect_claim_fn(cur, fn, _a0)
            if cf: return Atom(kind="claim_const", **cf)
        return Atom(kind="unknown", text=f"function {fn}()")
    if t == "A_Expr":
        return _classify_aexpr(_v(n), cur)
    if t == "NullTest":
        v = _v(n)
        if v.get("nulltesttype") == "IS_NOT_NULL" and _is_func(v.get("arg"), "auth.uid"):
            return Atom(kind="authuid_present")   # auth.uid() IS NOT NULL == any logged-in (authenticated) user
        return Atom(kind="unknown", text="nulltest")
    return Atom(kind="unknown", text=t or "node")



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


_DNF_BUDGET = 64   # F10: cap DNF min-term expansion; a pathological AND-of-ORs would otherwise cross-product

                   # into thousands of min-terms (each one probed). Beyond the cap, degrade to the solver
                   # floor: hand the whole predicate to the general solver as ONE node instead of enumerating.
                   # No corpus policy approaches this, so output is unchanged; this only bounds worst-case blowup.
def _dnf_ast(n):
    """Boolean AST -> DNF: list of min-terms, each a list of leaf nodes. NOT is pushed inward (De Morgan, BL-3)
    so `NOT(A AND B)` -> `(NOT A) OR (NOT B)` and `NOT(A OR B)` -> `(NOT A) AND (NOT B)` become separate
    min-terms the per-branch solver can witness; `NOT NOT A` -> `A`; `NOT <leaf>` is kept as a negated-leaf
    min-term (the solver negates it). Plain OR/AND are unchanged. Bounded by _DNF_BUDGET (F10)."""
    t = _t(n)
    if t == "BoolExpr":
        bo = _v(n).get("boolop"); args = _v(n).get("args", [])
        if bo == "NOT_EXPR" and args:
            inner = args[0]
            if _t(inner) == "BoolExpr":
                ibo = _v(inner).get("boolop"); iargs = _v(inner).get("args", [])
                if ibo == "NOT_EXPR" and iargs:                       # NOT NOT A -> A
                    return _dnf_ast(iargs[0])
                if ibo == "AND_EXPR":                                 # NOT(A AND B) -> (NOT A) OR (NOT B)
                    out = []
                    for a in iargs:
                        out += _dnf_ast(_not(a))
                        if len(out) > _DNF_BUDGET: return [[n]]
                    return out
                if ibo == "OR_EXPR":                                  # NOT(A OR B) -> (NOT A) AND (NOT B)
                    partial = [[]]
                    for a in iargs:
                        partial = [m + s for m in partial for s in _dnf_ast(_not(a))]
                        if len(partial) > _DNF_BUDGET: return [[n]]
                    return partial
            return [[n]]                                              # NOT <leaf>: keep (solver negates)
        if bo == "OR_EXPR":
            out = []
            for a in args:
                out += _dnf_ast(a)
                if len(out) > _DNF_BUDGET: return [[n]]
            return out
        if bo == "AND_EXPR":
            partial = [[]]
            for a in args:
                partial = [m + s for m in partial for s in _dnf_ast(a)]
                if len(partial) > _DNF_BUDGET: return [[n]]
            return partial
    return [[n]]



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



# ---- Function-body expansion (witness hints; the probe ALWAYS runs the REAL function) ---------
# UDF_UNDERSTANDING_PLAN: expand an opaque boolean policy function's parsed body into an effective
# predicate node, substitute the call-site constants for its parameters, and hand THAT to the
# general witness machinery to decide what to SEED. The action side is untouched: the probe still
# evaluates the real policy calling the real function, so a wrong or incomplete expansion produces
# an unconfirmed witness and degrades to the mock wiring proof -- never a false pass.

_EXPAND_FAIL = object()   # sentinel: an unexpandable user bool fn poisons the whole substitution


def _is_count_positive(v):
    """`count(*) > 0` / `count(*) >= 1` (either operand order) -> True."""
    if _t(v) != "A_Expr":
        return False
    av = _v(v)
    op = _names(av.get("name"))
    l, r = av.get("lexpr"), av.get("rexpr")
    def _is_count(x):
        return _t(x) == "FuncCall" and _names(_v(x).get("funcname")).split(".")[-1] == "count"
    def _thresh(x, opx):
        c = _const(x)
        return (opx == ">" and c == "0") or (opx == ">=" and c == "1")
    if op in (">", ">=") and _is_count(l) and _thresh(r, op):
        return True
    if op in ("<", "<=") and _is_count(r) and _thresh(l, {"<": ">", "<=": ">="}[op]):
        return True
    return False


def _subst_params(node, consts, argnames):
    """Deep-copy `node` replacing ParamRef $N (SQL bodies) and bare ColumnRef <argname> (named
    params / plpgsql variables) with the call-site constant nodes. Returns the new node, or
    _EXPAND_FAIL when a parameter reference cannot be resolved to a constant."""
    if isinstance(node, dict):
        if "ParamRef" in node and len(node) == 1:
            num = (node["ParamRef"] or {}).get("number")
            if not num or num > len(consts):
                return _EXPAND_FAIL
            return consts[num - 1]
        if "ColumnRef" in node and len(node) == 1:
            cn = _colname(node)
            if cn in argnames:
                i = argnames.index(cn)
                if i >= len(consts):
                    return _EXPAND_FAIL
                return consts[i]
            return node
        out = {}
        for k, val in node.items():
            r = _subst_params(val, consts, argnames)
            if r is _EXPAND_FAIL:
                return _EXPAND_FAIL
            out[k] = r
        return out
    if isinstance(node, list):
        out = []
        for x in node:
            r = _subst_params(x, consts, argnames)
            if r is _EXPAND_FAIL:
                return _EXPAND_FAIL
            out.append(r)
        return out
    return node


def _expand_fn_predicate(cur, fn, argnodes):
    """One function's body -> a closed predicate AST with the call-site constants substituted, or
    None. Accepted body shapes (single query only): a FROM-less `SELECT <expr>` (covers
    `SELECT EXISTS(...)` and a plpgsql RETURN expression), and `SELECT count(*) > 0 FROM ... WHERE ...`
    (rewritten to an EXISTS sublink). VOLATILE functions are refused (no stable witness semantics)."""
    parts = fn.split("."); name = parts[-1]; sch = parts[-2] if len(parts) > 1 else None
    cur.execute("""SELECT p.provolatile FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE p.proname=%s AND (%s::text IS NULL OR n.nspname=%s)
        ORDER BY (n.nspname='public')::int LIMIT 1""", (name, sch, sch))
    row = cur.fetchone()
    if not row or row[0] == "v":
        return None
    selects, argnames = _func_selects(cur, fn)
    if len(selects) != 1:
        return None
    ss = selects[0]
    tl = ss.get("targetList", [])
    node = None
    if len(tl) == 1 and not ss.get("fromClause"):
        node = tl[0].get("ResTarget", {}).get("val")
    elif len(tl) == 1 and ss.get("fromClause"):
        v = tl[0].get("ResTarget", {}).get("val")
        if _is_count_positive(v):
            sub = {k: ss[k] for k in ("fromClause", "whereClause") if k in ss}
            sub["targetList"] = [{"ResTarget": {"val": {"A_Const": {"ival": {"ival": 1}}}}}]
            sub["limitOption"] = "LIMIT_OPTION_DEFAULT"; sub["op"] = "SETOP_NONE"
            node = {"SubLink": {"subLinkType": "EXISTS_SUBLINK", "subselect": {"SelectStmt": sub}}}
    if node is None:
        return None
    consts = []
    for a in (argnodes or []):
        if _const(a) is None:
            return None            # a non-constant argument cannot be closed over -> stay on wiring
        consts.append(a)
    out = _subst_params(node, consts, argnames or [])
    return None if out is _EXPAND_FAIL else out


def _user_bool_fn(cur, fnname, _cache={}):
    """Is `fnname` a user-defined boolean function (SQL or plpgsql)? Cached per name."""
    if fnname in _cache:
        return _cache[fnname]
    parts = fnname.split("."); name = parts[-1]; sch = parts[-2] if len(parts) > 1 else None
    cur.execute("""SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        JOIN pg_type t ON t.oid=p.prorettype JOIN pg_language l ON l.oid=p.prolang
        WHERE p.proname=%s AND (%s::text IS NULL OR n.nspname=%s)
          AND t.typname='bool' AND l.lanname IN ('sql','plpgsql')
          AND n.nspname NOT IN ('pg_catalog','information_schema','auth')""", (name, sch, sch))
    _cache[fnname] = bool(cur.fetchone()[0])
    return _cache[fnname]


def _expand_udf_calls(node, cur, depth=0, seen=None):
    """Replace EVERY call to a user-defined boolean function anywhere inside `node` with its
    expanded body predicate, transitively (a function calling a function expands through, with a
    depth cap and a cycle guard). Returns the substituted node, or None when any such call cannot
    be expanded -- the caller then leaves the branch on the mock wiring path. Non-boolean and
    builtin functions are left untouched (the witness machinery handles or refuses them itself)."""
    seen = seen if seen is not None else frozenset()

    def walk(n):
        if isinstance(n, dict):
            if "FuncCall" in n and len(n) == 1:
                nm = _names((n["FuncCall"] or {}).get("funcname"))
                if nm and _user_bool_fn(cur, nm):
                    bare = nm.split(".")[-1]
                    if bare in seen or depth >= 3:
                        return _EXPAND_FAIL
                    exp = _expand_fn_predicate(cur, nm, (n["FuncCall"] or {}).get("args") or [])
                    if exp is None:
                        return _EXPAND_FAIL
                    exp2 = _expand_udf_calls(exp, cur, depth + 1, seen | {bare})
                    return _EXPAND_FAIL if exp2 is None else exp2
            out = {}
            for k, v in n.items():
                r = walk(v)
                if r is _EXPAND_FAIL:
                    return _EXPAND_FAIL
                out[k] = r
            return out
        if isinstance(n, list):
            out = []
            for x in n:
                r = walk(x)
                if r is _EXPAND_FAIL:
                    return _EXPAND_FAIL
                out.append(r)
            return out
        return n

    res = walk(node)
    return None if res is _EXPAND_FAIL else res


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
                if jk and arg is None:
                    # zero-arg fn (is_admin()): the expected value is an inline constant in the BODY
                    # (auth.jwt()->>'app_role' = 'admin') rather than a call-site argument.
                    _other = r if _jwt_keys(l) else l
                    if _const(_other) is not None:
                        return {"keys": [jk[-1]], "value": _const(_other)}
    return None



def _set_claim(c, keys, v):
    d = c
    for k in keys[:-1]:
        d = d.setdefault(k, {})
    d[keys[-1]] = v



# ---- F7: atom-kind handler registry ----------------------------------------------------------
# One handler per atom kind: contribute claims / row seed / aux rows to the identity class being
# built. Adding a kind = ONE entry here (plus, if it needs special seeding, its arm in _seed_plan).
# Handler contract: handler(at, st) mutates the build state `st` (claims, rowseed, aux,
# scalar_link, scalar_links, fk_val, tenant_keys, fn_mocks, has_temporal, handled/reason, idx, col_dom).

def _ident_link(st, col, kind):
    """Record an IDENTITY-linking column: one the row belongs to the identity THROUGH.

    `scalar_link` is singular and last-writer-wins, so on a conjunction like
    `org_id = auth.uid() AND project_id = (auth.jwt() ->> 'pid')` it names only ONE column, and the
    negative-control row the seed planner builds by flipping it is HALF-OWNED: foreign in one
    dimension and still the identity's own in the other. That is not a foreign row, so the negative
    control proves less than it claims. It is green today only because the conjunction denies a
    half-owned row anyway -- green for a reason other than the one asserted. Loosen the same policy
    to a disjunction and the block goes silently green and wrong.

    `scalar_links` accumulates EVERY identity link in order, each with its atom kind (foreign_val is
    kind-dependent). `scalar_link` keeps its existing value untouched, so the single-link consumers
    (emit's reassign-denied probe, the INSERT unique-link path) are unaffected.

    Deliberately NOT recorded: `row_const` / `col_in_set` -- value constraints, not identity links.
    Flipping those makes a row foreign for the wrong reason and can violate a CHECK or enum domain.
    Also not `array_col` / `temporal`: the seed planner already flips those by sniffing the literal."""
    if col and not any(c == col for c, _k in st["scalar_links"]):
        st["scalar_links"].append((col, kind))

def _atom_owner(at, st):
    v = CV[st["idx"] % len(CV)]; st["claims"]["sub"] = v; st["rowseed"][at["col"]] = f"'{v}'"; st["scalar_link"] = at["col"]; st["fk_val"] = v
    _ident_link(st, at["col"], "owner")

def _atom_const_identity(at, st):
    st["claims"]["sub"] = at["value"]

def _atom_tenant(at, st):
    v = CV[st["idx"] % len(CV)]; _set_claim(st["claims"], at["keys"], v); st["rowseed"][at["col"]] = f"'{v}'"; st["scalar_link"] = at["col"]; st["fk_val"] = v
    st["tenant_keys"].append(at["keys"]); _ident_link(st, at["col"], "tenant")

def _atom_claim_const(at, st):
    _set_claim(st["claims"], at["keys"], at["value"])

def _atom_row_const(at, st):
    st["rowseed"][at["col"]] = f"'{at['value']}'"; st["scalar_link"] = at["col"]

def _atom_membership(at, st):
    uid = MV[st["idx"] % len(MV)]; sc = CV[st["idx"] % len(CV)]; st["claims"]["sub"] = uid
    st["rowseed"][at["row_scope_col"]] = f"'{sc}'"; st["scalar_link"] = at["row_scope_col"]; st["fk_val"] = sc
    _ident_link(st, at["row_scope_col"], "membership")
    st["aux"].append({"table": at["mtable"], "cols": {at["muser_col"]: uid, at["mscope_col"]: sc},
                      "kind": "membership", "muser_col": at["muser_col"], "mscope_col": at["mscope_col"]})
    for _mk in at.get("mock_fns", []):   # mock the in-EXISTS fn to the seeded scope value (when it gates that same col)
        if _mk["mcol"] == at["mscope_col"]:
            st["fn_mocks"].append({"node": _mk["node"], "value": sc})

def _atom_array_col(at, st):
    uid = CV[st["idx"] % len(CV)]; st["claims"]["sub"] = uid; st["rowseed"][at["col"]] = f"ARRAY['{uid}']::uuid[]"

def _atom_temporal(at, st):
    st["has_temporal"] = True
    st["rowseed"][at["col"]] = "now() + interval '1 day'" if at["op"].startswith(">") else "now() - interval '1 day'"

def _atom_rbac(at, st):
    lbl = at.get("role_label", "tg_role"); st["claims"][at["claim"]] = lbl
    st["aux"].append({"table": at["rtable"], "cols": {at["role_col"]: lbl, at["perm_col"]: at["arg"]}, "kind": "rbac"})

def _atom_folder_owner(at, st):
    uid = CV[st["idx"] % len(CV)]; st["claims"]["sub"] = uid; st["rowseed"][at["col"]] = f"'{uid}/x'"; st["scalar_link"] = at["col"]
    _ident_link(st, at["col"], "folder_owner")

def _atom_auth_role(at, st):
    pass

def _atom_authuid_present(at, st):
    st["claims"]["sub"] = CV[st["idx"] % len(CV)]   # auth.uid() IS NOT NULL: give the authorized identity a concrete logged-in uid

def _atom_col_in_set(at, st):
    st["rowseed"][at["col"]] = f"'{at['values'][0]}'"   # seed a value that satisfies the membership; no scalar_link (value constraint, not identity link)

def _atom_col_not_in_set(at, st):
    dom = (st["col_dom"] or {}).get(at["col"])
    outside = next((x for x in (dom or []) if x not in at["values"]), None)
    if outside is None:
        st["handled"], st["reason"] = False, f"unsatisfiable branch: {at['col']} can never be outside {at['values']} (the enum/domain has no other value), so this NOT-IN/<> ALL predicate never grants — a dead or over-restrictive policy; left untested because no satisfying row exists"
    else:
        st["rowseed"][at["col"]] = f"'{outside}'"

def _atom_scalar_lookup(at, st):
    uid = f"a5000000-0000-4000-8000-{st['idx']:012x}"; st["claims"]["sub"] = uid   # unique per class (avoid PK collisions in the lookup table when >len(MV) classes)
    st["aux"].append({"table": at["ltable"], "cols": {at["lkey"]: uid, at["lcol"]: at["value"]},
                      "kind": "scalar_lookup", "role_value": at["value"]})

def _guc_val(idx):
    # Distinct from every JWT `sub` value (CV) so the unique-owner INSERT path in the seed planner, which
    # swaps in a fresh identity when the sub equals the owner literal, never mistakes a GUC owner for a uid.
    # uuid-shaped so a `uuid_col = current_setting(..)::uuid` policy casts cleanly as well as a text column.
    return f"9a000000-0000-4000-8000-{idx:012x}"

def _atom_guc_owner(at, st):
    """col = current_setting('name'): drive the REAL session GUC to the value the authorized row carries
    (never mocked). The rival identity sets the same GUC to a different tenant (seeding)."""
    v = _guc_val(st["idx"]); st["gucs"][at["keys"][0]] = v
    st["rowseed"][at["col"]] = f"'{v}'"; st["scalar_link"] = at["col"]; st["fk_val"] = v
    _ident_link(st, at["col"], "guc")

def _atom_session_owner(at, st):
    """col = SESSION_USER: act as a real role via SET SESSION AUTHORIZATION, own the seeded row as that
    role. The second discovered role is the rival (a different real session user)."""
    r = at["values"][0]; st["session"] = r; st["session_rival"] = at["values"][1]
    st["rowseed"][at["col"]] = "'" + r.replace("'", "''") + "'"; st["scalar_link"] = at["col"]; st["fk_val"] = r
    _ident_link(st, at["col"], "session")

ATOM_HANDLERS = {
    "guc_owner": _atom_guc_owner, "session_owner": _atom_session_owner,
    "owner": _atom_owner, "const_identity": _atom_const_identity, "tenant": _atom_tenant,
    "claim_const": _atom_claim_const, "row_const": _atom_row_const, "membership": _atom_membership,
    "array_col": _atom_array_col, "temporal": _atom_temporal, "rbac": _atom_rbac,
    "folder_owner": _atom_folder_owner, "auth_role": _atom_auth_role,
    "authuid_present": _atom_authuid_present, "col_in_set": _atom_col_in_set,
    "col_not_in_set": _atom_col_not_in_set, "scalar_lookup": _atom_scalar_lookup,
}


def build_class(min_term, idx, col_dom=None):
    st = {"idx": idx, "col_dom": col_dom,
          "claims": {"sub": CV[idx % len(CV)], "role": "authenticated"},
          "rowseed": {}, "aux": [], "scalar_link": None, "scalar_links": [], "fk_val": None, "handled": True,
          "reason": None, "has_temporal": False, "tenant_keys": [], "fn_mocks": [],
          "gucs": {}, "session": None, "session_rival": None}
    for at in min_term:
        h = ATOM_HANDLERS.get(at["kind"])
        if h is None:
            st["handled"], st["reason"] = False, f"unhandled atom: {at.get('text')}"
        else:
            h(at, st)
    # Non-JWT session identity (GUC / SESSION_USER) rides inside the claims under reserved `__rlsa_*` keys,
    # so every probe/emit path that already threads a claims JSON drives it unchanged. EmitContext.ident /
    # pident strip these keys before setting request.jwt.claims. Absent for every JWT-only class.
    if st["gucs"]:
        st["claims"]["__rlsa_guc"] = dict(st["gucs"])
    if st["session"]:
        st["claims"]["__rlsa_session"] = st["session"]
    # Every synthetic authenticated identity carries a future 'exp' so an expiry-aware helper that a policy
    # OR's alongside a handled branch (e.g. `has_role(...) OR user_id = auth.uid()`) returns false for this
    # identity instead of RAISE'ing invalid_jwt (P0001) when the real policy is probed.
    st["claims"].setdefault("exp", FUTURE_EXP)
    return IdentityClass(idx=idx, claims=st["claims"], rowseed=st["rowseed"], aux=st["aux"],
                         scalar_link=st["scalar_link"], scalar_links=st["scalar_links"],
                         fk_val=st["fk_val"], rowlinked=bool(st["rowseed"]),
                         handled=st["handled"], reason=st["reason"], has_temporal=st["has_temporal"],
                         kinds=[a["kind"] for a in min_term], tenant_keys=st["tenant_keys"],
                         fn_mocks=st["fn_mocks"],
                         guc_keys=(sorted(st["gucs"]) or None), session_rival=st["session_rival"])



def _cmd_dnf(pols, cmd, clause, cur):
    # Only policies applicable to a CLIENT identity (PUBLIC / authenticated / anon) shape the client DNF.
    # A policy granted only to service_role (or authenticator / supabase_auth_admin) must NOT create an
    # authenticated/anon class: service_role bypasses RLS and is reported separately, and folding its
    # `USING (true)` in would spawn a bogus "open" branch that a client identity cannot actually use.
    _client = {"public", "authenticated", "anon", "anonymous"}
    apps = [p for p in pols if p[2].upper() in (cmd, "ALL") and ((not p[3]) or any(r in _client for r in p[3]))]
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
            if pe: dnf.append([Atom(kind="unknown", text="parse-fail")]); srcs.append({"policy": p[0], "check": chk})
            continue
        for mt in _dnf_ast(w):
            atoms = [a for a in (classify_node(n, cur) for n in mt) if a.get("kind") != "_true_"]
            for a in atoms:
                if a.get("kind") == "auth_role" and a.get("value") == "authenticated": is_open = True
                if a.get("kind") == "authuid_present": is_open = True   # auth.uid() IS NOT NULL: open to any authenticated user
            if not atoms: is_open = True
            key = tuple(sorted(f"{a.get('kind')}|{a.get('col')}|{a.get('value')}|{a.get('mtable')}|{','.join(map(str, a.get('values', [])))}|{a.get('text')}" for a in atoms))   # text: two DIFFERENT unknown atoms must not collide (a colliding key silently dropped the second branch)
            if key not in seen: seen.add(key); dnf.append(atoms); srcs.append({"policy": p[0], "check": chk, "raw": list(mt)})
    rest, rest_raw = [], []
    for p in restr:
        pe = eff(p)
        w = _where(pe) if pe else None
        if w:
            rest_raw.append(w)   # MB-6: the RAW restrictive predicate node -> conjoined into every routed obligation
            for mt in _dnf_ast(w): rest += [classify_node(n, cur) for n in mt]
    dnf = [mt + rest for mt in dnf]
    if rest_raw:
        # A restrictive policy is AND'd onto whichever permissive branch grants (Postgres semantics). The
        # classified path already conjoins the classified restrictive atoms above (`mt + rest`); this carries
        # the same predicates in RAW form so the OBLIGATION ROUTER can conjoin them into an UNCLASSIFIED
        # branch's solver node too -- otherwise a rescued witness satisfies only the permissive part, the real
        # policy (which includes the restrictive check) denies, and the branch falls to PARTIALLY TESTED
        # (sound, but coverage lost). Same list for every min-term of this command.
        for s in srcs:
            s["raw_restrict"] = list(rest_raw)
    return dnf, bool(perm), is_open, srcs



def analyze(cur, schema, table):
    _ANALYZE_CTX.schema = schema   # read by _session_roles to prefer the schema's own roles
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
            cc["raw_restrict"] = srcs[i].get("raw_restrict") if i < len(srcs) else None   # MB-6: raw restrictive predicates to conjoin into the routed obligation
            classes.append(cc)
        per[cmd] = {"classes": classes, "open": is_open, "has_pol": has_pol}
        if cmd == "SELECT":
            per[cmd]["anon_open"] = any(("public" in (p[3] or []) or "anon" in (p[3] or []) or "anonymous" in (p[3] or [])) and _is_true_clause(p[4])
                                        for p in pols if p[2].upper() in ("SELECT", "ALL") and p[1] == "PERMISSIVE")
    notes = []
    _pgroles = sorted({r for p in pols for r in (p[3] or []) if str(r).startswith("pg_")})
    if _pgroles:
        notes.append("policy audience includes built-in group role(s) " + ", ".join(_pgroles) +
                     " -- membership in pg_* roles is computed by Postgres (not SET ROLE-able), so these"
                     " audiences are noted but not probed as custom roles; verify their reach manually")
    for p in pols:
        if p[2].upper() in ("SELECT", "ALL") and p[1] == "PERMISSIVE" and _is_true_clause(p[4]):
            notes.append(f"policy {p[0]}: SELECT USING (true) -> every {p[3]} sees ALL rows (review)")
        if p[2].upper() == "INSERT" and _is_true_clause(p[5]):
            notes.append(f"policy {p[0]}: INSERT WITH CHECK (true) -> any {p[3]} may write any row (review)")
    return pols, per, sorted(cmds, key=lambda c: ORDER.index(c) if c in ORDER else 9), notes

