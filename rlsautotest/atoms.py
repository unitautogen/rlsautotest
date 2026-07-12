# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""Predicate classification: policy clause -> boolean AST -> DNF min-terms -> labeled atoms / identity classes.

Split out of the original single-module cli.py; behavior-preserving.
"""
from __future__ import annotations
import argparse, json, re, sys
import psycopg
from pglast.parser import parse_sql_json
from .structs import Atom, IdentityClass
from .astutil import ORDER, _and_conjuncts, _array_consts, _colname, _colqual, _const, _eq_pairs, _find_queries, _is_func, _is_true_clause, _is_uuid, _jwt_anywhere, _jwt_keys, _list_consts, _names, _not, _t, _unwrap, _v, _where, _subquery_sig
from .values import CV, FUTURE_EXP, MV



def _membership(subselect, testexpr):
    """Recognize the CANONICAL membership subquery only: a single base table, an `auth.uid()` identity, exactly
    ONE correlation (subq col = outer col), optional opaque-fn conjuncts to mock, and NOTHING else. Anything
    richer (an extra `role='admin'`/`can_read` condition, a second correlation, OR in the WHERE) returns
    'unknown' so the branch falls to the general `_solve_subquery` witness builder, which seeds those too.
    F2: a thin labeler over the shared `_subquery_sig` reader — the shape grammar lives there, once."""
    sig = _subquery_sig(subselect, testexpr)
    if (sig is not None and sig["uid"] and len(sig["corr"]) == 1
            and not sig["extras"] and not sig["unmodeled"]):
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
# scalar_link, fk_val, tenant_keys, fn_mocks, has_temporal, handled/reason, idx, col_dom).

def _atom_owner(at, st):
    v = CV[st["idx"] % len(CV)]; st["claims"]["sub"] = v; st["rowseed"][at["col"]] = f"'{v}'"; st["scalar_link"] = at["col"]; st["fk_val"] = v

def _atom_const_identity(at, st):
    st["claims"]["sub"] = at["value"]

def _atom_tenant(at, st):
    v = CV[st["idx"] % len(CV)]; _set_claim(st["claims"], at["keys"], v); st["rowseed"][at["col"]] = f"'{v}'"; st["scalar_link"] = at["col"]; st["fk_val"] = v
    st["tenant_keys"].append(at["keys"])

def _atom_claim_const(at, st):
    _set_claim(st["claims"], at["keys"], at["value"])

def _atom_row_const(at, st):
    st["rowseed"][at["col"]] = f"'{at['value']}'"; st["scalar_link"] = at["col"]

def _atom_membership(at, st):
    uid = MV[st["idx"] % len(MV)]; sc = CV[st["idx"] % len(CV)]; st["claims"]["sub"] = uid
    st["rowseed"][at["row_scope_col"]] = f"'{sc}'"; st["scalar_link"] = at["row_scope_col"]; st["fk_val"] = sc
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

ATOM_HANDLERS = {
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
          "rowseed": {}, "aux": [], "scalar_link": None, "fk_val": None, "handled": True,
          "reason": None, "has_temporal": False, "tenant_keys": [], "fn_mocks": []}
    for at in min_term:
        h = ATOM_HANDLERS.get(at["kind"])
        if h is None:
            st["handled"], st["reason"] = False, f"unhandled atom: {at.get('text')}"
        else:
            h(at, st)
    # Every synthetic authenticated identity carries a future 'exp' so an expiry-aware helper that a policy
    # OR's alongside a handled branch (e.g. `has_role(...) OR user_id = auth.uid()`) returns false for this
    # identity instead of RAISE'ing invalid_jwt (P0001) when the real policy is probed.
    st["claims"].setdefault("exp", FUTURE_EXP)
    return IdentityClass(idx=idx, claims=st["claims"], rowseed=st["rowseed"], aux=st["aux"],
                         scalar_link=st["scalar_link"], fk_val=st["fk_val"], rowlinked=bool(st["rowseed"]),
                         handled=st["handled"], reason=st["reason"], has_temporal=st["has_temporal"],
                         kinds=[a["kind"] for a in min_term], tenant_keys=st["tenant_keys"],
                         fn_mocks=st["fn_mocks"])



def _cmd_dnf(pols, cmd, clause, cur):
    # Only policies applicable to a CLIENT identity (PUBLIC / authenticated / anon) shape the client DNF.
    # A policy granted only to service_role (or authenticator / supabase_auth_admin) must NOT create an
    # authenticated/anon class: service_role bypasses RLS and is reported separately, and folding its
    # `USING (true)` in would spawn a bogus "open" branch that a client identity cannot actually use.
    _client = {"public", "authenticated", "anon"}
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

