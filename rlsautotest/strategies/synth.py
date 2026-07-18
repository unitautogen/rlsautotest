# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""GUC / JWT-claim / mocked-scalar-fn gate strategy: SET the session input the policy reads,
SEED a matching row, and probe-verify (a wrong guess is harmless — the probe observes)."""
from __future__ import annotations

from ..astutil import _colname, _const, _jwt_anywhere, _jwt_keys, _names, _qi, _qlit, _t, _unwrap, _v, _where
from ..probe import _probe
from ..seeding import _synth_required_cols
from .base import HANDLED, PASS
from .mock import _opaque_fn_sig


def _synth_gate(conn, schema, table, cmd, coltypes):
    """If the (single) policy for cmd gates on `col = <session GUC / JWT claim>`, `col = ANY(<array claim>)`,
    or `col = <opaque scalar fn()>` (mocked), return a plan to synthesize a matching identity. Probe-verified
    downstream, so a wrong guess is harmless."""
    fld = "with_check" if cmd == "INSERT" else "qual"
    cur = conn.cursor()
    cur.execute(f"SELECT {fld} FROM pg_policies WHERE schemaname=%s AND tablename=%s AND cmd IN (%s,'ALL')", (schema, table, cmd))
    exprs = [r[0] for r in cur.fetchall() if r[0]]
    if len(exprs) != 1:
        return None
    e = exprs[0]
    w = _where(e)
    if w is None:
        return None
    # F6: read the gate from the parse tree, not regexes over the deparsed policy text — a stray
    # '...'::text literal elsewhere in the policy can no longer poison the claim path, casts are
    # unwrapped structurally, and `current_setting(...) = col` (reversed order) is recognized.
    def _walk_gates(n):
        out = []
        if not isinstance(n, dict): return out
        t0 = _t(n)
        if t0 == "BoolExpr":
            for a0 in _v(n).get("args", []): out += _walk_gates(a0)
        elif t0 == "A_Expr" and _names(_v(n).get("name")) == "=":
            out.append((_v(n).get("kind"), _v(n).get("lexpr"), _v(n).get("rexpr")))
        elif t0 == "SubLink" and _v(n).get("subLinkType") == "ANY_SUBLINK":
            out.append(("IN_SUBLINK", _v(n).get("testexpr"), _v(n).get("subselect")))
        return out
    for (kind0, L, R) in _walk_gates(w):
        if kind0 == "IN_SUBLINK":                              # col IN (SELECT jsonb_array_elements_text(auth.jwt()->'k'))
            col = _colname(L); jk = _jwt_anywhere(R)
            if col in coltypes and jk:
                return {"col": col, "kind": "claim_array", "path": jk}
            continue
        arr = (kind0 == "AEXPR_OP_ANY")                        # col = ANY(<claim-derived array>)
        for a, b in ((L, R), (R, L)):
            col = _colname(a)
            if not col or col not in coltypes:
                continue
            bu = _unwrap(b)
            if _t(bu) == "FuncCall" and _names(_v(bu).get("funcname")).split(".")[-1] == "current_setting":
                _ga = _v(bu).get("args", [])
                _gn = _const(_ga[0]) if _ga else None
                if _gn:
                    return {"col": col, "kind": "guc", "name": _gn}
            jk = _jwt_keys(b) or (arr and _jwt_anywhere(b))
            if jk:
                return {"col": col, "kind": "claim_array" if arr else "claim_scalar", "path": jk}
    # `col = <opaque scalar fn()>` (e.g. realtime.topic() = room_topic): mock the fn to the seeded value.
    if w is not None and _t(w) == "A_Expr" and _names(_v(w).get("name")) == "=":
        L, R = _v(w).get("lexpr"), _v(w).get("rexpr")
        gcol = _colname(L) or _colname(R)
        other = R if _colname(L) else L
        if gcol in coltypes:
            sig = _opaque_fn_sig(conn, other)
            if sig:
                return {"col": gcol, "kind": "mockfn", **sig}
    return None


def synth_emit(ctx, baker, cmd, gate):
    """Drive an opaque GUC/claim-gated command by SETTING the input (GUC / JWT claim) and SEEDING a
    matching row, then probe-verify. Returns True if handled, False to fall through (e.g. unsatisfiable FK)."""
    conn, schema, table, q = ctx.conn, ctx.schema, ctx.table, ctx.q
    coltypes, cols, fkmap, unique_cols = ctx.coltypes, ctx.cols, ctx.fkmap, ctx.unique_cols
    body, n, reseed, fill = ctx.body, ctx.n, ctx.reseed, ctx.fill
    desc, _upd_val, upd_col, _fk_cols = ctx.desc, ctx.upd_val, ctx.upd_col, ctx.fk_cols
    _spair, _vlit, _claims_for = ctx.spair, ctx.vlit, ctx.claims_for
    req, bad = _synth_required_cols(conn, schema, table, fkmap)
    if bad: return False
    ctype = coltypes.get(gate["col"], "text")
    Va, Vb = _spair(ctype)
    seedcols = {gate["col"]: _vlit(ctype, Va)}
    for rn, rt in req:
        if rn != gate["col"]: seedcols[rn] = fill(rt)
    seedrow = f"INSERT INTO {q}({', '.join(_qi(c) for c in seedcols)}) VALUES ({', '.join(seedcols.values())})"
    if cmd == "UPDATE":
        # Update a NEUTRAL column (not the gated/scope column): SET gate_col would test scope-movement,
        # not the UPDATE grant. Prefer the global upd_col if it isn't the gate col, else pick any plain
        # non-gate, non-FK, non-unique column (e.g. `body` on a GUC-scoped `items`).
        wc = upd_col if (upd_col and upd_col[0] != gate["col"]) else next(
            ((n0, t0) for (n0, t0, c0, h0) in cols if not h0 and n0 != gate["col"] and n0 not in unique_cols and n0 not in _fk_cols), None)
        if not wc: return True   # no neutral column to UPDATE without touching the gated column -> honest skip
        act = f"UPDATE {q} SET {_qi(wc[0])}={_upd_val(wc[0], wc[1])}"
    elif cmd == "DELETE": act = f"DELETE FROM {q}"
    elif cmd == "INSERT": act = seedrow
    else: act = None
    def one(who, V, role, ident):
        guc = (gate["name"], V) if (gate["kind"] == "guc" and V is not None) else None
        mock_sql = None
        if gate["kind"] == "mockfn":
            who = who + " [mocked; wiring]"   # flips the report's mock footgun; identity parsing still keys on who's words
            mv = V if V is not None else Vb   # value the opaque fn is mocked to return (=Va matches the seeded col -> grant)
            mock_sql = (f"CREATE OR REPLACE FUNCTION {gate['q']}({gate['args']}) RETURNS {gate['rettype']} "
                        f"LANGUAGE sql AS $$ SELECT {_vlit(gate['rettype'], mv)}::{gate['rettype']} $$")
        claims = None if role == "anon" else _claims_for(gate, V)
        pid = ([f"SELECT set_config('{guc[0]}', '{guc[1]}', true)"] if guc else [])
        pid += (["SELECT set_config('request.jwt.claims', '', true)", "SET LOCAL ROLE anon"] if role == "anon"
                else [f"SELECT set_config('request.jwt.claims', {_qlit(claims)}, true)", "SET LOCAL ROLE authenticated"])
        arrange = [f"DELETE FROM {q}"] + ([mock_sql] if mock_sql else []) + ([] if cmd == "INSERT" else [seedrow])
        if cmd == "SELECT":
            o = _probe(conn, arrange, pid, "read", f"SELECT count(*) FROM {q}")
            asrt = baker.read_assert(o, who, ident=ident, mocked=(gate["kind"] == "mockfn"))
        else:
            o = _probe(conn, arrange, pid, "write", act)
            asrt = baker.write_assert(o, cmd, act, who, ident=ident, mocked=(gate["kind"] == "mockfn"))
        n[0] += 1
        body.append("RESET ROLE;")
        body.append(f"DELETE FROM {q};")
        if cmd != "INSERT": body.append(seedrow + ";")
        if mock_sql: body.append(mock_sql + ";")   # install the fn mock as the privileged role, before SET ROLE
        if guc: body.append(f"SELECT set_config('{guc[0]}', '{guc[1]}', true);")
        body.extend(["SELECT set_config('request.jwt.claims', '', true);", "SET LOCAL ROLE anon;"] if role == "anon"
                    else [f"SELECT set_config('request.jwt.claims', {_qlit(claims)}, true);", "SET LOCAL ROLE authenticated;"])
        body.append(asrt)
        body.append("RESET ROLE;")
        body.append(reseed)
    one("authenticated, authorized", Va, "authenticated", "authorized")
    one("authenticated, not authorized", Vb, "authenticated", "other")
    one("anon", Vb if gate["kind"] in ("guc", "mockfn") else None, "anon", "anon")   # GUC/mockfn: give anon a valid (mismatch) value so the ::uuid cast can't 22P02
    return True


def run(ctx, baker, cmd):
    if ctx.classes:   # a classified branch owns this command; these strategies serve the unclassified case
        return PASS
    gate = _synth_gate(ctx.conn, ctx.schema, ctx.table, cmd, ctx.coltypes)   # GUC / JWT-claim gate -> SET the input + SEED a match
    if gate and synth_emit(ctx, baker, cmd, gate):
        return HANDLED
    return PASS
