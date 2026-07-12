# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""Force-mock strategy (last resort): the predicate references opaque fn(s) no specific
path handled — mock them to force the predicate true/false, probe, and bake (wiring proof)."""
from __future__ import annotations
import re

from ..astutil import _colname, _const, _names, _qlit, _t, _v
from ..probe import _probe, _unrel_fail
from ..seeding import _synthesize_row
from .base import AUGMENT, PASS
from .mock import _mocklit, _opaque_fn_sig


def _force_sentinels(typ):
    t = (typ or "text").lower()
    if "uuid" in t: return ("5cf00000-0000-4000-8000-0000000000a1", "5cf00000-0000-4000-8000-0000000000b2")
    if any(k in t for k in ("int", "numeric", "real", "double", "decimal", "money", "serial")): return ("424242", "515151")
    if "bool" in t: return ("true", "false")
    return ("rlsf_a", "rlsf_b")


def _force_atom_plan(conn, node, coltypes):
    """How to FORCE one unhandled atom true/false by mocking the opaque fn(s) in it. Returns
       {"fns": [(sig, true_lit, false_lit), ...], "seed": (col, col_lit) | None}  or None if not forceable.
    Covers: a boolean fn used as the atom; `fn() = const`; `col = fn()` (seed the col); `fn() = fn()`.
    Equality only — ordering/pattern/arithmetic stay NT (force can't be coordinated soundly)."""
    tnode = _t(node)
    if tnode in ("FuncCall", "SubLink"):                       # boolean fn used directly as the predicate atom
        sig = _opaque_fn_sig(conn, node, allow_bool=True)
        if sig and (sig["rettype"] or "").lower() in ("boolean", "bool"):
            return {"fns": [(sig, "true", "false")], "seed": None}
        return None
    if tnode != "A_Expr" or _names(_v(node).get("name")) != "=":
        return None
    L, R = _v(node).get("lexpr"), _v(node).get("rexpr")
    sigL = _opaque_fn_sig(conn, L, allow_bool=True)
    sigR = _opaque_fn_sig(conn, R, allow_bool=True)
    if sigL and sigR:                                          # fn() = fn()  -> mock equal (true) / differ (false)
        return {"fns": [(sigL, _mocklit(sigL["rettype"], "rlsf_eq"), _mocklit(sigL["rettype"], "rlsf_eq")),
                        (sigR, _mocklit(sigR["rettype"], "rlsf_eq"), _mocklit(sigR["rettype"], "rlsf_ne"))], "seed": None}
    sig = sigL or sigR
    other = R if sigL else L
    if not sig:
        return None
    c = _const(other)
    if c is not None:                                          # fn() = const -> mock fn to const (true) / other (false)
        Sd = str(int(c) + 1) if re.fullmatch(r"-?\d+", str(c)) else ("rlsf_other" if str(c) != "rlsf_other" else "rlsf_alt")
        return {"fns": [(sig, _mocklit(sig["rettype"], c), _mocklit(sig["rettype"], Sd))], "seed": None}
    col = _colname(other)
    if col and col in coltypes:                                # col = fn() -> seed col, mock fn to match (true) / differ (false)
        Sg, Sd = _force_sentinels(coltypes[col])
        return {"fns": [(sig, _mocklit(sig["rettype"], Sg), _mocklit(sig["rettype"], Sd))],
                "seed": (col, _mocklit(coltypes[col], Sg))}
    return None


def mock_force_emit(ctx, baker, cmd):
    """Last-resort wiring proof: the predicate references opaque fn(s) no specific path handled. MOCK
    them to FORCE the predicate true (authorized -> grant) and false (-> deny), PROBE to OBSERVE the
    real outcome, and bake it. Bails to NT if the forced-grant isn't actually observed -> never a
    false pass. Single min-term, equality-coordinated atoms only (see _force_atom_plan). The fn's own
    logic stays unverified -> [mocked; wiring] tag -> report footgun."""
    conn, schema, table, q = ctx.conn, ctx.schema, ctx.table, ctx.q
    per, coltypes, NB = ctx.per, ctx.coltypes, ctx.NB
    body, n, reseed, desc = ctx.body, ctx.n, ctx.reseed, ctx.desc
    _upd_val, upd_col = ctx.upd_val, ctx.upd_col
    ucls = [c for c in per.get(cmd, {}).get("classes", []) if not c.get("handled") and c.get("raw_atoms")]
    if len(ucls) != 1:                                  # multi-OR opaque -> honest NT
        return False
    fns, seedcols = {}, {}
    for node in ucls[0]["raw_atoms"]:
        plan = _force_atom_plan(conn, node, coltypes)
        if not plan:                                    # an atom we can't force -> bail (NT)
            return False
        for (sig, tv, fv) in plan["fns"]:
            k = sig["q"]
            if k in fns and (fns[k]["t"] != tv or fns[k]["f"] != fv):
                return False                            # same fn needs conflicting values -> bail
            fns[k] = {"sig": sig, "t": tv, "f": fv}
        if plan["seed"]:
            sc, sv = plan["seed"]
            if sc in seedcols and seedcols[sc] != sv:
                return False
            seedcols[sc] = sv
    if not fns:
        return False
    recipe, srow, setup = _synthesize_row(conn, schema, table, fixed=seedcols)
    if recipe is None or not srow:
        return False
    setup = setup or []
    ins = f"INSERT INTO {q}({', '.join(srow)}) VALUES ({', '.join(srow.values())})"
    def mocks(which):
        return [f"CREATE OR REPLACE FUNCTION {f['sig']['q']}({f['sig']['args']}) RETURNS {f['sig']['rettype']} LANGUAGE sql AS $$ SELECT {f[which]} $$" for f in fns.values()]
    if cmd == "UPDATE":
        if not upd_col: return False
        act = f"UPDATE {q} SET {upd_col[0]}={_upd_val(upd_col[0], upd_col[1])}"
    elif cmd == "DELETE": act = f"DELETE FROM {q}"
    elif cmd == "INSERT": act = ins
    elif cmd == "SELECT": act = None
    else: return False
    def arr(which):
        base = [f"DELETE FROM {q}"] + mocks(which) + setup
        return base if cmd == "INSERT" else base + [ins]
    NBpid = [f"SELECT set_config('request.jwt.claims', {_qlit(NB)}, true)", "SET LOCAL ROLE authenticated"]
    anonpid = ["SELECT set_config('request.jwt.claims', '', true)", "SET LOCAL ROLE anon"]
    if cmd == "SELECT":   # GRANT probe FIRST: only bake if forcing the fn true actually grants
        og = _probe(conn, arr("t"), NBpid, "read", f"SELECT count(*) FROM {q}")
        if og[2] or og[0] != "count" or og[1] < 1: return False
        od = _probe(conn, arr("f"), NBpid, "read", f"SELECT count(*) FROM {q}")
        oa = _probe(conn, arr("f"), anonpid, "read", f"SELECT count(*) FROM {q}")
    else:
        og = _probe(conn, arr("t"), NBpid, "write", act)
        if og[2] or not (og[0] == "rows" and og[1] >= 1): return False
        od = _probe(conn, arr("f"), NBpid, "write", act)
        oa = _probe(conn, arr("f"), anonpid, "write", act)
    def bake(o, who, ident):
        if cmd == "SELECT":
            return baker.read_assert(o, who, ident=ident, mocked=True)
        return baker.write_assert(o, cmd, act, who, ident=ident, mocked=True)
    def emit_one(o, who, which, role, ident):
        n[0] += 1
        body.append("RESET ROLE;"); body.append(f"DELETE FROM {q};")
        body.extend((s.rstrip().rstrip(';') + ";") for s in mocks(which))
        body.extend((s.rstrip().rstrip(';') + ";") for s in setup)
        if cmd != "INSERT": body.append(ins + ";")
        body.extend(["SELECT set_config('request.jwt.claims', '', true);", "SET LOCAL ROLE anon;"] if role == "anon"
                    else [f"SELECT set_config('request.jwt.claims', {_qlit(NB)}, true);", "SET LOCAL ROLE authenticated;"])
        body.append(bake(o, who, ident)); body.append("RESET ROLE;"); body.append(reseed)
    fnlist = ", ".join(f["sig"]["name"] + "()" for f in fns.values())
    emit_one(og, "authenticated, authorized when " + fnlist + " [mocked; wiring]", "t", "authenticated", "authorized")
    emit_one(od, "authenticated, not authorized when " + fnlist + " forced false [mocked; wiring]", "f", "authenticated", "other")
    emit_one(oa, "anon [mocked; wiring]", "f", "anon", "anon")
    return True


def run(ctx, baker, cmd):
    if ctx.classes:   # a classified branch owns this command; force-mock serves the unclassified case
        return PASS
    mock_force_emit(ctx, baker, cmd)   # opaque SCALAR fn in a comparison -> force-mock (wiring), else NT
    return AUGMENT   # the old ladder ignored the return value and fell through to the identity battery
