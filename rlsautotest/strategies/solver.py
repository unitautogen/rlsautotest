# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""The general witness-solver strategy: derive a witness for an ARBITRARY predicate,
DB-verify it, and bake the observed grant/deny pair. Includes the construct-first
DB-oracle floors (BL-6 single-column, BL-11 joint session x multi-column search)."""
from __future__ import annotations
import json

from ..astutil import _claim_paths, _expr_cols, _expr_consts, _jwt_anywhere, _qi, _qlit, _qt, _where
from ..atoms import _set_claim
from ..probe import _probe
from ..seeding import _aux_row_stmts, _ensure_table_loaded, _mock_valid_row, _synth_required_cols
from ..witness import _WV_UID, _candidate_sessions, _candidate_values, _solve_predicate, _wv_ctx, _wv_lit
from ..structs import Observation
from .base import HANDLED, PASS


def _construct_witness(ctx, expr):
    """BL-6 construct-first DB-ORACLE floor: when no specific leaf can witness `expr`, vary a single free
    row column over a bounded candidate set and let Postgres tell us which value makes the predicate TRUE
    (grant) vs FALSE (deny). A brand-new operator/function (`starts_with(col,'x')`, `col % 2 = 0`, a custom
    operator) becomes solvable with ZERO operator-specific code. Returns (sat, fal) witness contexts or
    None. SOUND: every candidate is DB-probed and only a confirmed true+false pair is returned (and
    solve_emit re-verifies before baking) -> never a false pass; no pair within budget -> honest NT.
    Scope: row-column-driven predicates (claim-dependent ones are left to the claim-aware leaves / NT)."""
    conn, schema, table, q = ctx.conn, ctx.schema, ctx.table, ctx.q
    coltypes, enums = ctx.coltypes, ctx.enums
    fkmap, colsmap, checks, relchecks, compfks = ctx.fkmap, ctx.colsmap, ctx.checks, ctx.relchecks, ctx.compfks
    if _jwt_anywhere(expr):                       # claim-dependent -> not the row-column floor
        return None
    cols = _expr_cols(expr, coltypes)
    if not cols:
        return None
    col = cols[0]; ct = coltypes.get(col, "text")
    cands = []
    for v in (_candidate_values(ct, enums) + _expr_consts(expr)):
        if v not in cands: cands.append(v)
    parents, base_row = _mock_valid_row(schema, table, fkmap, colsmap, enums, checks, relchecks, compfks, conn)
    pid = [f"SELECT set_config('request.jwt.claims', {_qlit(json.dumps({'sub': _WV_UID, 'role': 'authenticated'}))}, true)",
           "SET LOCAL ROLE authenticated"]
    grant_v = deny_v = None; got_g = got_d = False
    for cand in cands:
        rr = dict(base_row); rr[col] = _wv_lit(ct, cand)
        ins = f"INSERT INTO {q}({', '.join(_qi(c) for c in rr)}) VALUES ({', '.join(rr.values())})"
        o = _probe(conn, [f"DELETE FROM {q}"] + parents + [ins], pid, "read", f"SELECT count(*) FROM {q}")
        if o[2] or o[0] != "count":
            continue                               # this candidate couldn't be seeded/observed -> try the next
        if o[1] >= 1 and not got_g: grant_v, got_g = cand, True
        elif o[1] == 0 and not got_d: deny_v, got_d = cand, True
        if got_g and got_d: break
    if not (got_g and got_d):
        return None
    sat = _wv_ctx(); sat["sub"] = _WV_UID; sat["row"][col] = grant_v
    fal = _wv_ctx(); fal["sub"] = _WV_UID; fal["row"][col] = deny_v
    return (sat, fal)


def _search_witness(ctx, expr):
    """BL-11 JOINT signature-driven DB-oracle search — the completion of the construct-first floor. Where
    `_construct_witness` varies a SINGLE row column, this collects the FULL controllable signature the
    predicate references (every row column AND every JWT claim path) and searches a bounded cross-product
    of (session x row) candidate assignments, letting Postgres judge each, until it finds one that GRANTS
    and one that DENIES. Closes the two real residual gaps: genuinely JOINT multi-column predicates and
    CLAIM-dependent novel predicates (which `_construct_witness` refuses outright). Budget-capped ->
    honest NT beyond the bound; DB-confirmed (solve_emit re-verifies before baking) -> never a false pass.
    Out of scope (correctly NT): hidden/external-state functions, and satisfiers outside the candidate set."""
    import itertools
    conn, schema, table, q = ctx.conn, ctx.schema, ctx.table, ctx.q
    coltypes, enums = ctx.coltypes, ctx.enums
    fkmap, colsmap, checks, relchecks, compfks = ctx.fkmap, ctx.colsmap, ctx.checks, ctx.relchecks, ctx.compfks
    cols = _expr_cols(expr, coltypes)
    cpaths = _claim_paths(expr)
    if not (cols or cpaths) or len(cols) > 3:        # nothing controllable, or too many cols (combinatorial)
        return None
    cands = {c: list(dict.fromkeys(_candidate_values(coltypes.get(c, "text"), enums) + _expr_consts(expr))) for c in cols}
    combos = [dict(zip(cols, p)) for p in itertools.product(*[cands[c] for c in cols])] if cols else [{}]
    if len(combos) > 96:
        combos = combos[:96]
    sessions = _candidate_sessions(cpaths)
    parents, base_row = _mock_valid_row(schema, table, fkmap, colsmap, enums, checks, relchecks, compfks, conn)
    def _pid(sub, claimset):
        base = {"role": "authenticated"}
        if sub: base["sub"] = sub
        for keys, val in claimset: _set_claim(base, keys, val)
        return [f"SELECT set_config('request.jwt.claims', {_qlit(json.dumps(base))}, true)", "SET LOCAL ROLE authenticated"]
    sat = fal = None; budget = 220
    for (sub, claimset) in sessions:
        pid = _pid(sub, claimset)
        for combo in combos:
            if budget <= 0: break
            budget -= 1
            rr = dict(base_row)
            for c, v in combo.items(): rr[c] = _wv_lit(coltypes.get(c, "text"), v)
            ins = f"INSERT INTO {q}({', '.join(_qi(c) for c in rr)}) VALUES ({', '.join(rr.values())})"
            o = _probe(conn, [f"DELETE FROM {q}"] + parents + [ins], pid, "read", f"SELECT count(*) FROM {q}")
            if o[2] or o[0] != "count":
                continue
            if o[1] >= 1 and sat is None: sat = (sub, claimset, combo)
            elif o[1] == 0 and fal is None: fal = (sub, claimset, combo)
            if sat and fal: break
        if sat and fal: break
    if not (sat and fal):
        return None
    def _ctx(sub, claimset, combo):
        wctx = _wv_ctx(); wctx["sub"] = sub
        wctx["claims"].extend(claimset)
        for c, v in combo.items(): wctx["row"][c] = v
        return wctx
    return (_ctx(*sat), _ctx(*fal))


def solve_emit(ctx, baker, cmd, node=None):
    """General fallback: derive a witness for an ARBITRARY predicate, VERIFY it against the DB, and
    bake the observed grant/deny pair. With `node` given, solve THAT one predicate (per-min-term
    fallback for an unhandled branch, BL-1); otherwise iterate the table's permissive policies (the
    all-NT case). Skips opaque-fn tables (mock owns those). An unconfirmed witness bakes nothing -> NT."""
    conn, schema, table, q = ctx.conn, ctx.schema, ctx.table, ctx.q
    coltypes, enums, udfs = ctx.coltypes, ctx.enums, ctx.udfs
    fkmap, colsmap, checks, relchecks, compfks = ctx.fkmap, ctx.colsmap, ctx.checks, ctx.relchecks, ctx.compfks
    body, n, reseed, desc = ctx.body, ctx.n, ctx.reseed, ctx.desc
    _upd_val, upd_col = ctx.upd_val, ctx.upd_col
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
        if not plan or plan[0] is None or plan[1] is None:   # no specific-leaf witness ...
            plan = _construct_witness(ctx, expr_node)        # ... BL-6 floor: DB-oracle search over a single column ...
        if not plan or plan[0] is None or plan[1] is None:
            plan = _search_witness(ctx, expr_node)           # ... BL-11: joint search over (session x multi-column) candidates
        if not plan or plan[0] is None or plan[1] is None:   # need BOTH a true and a false witness for a grant/deny pair
            continue
        sat, fal = plan
        def ctx_sql(wctx):
            base = {"role": wctx.get("role", "authenticated")}
            if wctx.get("sub"): base["sub"] = wctx["sub"]
            for keys, val in wctx["claims"]:
                _set_claim(base, keys, val)
            rowcols = {cc: _wv_lit(coltypes.get(cc, "text"), vv) for cc, vv in wctx["row"].items()}
            aux = []
            for a in wctx["aux"]:
                _ensure_table_loaded(conn, a["table"], fkmap, colsmap)   # solver-discovered table (see seeding)
                aux += _aux_row_stmts(conn, a, fkmap, colsmap, enums)
            return json.dumps(base), [f"SELECT set_config('{k}', '{v}', true)" for k, v in wctx["guc"].items()], rowcols, aux
        s_claims, s_gucs, s_row, s_aux = ctx_sql(sat)
        f_claims, f_gucs, f_row, f_aux = ctx_sql(fal)
        parents, base_row = _mock_valid_row(schema, table, fkmap, colsmap, enums, checks, relchecks, compfks, conn)
        def rowins(over):
            rr = dict(base_row); rr.update(over)
            if not rr:                              # every column has a default -> DEFAULT VALUES (not broken `t() VALUES ()`)
                return f"INSERT INTO {q} DEFAULT VALUES"
            return f"INSERT INTO {q}({', '.join(_qi(c) for c in rr)}) VALUES ({', '.join(rr.values())})"
        def idsql(claims, gucs):
            return list(gucs) + [f"SELECT set_config('request.jwt.claims', {_qlit(claims)}, true)", "SET LOCAL ROLE authenticated"]
        if cmd == "SELECT":
            arr_t = [f"DELETE FROM {q}"] + parents + s_aux + [rowins(s_row)]
            arr_f = [f"DELETE FROM {q}"] + parents + f_aux + [rowins(f_row)]
            ot = _probe(conn, arr_t, idsql(s_claims, s_gucs), "read", f"SELECT count(*) FROM {q}")
            of = _probe(conn, arr_f, idsql(f_claims, f_gucs), "read", f"SELECT count(*) FROM {q}")
            if ot[2] or of[2] or not (ot[0] == "count" and ot[1] >= 1 and of[0] == "count" and of[1] == 0):
                continue   # DB didn't confirm the witness (or precondition unreliable) -> try the next policy, else stay NT
            ctx.observations.append(Observation(cmd="SELECT", ident="authorized", exp=True))
            n[0] += 1
            body.append("RESET ROLE;"); body.extend(s + ";" for s in arr_t); body.extend(s + ";" for s in idsql(s_claims, s_gucs))
            body.append(f"SELECT is( (SELECT count(*) FROM {q})::int, {ot[1]}, {desc('SELECT: authenticated, authorized sees its row(s) [solver]')} );")
            body.append("RESET ROLE;")
            ctx.observations.append(Observation(cmd="SELECT", ident="other", exp=False))
            n[0] += 1
            body.append("RESET ROLE;"); body.extend(s + ";" for s in arr_f); body.extend(s + ";" for s in idsql(f_claims, f_gucs))
            body.append(f"SELECT is( (SELECT count(*) FROM {q})::int, 0, {desc('SELECT: authenticated, not authorized sees nothing [solver]')} );")
            body.append("RESET ROLE;")
            oa = _probe(conn, arr_t, ["SELECT set_config('request.jwt.claims', '', true)", "SET LOCAL ROLE anon"], "read", f"SELECT count(*) FROM {q}")
            if not oa[2]:   # also probe anon so the matrix is complete (no stray '– not tested' cell)
                ctx.observations.append(Observation(cmd="SELECT", ident="anon", exp=(oa[0] == "count" and oa[1] >= 1)))
                n[0] += 1
                body.append("RESET ROLE;"); body.extend(s + ";" for s in arr_t)
                body.append("SELECT set_config('request.jwt.claims', '', true);"); body.append("SET LOCAL ROLE anon;")
                body.append(f"SELECT is( (SELECT count(*) FROM {q})::int, {oa[1]}, {desc('SELECT: anon sees ' + str(oa[1]) + ' row(s) [solver]')} );" if oa[0] == "count"
                            else f"SELECT throws_ok( $$ SELECT 1 FROM {q} $$, '{oa[1]}', NULL, {desc('SELECT: anon denied (' + oa[1] + ') [solver]')} );")
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
                act_t = act_f = f"UPDATE {q} SET {_qi(upd_col[0])}={_upd_val(upd_col[0], upd_col[1])}"
            else:
                act_t = act_f = f"DELETE FROM {q}"
            arr_t = [f"DELETE FROM {q}"] + parents + s_aux + [rowins(s_row)]
            arr_f = [f"DELETE FROM {q}"] + parents + f_aux + [rowins(f_row)]
        ot = _probe(conn, arr_t, idsql(s_claims, s_gucs), "write", act_t)
        of = _probe(conn, arr_f, idsql(f_claims, f_gucs), "write", act_f)
        if ot[2] or of[2] or not ((ot[0] == "rows" and ot[1] >= 1) and (of[0] == "err" or (of[0] == "rows" and of[1] == 0))):
            continue
        ctx.observations.append(Observation(cmd=cmd, ident="authorized", exp=True))
        n[0] += 1
        body.append("RESET ROLE;"); body.extend(s + ";" for s in arr_t); body.extend(s + ";" for s in idsql(s_claims, s_gucs))
        body.append(f"SELECT {'lives_ok' if cmd == 'INSERT' else 'isnt_empty'}( $$ {act_t}{'' if cmd == 'INSERT' else ' RETURNING 1'} $$, {desc(cmd + ': authenticated, authorized may act [solver]')} );")
        body.append("RESET ROLE;"); body.append(reseed)
        ctx.observations.append(Observation(cmd=cmd, ident="other", exp=False))
        n[0] += 1
        body.append("RESET ROLE;"); body.extend(s + ";" for s in arr_f); body.extend(s + ";" for s in idsql(f_claims, f_gucs))
        if of[0] == "err":
            body.append(f"SELECT throws_ok( $$ {act_f} $$, '{of[1]}', NULL, {desc(cmd + ': authenticated, not authorized denied (' + of[1] + ') [solver]')} );")
        else:
            body.append(f"SELECT is_empty( $$ {act_f} RETURNING 1 $$, {desc(cmd + ': authenticated, not authorized affects 0 rows [solver]')} );")
        body.append("RESET ROLE;"); body.append(reseed)
        oa = _probe(conn, arr_t, ["SELECT set_config('request.jwt.claims', '', true)", "SET LOCAL ROLE anon"], "write", act_t)
        if not oa[2]:   # also probe anon so the matrix is complete (no stray '– not tested' cell)
            ctx.observations.append(Observation(cmd=cmd, ident="anon", exp=(oa[0] == "rows" and oa[1] >= 1)))
            n[0] += 1
            body.append("RESET ROLE;"); body.extend(s + ";" for s in arr_t)
            body.append("SELECT set_config('request.jwt.claims', '', true);"); body.append("SET LOCAL ROLE anon;")
            if oa[0] == "err":
                body.append(f"SELECT throws_ok( $$ {act_t} $$, '{oa[1]}', NULL, {desc(cmd + ': anon denied (' + oa[1] + ') [solver]')} );")
            elif oa[0] == "rows" and oa[1] >= 1:
                body.append(f"SELECT isnt_empty( $$ {act_t} RETURNING 1 $$, {desc(cmd + ': anon CAN act (policy permits anon) - REVIEW [solver]')} );")
            else:
                body.append(f"SELECT is_empty( $$ {act_t} RETURNING 1 $$, {desc(cmd + ': anon affects 0 rows [solver]')} );")
            body.append("RESET ROLE;"); body.append(reseed)
        return True
    return False


def run(ctx, baker, cmd):
    if ctx.classes:   # a classified branch owns this command; these strategies serve the unclassified case
        return PASS
    if solve_emit(ctx, baker, cmd):                            # general witness solver (DB-verified)
        return HANDLED
    return PASS
