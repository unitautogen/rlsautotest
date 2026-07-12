# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""Relational-state strategy (BL-12): a policy gated on the STATE of the tables it reads
(a COUNT/aggregate threshold) — seed candidate cardinalities and let Postgres evaluate."""
from __future__ import annotations
import json

from ..astutil import _expr_consts, _qlit, _where
from ..probe import _probe
from ..seeding import _aux_row_stmts, _ensure_table_loaded, _mock_valid_row
from ..witness import _WV_UID, _subquery_tables, _wv_lit
from ..structs import Observation
from .base import HANDLED, PASS


def relstate_emit(ctx, baker, cmd):
    """BL-12 RELATIONAL-STATE DB-oracle floor: a policy gated on the STATE of the tables it reads (a
    COUNT/aggregate threshold, a multi-row condition) is not a fixed shape. Find the aux tables the
    policy's subqueries read, SEED A CANDIDATE NUMBER of matching rows (cardinalities taken from the
    predicate's own integer constants + small defaults), and let Postgres evaluate the REAL aggregate:
    the cardinality that makes the gated row visible is the witness, one that hides it is the falsifier.
    The DB computes the count/sum, so a brand-new aggregate gate works with ZERO per-operator code.
    Probe-and-baked (sound) + budget-capped -> honest NT past the bound. SELECT only (the common case)."""
    conn, schema, table, q = ctx.conn, ctx.schema, ctx.table, ctx.q
    coltypes, enums = ctx.coltypes, ctx.enums
    fkmap, colsmap, checks, relchecks, compfks = ctx.fkmap, ctx.colsmap, ctx.checks, ctx.relchecks, ctx.compfks
    body, n, reseed, desc = ctx.body, ctx.n, ctx.reseed, ctx.desc
    if cmd != "SELECT":
        return False
    _rc = conn.cursor()
    _rc.execute("SELECT qual FROM pg_policies WHERE schemaname=%s AND tablename=%s AND cmd IN ('SELECT','ALL') AND permissive='PERMISSIVE'", (schema, table))
    for (qual,) in _rc.fetchall():
        node = _where(qual) if qual else None
        if node is None:
            continue
        subs = _subquery_tables(node)
        if not subs or len(subs) > 2:               # nothing to vary, or too many aux tables (combinatorial)
            continue
        ints = sorted({int(c) for c in _expr_consts(node) if str(c).lstrip("-").isdigit()})
        Kc = [k for k in sorted(set([0, 1, 2] + ints + [i + 1 for i in ints] + [max(0, i - 1) for i in ints])) if 0 <= k <= 12][:8]
        parents, base_row = _mock_valid_row(schema, table, fkmap, colsmap, enums, checks, relchecks, compfks, conn)
        pid = [f"SELECT set_config('request.jwt.claims', {_qlit(json.dumps({'sub': _WV_UID, 'role': 'authenticated'}))}, true)", "SET LOCAL ROLE authenticated"]
        grow = {}
        for s in subs:
            for (_mc, gcol) in s["corr"]: grow[gcol] = s["scope"]
        def aux_seed(K):                            # DELETE each aux table, then seed K matching rows
            out = []
            for s in subs:
                _ensure_table_loaded(conn, s["mtable"], fkmap, colsmap)   # solver-discovered table (see seeding)
                out.append(f"DELETE FROM {s['mtable']}")
                cols = {}
                if s["uid"]: cols[s["uid"]] = _WV_UID
                for (mcol, _g) in s["corr"]: cols[mcol] = s["scope"]
                cols.update(s["extras"])
                for nc in s["num"]: cols[nc] = "1000000"
                for _ in range(K):
                    out += _aux_row_stmts(conn, {"table": s["mtable"], "cols": cols}, fkmap, colsmap, enums)
            return out
        def gated_ins():
            rr = dict(base_row)
            for c, v in grow.items(): rr[c] = _wv_lit(coltypes.get(c, "text"), v)
            if not rr:                              # every column has a default (no required cols) -> DEFAULT VALUES
                return f"INSERT INTO {q} DEFAULT VALUES"
            return f"INSERT INTO {q}({', '.join(rr)}) VALUES ({', '.join(rr.values())})"
        satK = falK = satN = None
        for K in Kc:
            o = _probe(conn, [f"DELETE FROM {q}"] + parents + aux_seed(K) + [gated_ins()], pid, "read", f"SELECT count(*) FROM {q}")
            if o[2] or o[0] != "count":
                continue
            if o[1] >= 1 and satK is None: satK, satN = K, o[1]
            elif o[1] == 0 and falK is None: falK = K
            if satK is not None and falK is not None:
                break
        if satK is None or falK is None:
            continue
        def bake(K, who, cnt, role, ident):
            ctx.observations.append(Observation(cmd="SELECT", ident=ident, exp=(cnt >= 1)))
            n[0] += 1
            body.append("RESET ROLE;")
            body.extend(s + ";" for s in ([f"DELETE FROM {q}"] + parents + aux_seed(K) + [gated_ins()]))
            if role == "anon":
                body.extend(["SELECT set_config('request.jwt.claims', '', true);", "SET LOCAL ROLE anon;"])
            else:
                body.extend(s + ";" for s in pid)
            body.append(f"SELECT is( (SELECT count(*) FROM {q})::int, {cnt}, {desc('SELECT: ' + who + ' [relstate]')} );")
            body.append("RESET ROLE;")
        bake(satK, f"authenticated, authorized (relstate: {satK} row(s)) sees its row", satN, "authenticated", "authorized")
        bake(falK, f"authenticated, not authorized (relstate: {falK} row(s)) sees nothing", 0, "authenticated", "other")
        _oa = _probe(conn, [f"DELETE FROM {q}"] + parents + aux_seed(satK) + [gated_ins()], ["SELECT set_config('request.jwt.claims', '', true)", "SET LOCAL ROLE anon"], "read", f"SELECT count(*) FROM {q}")
        if not _oa[2] and _oa[0] == "count":
            bake(satK, f"anon (relstate) sees {_oa[1]} row(s)", _oa[1], "anon", "anon")
        body.append(reseed)
        return True
    return False


def run(ctx, baker, cmd):
    if ctx.classes:   # a classified branch owns this command; these strategies serve the unclassified case
        return PASS
    if relstate_emit(ctx, baker, cmd):                         # BL-12: relational-state (cardinality/aggregate) DB-oracle floor
        return HANDLED
    return PASS
