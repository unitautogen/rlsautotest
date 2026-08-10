# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""Relational-state strategy (BL-12): a policy gated on the STATE of the tables it reads
(a COUNT/aggregate threshold) — seed candidate cardinalities and let Postgres evaluate."""
from __future__ import annotations
import json

from ..astutil import _expr_consts, _qi, _qlit, _where
from ..atoms import _expand_udf_calls
from ..probe import _probe
from ..seeding import _aux_row_stmts, _ensure_table_loaded, _mock_valid_row
from ..witness import _WV_UID, _subquery_tables, _wv_lit
from ..structs import Observation
from .base import HANDLED, PASS


def relstate_emit(ctx, baker, cmd, node=None):
    """BL-12 RELATIONAL-STATE DB-oracle floor: a policy gated on the STATE of the tables it reads (a
    COUNT/aggregate threshold, a multi-row condition) is not a fixed shape. Find the aux tables the
    policy's subqueries read, SEED A CANDIDATE NUMBER of matching rows (cardinalities taken from the
    predicate's own integer constants + small defaults), and let Postgres evaluate the REAL aggregate:
    the cardinality that makes the gated row visible is the witness, one that hides it is the falsifier.
    The DB computes the count/sum, so a brand-new aggregate gate works with ZERO per-operator code.
    Probe-and-baked (sound) + budget-capped -> honest NT past the bound. SELECT only (the common case).
    With `node` given, floor THAT one predicate (a per-branch rescue for an unhandled min-term); otherwise
    iterate the table's permissive SELECT policies -- ALL of them, accumulating (no first-win): each policy
    that yields a confirmed witness/falsifier pair gets its own battery, tagged ' [branch N]' past the first."""
    conn, schema, table, q = ctx.conn, ctx.schema, ctx.table, ctx.q
    coltypes, enums = ctx.coltypes, ctx.enums
    fkmap, colsmap, checks, relchecks, compfks = ctx.fkmap, ctx.colsmap, ctx.checks, ctx.relchecks, ctx.compfks
    body, n, reseed, desc = ctx.body, ctx.n, ctx.reseed, ctx.desc
    if cmd != "SELECT":
        # MB-4: the write-direction sibling floor. Kept in its own function so the SELECT path below
        # stays byte-identical; a schema with no write-command relational-state policy is unaffected.
        return _relstate_write(ctx, baker, cmd, node) if cmd in ("INSERT", "UPDATE", "DELETE") else False
    if node is not None:
        _cands = [node]
    else:
        _rc = conn.cursor()
        _rc.execute("SELECT qual FROM pg_policies WHERE schemaname=%s AND tablename=%s AND cmd IN ('SELECT','ALL') AND permissive='PERMISSIVE'", (schema, table))
        _cands = []
        for (qual,) in _rc.fetchall():
            _nd = _where(qual) if qual else None
            if _nd is not None and ctx.udfs and _expand_udf_calls is not None:
                from .solver import _calls_udf
                if _calls_udf(_nd, ctx.udfs):
                    _nd = _expand_udf_calls(_nd, conn.cursor())   # witness hints; the probe runs the REAL fn
            _cands.append(_nd)
    _emitted = 0
    for node in _cands:
        if node is None:
            continue
        _tag = '' if _emitted == 0 else f' [branch {_emitted + 1}]'   # first battery keeps the historical labels
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
            return f"INSERT INTO {q}({', '.join(_qi(c) for c in rr)}) VALUES ({', '.join(rr.values())})"
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
            body.append(f"SELECT is( (SELECT count(*) FROM {q})::int, {cnt}, {desc('SELECT: ' + who + ' [relstate]' + _tag)} );")
            body.append("RESET ROLE;")
        bake(satK, f"authenticated, authorized (relstate: {satK} row(s)) sees its row", satN, "authenticated", "authorized")
        bake(falK, f"authenticated, not authorized (relstate: {falK} row(s)) sees nothing", 0, "authenticated", "other")
        _oa = _probe(conn, [f"DELETE FROM {q}"] + parents + aux_seed(satK) + [gated_ins()], ["SELECT set_config('request.jwt.claims', '', true)", "SET LOCAL ROLE anon"], "read", f"SELECT count(*) FROM {q}")
        if not _oa[2] and _oa[0] == "count":
            bake(satK, f"anon (relstate) sees {_oa[1]} row(s)", _oa[1], "anon", "anon")
        elif not _oa[2] and _oa[0] == "err" and _oa[1] == "42501":
            # anon holds no SELECT grant on this table: SQLSTATE 42501 fires at the GRANT check,
            # BEFORE any policy row filtering, so the denial is provable even though the policy
            # branch itself is unclassified. Probe-and-bake honest: we observed the 42501 against
            # the live DB under the same arrange, so we bake exactly that as a throws_ok denial
            # (mirrors the write batteries' implicit-deny tests) instead of leaving the cell '-'.
            ctx.observations.append(Observation(cmd="SELECT", ident="anon", exp=False))
            n[0] += 1
            body.append("RESET ROLE;")
            body.extend(s + ";" for s in ([f"DELETE FROM {q}"] + parents + aux_seed(satK) + [gated_ins()]))
            body.extend(["SELECT set_config('request.jwt.claims', '', true);", "SET LOCAL ROLE anon;"])
            body.append(f"SELECT throws_ok( $$ SELECT count(*) FROM {q} $$, '42501', NULL, {desc('SELECT: anon, no SELECT grant denied (42501) [relstate]' + _tag)} );")
            body.append("RESET ROLE;")
        body.append(reseed)
        _emitted += 1
    return _emitted > 0


def _relstate_write(ctx, baker, cmd, node=None):
    """MB-4: the write-direction (INSERT/UPDATE/DELETE) sibling of the relational-state SELECT floor.
    A FOR ALL / write policy gated on the STATE of the tables it reads (a COUNT/aggregate threshold)
    gates writes the same way -- so seed a CANDIDATE NUMBER of matching rows, ACT, and observe: the
    cardinality that lets the write LAND is the witness, one that BLOCKS it is the falsifier. INSERT is
    gated by WITH CHECK (USING fallback), UPDATE/DELETE by USING. The DB evaluates the real aggregate,
    so a brand-new gate needs zero per-operator code. Probe-and-baked (only observed outcomes emitted)
    + budget-capped -> honest NT past the bound; the observed grant/deny pair is baked via write_assert."""
    conn, schema, table, q = ctx.conn, ctx.schema, ctx.table, ctx.q
    coltypes, enums = ctx.coltypes, ctx.enums
    fkmap, colsmap, checks, relchecks, compfks = ctx.fkmap, ctx.colsmap, ctx.checks, ctx.relchecks, ctx.compfks
    body, n, reseed, desc = ctx.body, ctx.n, ctx.reseed, ctx.desc
    upd_col = ctx.upd_col
    if cmd == "UPDATE" and not upd_col:
        return False                                # no neutral column to SET -> honest NT (avoid col=col SELECT-perm noise)
    if node is not None:
        _cands = [node]
    else:
        _rc = conn.cursor()
        _order = "with_check, qual" if cmd == "INSERT" else "qual, with_check"   # INSERT gated by WITH CHECK (USING fallback)
        _rc.execute(f"SELECT {_order} FROM pg_policies WHERE schemaname=%s AND tablename=%s AND cmd IN (%s,'ALL') AND permissive='PERMISSIVE'", (schema, table, cmd))
        _cands = []
        for (a, b) in _rc.fetchall():
            _pe = a if a is not None else b
            _nd = _where(_pe) if _pe else None
            if _nd is not None and ctx.udfs:
                from .solver import _calls_udf
                if _calls_udf(_nd, ctx.udfs):
                    _nd = _expand_udf_calls(_nd, conn.cursor())   # witness hints; the probe runs the REAL fn
            if _nd is not None:
                _cands.append(_nd)
    _emitted = 0
    for node in _cands:
        if node is None:
            continue
        _tag = '' if _emitted == 0 else f' [branch {_emitted + 1}]'
        subs = _subquery_tables(node)
        if not subs or len(subs) > 2:               # nothing to vary, or too many aux tables (combinatorial)
            continue
        ints = sorted({int(c) for c in _expr_consts(node) if str(c).lstrip("-").isdigit()})
        Kc = [k for k in sorted(set([0, 1, 2] + ints + [i + 1 for i in ints] + [max(0, i - 1) for i in ints])) if 0 <= k <= 12][:8]
        parents, base_row = _mock_valid_row(schema, table, fkmap, colsmap, enums, checks, relchecks, compfks, conn)
        pid = [f"SELECT set_config('request.jwt.claims', {_qlit(json.dumps({'sub': _WV_UID, 'role': 'authenticated'}))}, true)", "SET LOCAL ROLE authenticated"]
        anonpid = ["SELECT set_config('request.jwt.claims', '', true)", "SET LOCAL ROLE anon"]
        grow = {}
        for s in subs:
            for (_mc, gcol) in s["corr"]: grow[gcol] = s["scope"]
        def aux_seed(K):
            out = []
            for s in subs:
                _ensure_table_loaded(conn, s["mtable"], fkmap, colsmap)
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
            if not rr:
                return f"INSERT INTO {q} DEFAULT VALUES"
            return f"INSERT INTO {q}({', '.join(_qi(c) for c in rr)}) VALUES ({', '.join(rr.values())})"
        if cmd == "INSERT":
            act = gated_ins()
            def arr(K): return [f"DELETE FROM {q}"] + parents + aux_seed(K)            # the insert IS the action; no pre-seeded row
        elif cmd == "UPDATE":
            act = f"UPDATE {q} SET {_qi(upd_col[0])}={ctx.upd_val(upd_col[0], upd_col[1])}"
            def arr(K): return [f"DELETE FROM {q}"] + parents + aux_seed(K) + [gated_ins()]
        else:  # DELETE
            act = f"DELETE FROM {q}"
            def arr(K): return [f"DELETE FROM {q}"] + parents + aux_seed(K) + [gated_ins()]
        satK = satO = falK = falO = None
        for K in Kc:
            o = _probe(conn, arr(K), pid, "write", act)
            if o[2]:
                continue
            if o[0] == "rows" and o[1] >= 1 and satK is None: satK, satO = K, o
            elif ((o[0] == "err" and o[1] == "42501") or (o[0] == "rows" and o[1] == 0)) and falK is None: falK, falO = K, o
            if satK is not None and falK is not None:
                break
        if satK is None or falK is None:
            continue
        def bake(K, o, who, ident, role="authenticated"):
            n[0] += 1
            body.append("RESET ROLE;")
            body.extend(s + ";" for s in arr(K))
            if role == "anon":
                body.extend(["SELECT set_config('request.jwt.claims', '', true);", "SET LOCAL ROLE anon;"])
            else:
                body.extend(s + ";" for s in pid)
            body.append(baker.write_assert(o, cmd, act, who, ident=ident))
            body.append("RESET ROLE;")
        bake(satK, satO, f"authenticated, authorized (relstate: {satK} row(s)) [relstate]{_tag}", "authorized")
        bake(falK, falO, f"authenticated, not authorized (relstate: {falK} row(s)) [relstate]{_tag}", "other")
        _oa = _probe(conn, arr(satK), anonpid, "write", act)
        if not _oa[2]:
            bake(satK, _oa, f"anon (relstate) [relstate]{_tag}", "anon", role="anon")
        body.append(reseed)
        _emitted += 1
    return _emitted > 0


def run(ctx, baker, cmd):
    if ctx.classes:   # a classified branch owns this command; these strategies serve the unclassified case
        return PASS
    if relstate_emit(ctx, baker, cmd):                         # BL-12: relational-state (cardinality/aggregate) DB-oracle floor
        return HANDLED
    return PASS
