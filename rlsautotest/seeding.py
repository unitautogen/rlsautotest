# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""Seed planning and row synthesis (probe-and-repair) for identity classes and solver witnesses.

Split out of the original single-module cli.py; behavior-preserving.
"""
from __future__ import annotations
import json
import re
import psycopg
from .astutil import _split_statements, _sq
from .values import FOREIGN, FUTURE_EXP, INS, RIVAL_ORG, RIVAL_SUB, _bump_lit, _castable_lit, _fill_lit, _nonempty_array_lit, _pick_lit, _verified_lit
from .catalog import _FK_SQL, _check_bool_udfs, _columns, _constraint_meta, _fk_by_name
from .atoms import _set_claim


def _aux_row_stmts(conn, a, fkmap, colsmap, enums):
    """INSERT statements for ONE witness aux row {table, cols}. Composite-FK tables (F10) route
    through the probe-and-repair synthesizer, which reacts to the real 23503 and seeds the composite
    parent tuple — _seed_one only walks single-column FK parents. Plain tables keep the exact
    _seed_one output (byte-identical)."""
    fixed = {k: f"'{v}'" for k, v in a["cols"].items()}
    if conn is not None:
        s2, t2 = _sq(a["table"])
        try:
            comp = _constraint_meta(conn.cursor(), s2, t2)[3]
        except Exception:
            comp = []
        if comp:
            recipe, srow, setup = _synthesize_row(conn, s2, t2, fixed=fixed)
            if recipe is not None and srow:
                return (setup or []) + [f"INSERT INTO {a['table']}({', '.join(srow)}) VALUES ({', '.join(srow.values())})"]
    return _seed_one(a["table"], fixed, fkmap, colsmap, enums, conn=conn)


def _ensure_table_loaded(conn, tbl, fkmap, colsmap):
    """Load columns + FKs for a table the SOLVER discovered at witness time (a policy-subquery table
    the classifier rejected, so _load_ctx never loaded it). Without this _seed_one cannot know the
    table's NOT NULL shape and the aux row fails to seed -> the witness never confirms -> NT."""
    if tbl in colsmap or conn is None:
        return
    cur = conn.cursor()
    s2, t2 = _sq(tbl)
    colsmap[tbl] = _columns(cur, s2, t2)
    cur.execute(_FK_SQL, (s2, t2))
    fkmap[tbl] = {col: (f"{ps}.{pt}", pc) for (col, ps, pt, pc) in cur.fetchall()}


def _seed_one(table_fqn, fixed, fkmap, colsmap, enums, conn=None):
    """INSERT stmts (FK parents first, ON CONFLICT DO NOTHING) for one row of table_fqn: `fixed` {col: literal}
    plus required NOT-NULL/no-default columns filled with type-valid values. With `conn`, every guessed
    literal is DB-verified (F3): known types keep their exact literal, an exotic type gets an
    oracle-repaired castable value instead of a doomed 'x'."""
    stmts = []
    def fill(t): return _verified_lit(conn, t, _fill_lit(t, enums))
    def pick(t): return _verified_lit(conn, t, _pick_lit(t, enums))
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



def _unq(v):
    return v[1:-1] if isinstance(v, str) and v.startswith("'") and v.endswith("'") else v



def _wrap_seed(block):
    """P2b: wrap each statement of an ARRANGE/seed block in public._rlsa_try(...) so a failing seed (a genuinely
    un-seedable table) is swallowed in its own subtransaction rather than aborting the whole emitted pgTAP file
    under pg_prove / `supabase test db`. The table then stays empty and the baked UNRELIABLE assertion runs and
    prints a clean `not ok … UNRELIABLE` line. Dollar-quote-aware split (keeps CREATE FUNCTION $$…$$ bodies
    intact); the tag is space-padded so an inner `$$` can't run into the outer tag. NOTE: only the EMITTED
    artifact is wrapped — the engine's own live probe uses the raw, unwrapped seed (run before _rlsa_try exists)."""
    out = []
    for s in _split_statements(block):
        st = s.strip().rstrip(";").strip()
        if st:
            out.append(f"SELECT public._rlsa_try($rlsa_seed$ {st} $rlsa_seed$);")
    return "\n".join(out)



def _seed_plan(schema, table, per, cmds, cols, fkmap, colsmap, enums, unique_cols, checks=None, cuniques=None, relchecks=None, compfks=None, conn=None):
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

    # F3: DB-verify every guessed literal (_verified_lit). A type the static tables know keeps its exact
    # literal (emitted SQL unchanged); an exotic column type (inet, bytea, DOMAIN, citext, range, custom)
    # is oracle-repaired to a castable value instead of a doomed 'x' -> the seed INSERT stops dying at the
    # cast and the classified path (and the UPDATE-probe SET, which uses this same fill) can test it. Base
    # guess tables are shared via values._fill_lit / _pick_lit (same tables as _seed_one / _mock_valid_row).
    def fill(t): return _verified_lit(conn, t, _fill_lit(t, enums))
    def pick(t): return _verified_lit(conn, t, _pick_lit(t, enums))

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

    def _anc_tables(t0):                                 # t0 + its transitive FK-parent tables
        seen2, st = set(), [t0]
        while st:
            t = st.pop()
            if t in seen2: continue
            seen2.add(t)
            for (pt, _pc) in fkmap.get(t, {}).values(): st.append(pt)
        return seen2
    # SEEDING ORDER is topological, not a fixed "aux always first" heuristic. Decide it by the FK dependency
    # between the table under test (q) and its aux/scope tables (deeper FK parents are seeded inline by
    # anc()/ensure() with ON CONFLICT, so this 2-block order is the full topological order for the shapes that
    # occur):
    #   - q_scope_parent (q is an FK-ANCESTOR of an aux table, e.g. orgs with memberships.org_id -> orgs.id,
    #     or an rbac/scalar-lookup table that points back at q): seed q's MAIN rows FIRST so the aux FK resolves
    #     against the real row, THEN the aux rows. (Previously this was patched with an idempotency hack on the
    #     main insert; ordering removes the self-collision at the source. ON CONFLICT is kept as a belt-and-
    #     suspenders no-op.)
    #   - otherwise: seed AUX first (q may FK-reference the aux/scope table — e.g. the membership-linking
    #     column must exist before the main row's generic FK fill would overwrite it), then the main rows.
    q_scope_parent = any(a.get("table") and a["table"] != q and q in _anc_tables(a["table"])
                         for c in all_h for a in c["aux"])
    for at in {a["table"] for c in all_h for a in c["aux"]}:
        stmts.append(f"  DELETE FROM {at};")
    def seed_aux():
        aux_seen = set()
        for c in all_h:
            for a in c["aux"]:
                ak = (a["table"], tuple(sorted(a["cols"].items())))
                if ak in aux_seen: continue
                aux_seen.add(ak)
                av = {k: f"'{val}'" for k, val in a["cols"].items()}
                v = row_values(a["table"], av); anc(v, a["table"]); stmts.append(insert(a["table"], v, conflict=True))
    def seed_main():
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
    if q_scope_parent:
        seed_main(); seed_aux()
    else:
        seed_aux(); seed_main()

    # ── rival tenant: the "authenticated, not authorized" negative control is a LEGITIMATE user of a
    #    DIFFERENT tenant (org B), not a no-tenant outsider — so a green block proves cross-tenant isolation
    #    (having tenancy != having A's tenancy), and a buggy policy like `org_id IS NOT NULL` is caught.
    rival_claims = {"sub": RIVAL_SUB, "role": "authenticated", "exp": FUTURE_EXP}
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



def _mock_valid_row(schema, table, fkmap, colsmap, enums, checks=None, relchecks=None, compfks=None, conn=None):
    """Build (fk_parent_insert_stmts, {col: literal}) for ONE valid row of schema.table.
    Used to seed the precondition for opaque-function-gated write tests (the mock path): when a
    table's only policies delegate to an opaque boolean fn, there's no 'handled' class and thus
    no base seed, so the engine has no row to INSERT/UPDATE/DELETE. This synthesizes one — FK
    parents seeded recursively (ON CONFLICT DO NOTHING), required (NOT NULL, no-default,
    non-identity) columns filled with type-valid literals."""
    q = f"{schema}.{table}"
    checks = checks or {}
    def _ck(tbl, col): return (checks.get(tbl) or {}).get(col)   # CHECK-satisfying literal, if any

    def _fill(t): return _verified_lit(conn, t, _fill_lit(t, enums))
    def _pick(t): return _verified_lit(conn, t, _pick_lit(t, enums))

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
        if nn and not hd: row[n] = _castable_lit(conn, t)
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
            row[col] = _castable_lit(conn, coltypes.get(col, "text"))
        elif ss == "23503" and cname:                               # FK (single or composite)
            fk = _fk_by_name(cur, cname)
            if not fk: return None, None, None
            for lc in fk["cols"]:
                if lc not in row or row[lc] == "NULL": row[lc] = _castable_lit(conn, coltypes.get(lc, "text"))
            ps, t2 = _sq(fk["parent"])
            prec, _pv, _ps = _synthesize_row(conn, ps, t2, fixed={pc: row[lc] for lc, pc in zip(fk["cols"], fk["pcols"])}, _depth=_depth + 1)
            if prec is None: return None, None, None
            parents.append(prec)
        elif ss == "23514" and cname:                               # CHECK
            new = [(s, o) for (s, o) in _check_bool_udfs(cur, cname) if s not in {m for m, _ in mocks}]
            if new:
                mocks += new                                        # CHECK delegates to a boolean UDF -> neutralize it for the insert
            else:
                # array-cardinality CHECK (cardinality(col) > 0 / array_length(col,1) >= N): the default/empty
                # array violates it -> supply a non-empty array for that column and retry.
                cur.execute("""SELECT pg_get_constraintdef(oid) FROM pg_constraint
                               WHERE conname=%s AND conrelid = format('%%I.%%I', %s::text, %s::text)::regclass""", (cname, schema, table))
                _cd = cur.fetchone()
                _m = re.search(r'(?:cardinality|array_length)\s*\(\s*"?([a-zA-Z_]\w*)"?', (_cd[0] if _cd else "") or "")
                _ac = _m.group(1) if _m else None
                if _ac and coltypes.get(_ac, "").endswith("[]") and row.get(_ac) is None:
                    row[_ac] = _nonempty_array_lit(coltypes[_ac])   # e.g. roles text[] -> '{x}'
                else:
                    return None, None, None                          # non-array / other non-function CHECK -> not repairable here
        elif ss == "23505" and cname:                               # UNIQUE -> vary a column
            cur.execute("SELECT array_agg(a.attname) FROM pg_constraint c JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=ANY(c.conkey) WHERE c.conname=%s", (cname,))
            ur = cur.fetchone(); tgt = next((u for u in (list(ur[0]) if ur and ur[0] else []) if u in row), None)
            if not tgt: return None, None, None
            salt[0] += 1; row[tgt] = _bump_lit(coltypes.get(tgt, "text"), salt[0])
        else:
            return None, None, None
    return None, None, None



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

