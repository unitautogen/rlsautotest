# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""Opaque-boolean-function wiring strategy: the policy delegates to fn(s) we can't reason
into, so MOCK them true/false and prove the policy wires to them (wiring proof — the
function's own logic stays unverified -> report footgun)."""
from __future__ import annotations
import re

from ..astutil import _names, _qi, _qlit, _t, _unwrap, _v, _where
from ..probe import _probe, _unrel_fail
from ..seeding import _mock_valid_row, _synthesize_row
from ..structs import Observation
from .base import AUGMENT, PASS


def _policy_fn_names(conn, schema, table):
    """Every function NAME called anywhere in this table's policy clauses, read from the parse
    trees (F6: no regex on SQL). Returns {(schema_or_None, name)} for qualified and bare calls."""
    cur = conn.cursor()
    cur.execute("SELECT qual, with_check FROM pg_policies WHERE schemaname=%s AND tablename=%s", (schema, table))
    called = set()
    def walk(n):
        if isinstance(n, dict):
            if _t(n) == "FuncCall":
                fn = _names(_v(n).get("funcname"))
                if fn:
                    called.add((fn.rsplit(".", 1)[0], fn.rsplit(".", 1)[1]) if "." in fn else (None, fn))
            for v in n.values(): walk(v)
        elif isinstance(n, list):
            for x in n: walk(x)
    for (q1, q2) in cur.fetchall():
        for e in (q1, q2):
            if not e:
                continue
            nd = _where(e)
            if nd is not None:
                walk(nd)
    return called


def _policy_bool_udfs(conn, schema, table):
    """User-defined boolean functions referenced by this table's policies — candidates to MOCK when the
    policy delegates the decision to an opaque function we can't drive via real inputs (RBAC etc.).
    Matches actual FuncCall nodes in the policy ASTs, so a function name that merely appears inside a
    string literal (or a quoted spelling the old text-regex mishandled) can no longer be mock-listed."""
    called = _policy_fn_names(conn, schema, table)
    if not called:
        return []
    cur = conn.cursor()
    cur.execute("""SELECT n.nspname, p.proname, pg_get_function_identity_arguments(p.oid), pg_get_functiondef(p.oid)
        FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_type t ON t.oid=p.prorettype
        WHERE t.typname='bool' AND n.nspname NOT IN ('pg_catalog','information_schema','auth')""")
    out = []
    for nsp, name, args, fdef in cur.fetchall():
        if (nsp, name) in called or (None, name) in called:   # qualified call, or a bare call resolved by search_path
            out.append({"name": name, "q": f'"{nsp}"."{name}"', "args": args, "def": fdef})
    return out


def _opaque_fn_sig(conn, node, allow_bool=False):
    """If `node` is a call to a NON-builtin user function (optionally wrapped in a `(SELECT fn() ...)`
    sublink), return its mock signature {q,args,rettype,def,name}; else None. By default boolean fns are
    excluded (the mock_emit wiring path owns those); pass allow_bool=True for the general force-mock fallback.
    Used to MOCK an opaque scalar fn that is COMPARED to a column (e.g. `realtime.topic() = room_topic`):
    we can't reason into the function, but we can replace it with a constant and seed the other side to
    match/mismatch — a wiring proof (the function's own logic stays unverified). Boolean fns are excluded
    here (the mock_emit wiring path owns those)."""
    n = node
    if _t(n) == "SubLink":
        sv = _v(n)
        if sv.get("subLinkType") != "EXPR_SUBLINK":
            return None
        tl = (sv.get("subselect") or {}).get("SelectStmt", {}).get("targetList", [])
        if not tl:
            return None
        n = tl[0].get("ResTarget", {}).get("val")
    n = _unwrap(n) if n else n
    if not n or _t(n) != "FuncCall":
        return None
    fn = _names(_v(n).get("funcname")); short = fn.split(".")[-1]
    if any(b in fn for b in ("auth.", "pg_catalog.")) or short in ("now", "current_setting", "uid", "jwt", "role"):
        return None   # context primitives are CONTROLLED (claims/GUC), not mocked
    nsp = fn.split(".")[0] if "." in fn else None
    cur = conn.cursor()
    if nsp:
        cur.execute("""SELECT n.nspname, p.proname, pg_get_function_identity_arguments(p.oid),
            format_type(p.prorettype,NULL), pg_get_functiondef(p.oid), t.typname
            FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_type t ON t.oid=p.prorettype
            WHERE n.nspname=%s AND p.proname=%s LIMIT 1""", (nsp, short))
    else:
        cur.execute("""SELECT n.nspname, p.proname, pg_get_function_identity_arguments(p.oid),
            format_type(p.prorettype,NULL), pg_get_functiondef(p.oid), t.typname
            FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_type t ON t.oid=p.prorettype
            WHERE p.proname=%s AND n.nspname NOT IN ('pg_catalog','information_schema','auth') LIMIT 1""", (short,))
    r = cur.fetchone()
    if not r:
        return None
    nspn, pn, args, rettype, fdef, typ = r
    if typ == "bool" and not allow_bool:
        return None   # boolean policy fns are wiring-tested by mock_emit, not the scalar `col = fn()` gate
    return {"q": f'"{nspn}"."{pn}"', "args": args, "rettype": rettype, "def": fdef, "name": pn}


def _mocklit(rettype, raw):
    """A SQL literal of `rettype` for a function-mock body (`SELECT <lit>`)."""
    rt = (rettype or "").lower()
    if rt in ("boolean", "bool"):
        return "true" if str(raw).lower() in ("true", "t", "1") else "false"
    if any(k in rt for k in ("int", "numeric", "real", "double", "decimal", "money", "serial")) and re.fullmatch(r"-?\d+(\.\d+)?", str(raw or "")):
        return str(raw)
    return "'" + str(raw).replace("'", "''") + "'::" + (rettype or "text")


def _ins_sql(q, row):
    """INSERT text for a synthesized row; an EMPTY row (every column defaultable) is valid SQL as
    DEFAULT VALUES — `INSERT INTO t() VALUES ()` is not (it silently killed the wiring precondition)."""
    if not row:
        return f"INSERT INTO {q} DEFAULT VALUES"
    return f"INSERT INTO {q}({', '.join(_qi(c) for c in row)}) VALUES ({', '.join(row.values())})"


def _mock_preflight(ctx):
    """Can the CONNECTION role actually CREATE OR REPLACE every policy UDF this battery mocks?
    Tested in the probe's own context (RESET ROLE, savepoint, rolled back) so the answer is exactly
    what the emitted battery would experience. Returns None, or the sqlstate of the first failure.
    Issue #2: without this, a permission failure was swallowed downstream and the degenerate
    (real-function) behavior was baked as the expected behavior — a false-passing suite."""
    cur = ctx.conn.cursor()
    try: cur.execute("RESET ROLE")
    except Exception: pass
    cur.execute("SAVEPOINT _rlsa_mockpre")
    err = None
    try:
        for u in ctx.udfs:
            cur.execute(f"CREATE OR REPLACE FUNCTION {u['q']}({u['args']}) RETURNS boolean LANGUAGE sql AS $$ SELECT true $$")
    except Exception as e:
        err = getattr(e, "sqlstate", None) or "XX000"
    finally:
        try: cur.execute("ROLLBACK TO SAVEPOINT _rlsa_mockpre"); cur.execute("RELEASE SAVEPOINT _rlsa_mockpre")
        except Exception: pass
    return err


def mock_emit(ctx, baker, cmd):
    """Opaque-function-gated command: prove the policy WIRES to the function, both directions.
    (Wiring proof — the function's own logic is out of scope / tested by the function engine.)"""
    conn, schema, table, q = ctx.conn, ctx.schema, ctx.table, ctx.q
    body, n, reseed, desc, NB = ctx.body, ctx.n, ctx.reseed, ctx.desc, ctx.NB
    udfs, geff, _upd_val, upd_col = ctx.udfs, ctx.geff, ctx.upd_val, ctx.upd_col
    total_rows, nobody_ins = ctx.total_rows, ctx.nobody_ins
    fkmap, colsmap, enums, checks, relchecks, compfks = ctx.fkmap, ctx.colsmap, ctx.enums, ctx.checks, ctx.relchecks, ctx.compfks
    def mock_one(val, assertion, write, preseed=None, ident=None, exp=True):
        """Replace every policy UDF with a constant `val` (FakeFunction), act, assert, restore, re-seed."""
        ctx.observations.append(Observation(cmd=cmd, ident=ident, exp=exp, mocked=True))
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
    if not udfs:
        return
    _pferr = _mock_preflight(ctx)
    if _pferr:
        # The mock cannot be installed by this connection role -> the wiring proof is impossible in this
        # environment. NEVER emit the battery (its observations would be artifacts): one loud, failing,
        # UNRELIABLE line per identity so the report shows ‼, the note names the cause, and CI gates.
        fns = ", ".join(u["q"] for u in udfs)
        reason = ("cannot CREATE OR REPLACE " + fns + " as the connection role -- mock wiring impossible in "
                  "this environment; connect as a role that owns the function/schema (Supabase: supabase_admin) "
                  "or run `rlsautotest doctor`")
        for _id, _who in (("authorized", "authenticated, authorized"), ("other", "authenticated, not authorized")):
            ctx.observations.append(Observation(cmd=cmd, ident=_id, kind="unreliable", mocked=True))
            n[0] += 1
            body.append(_unrel_fail(desc, cmd + ": " + _who + " [mocked; wiring]", ("err", _pferr, reason)))
        return
    if not geff("authenticated", cmd):
        # authenticated has NO grant for this command (e.g. a FOR ALL policy exists but only
        # SELECT/INSERT/DELETE were granted): a mock "authorized can" test would just hit 42501
        # (missing grant) and, since is_empty/isnt_empty don't trap it, abort the pgTAP file.
        # The DENIAL is the expected behavior, so record it as a REAL passing test under the
        # AUTHORIZED identity: even a fully policy-authorized user is blocked at the GRANT layer.
        # Probe first and bake ONLY an observed clean 42501 (anything else -> honest dash).
        sx = (ctx.deny_stmt or {}).get(cmd)
        if sx:
            pid = [f"SELECT set_config('request.jwt.claims', {_qlit(NB)}, true)", "SET LOCAL ROLE authenticated"]
            o = _probe(conn, [], pid, "read" if cmd == "SELECT" else "write", sx)
            if o[0] == "err" and o[1] == "42501" and not o[2]:
                ctx.observations.append(Observation(cmd=cmd, ident="authorized", exp=False))
                n[0] += 1
                body.append(f"SELECT set_config('request.jwt.claims', {_qlit(NB)}, true);")
                body.append("SET LOCAL ROLE authenticated;")
                body.append(f"SELECT throws_ok( $$ {sx} $$, '42501', NULL, {desc(cmd + ': authenticated, authorized has no ' + cmd + ' grant - denied as expected')} );")
                body.append("RESET ROLE;")
        return
    fns = ", ".join(u["name"] + "()" for u in udfs)
    # Need a valid row to act on. Prefer the probe-and-repair synthesizer (handles composite FK,
    # CHECK-delegated UDFs, etc. by reacting to real INSERT errors); fall back to the static builder,
    # then to the weak count. `recipe` makes a row exist (mocks restored); `setup` is the pre-insert
    # part (parent seeds + CHECK-UDF neutralizers, left active) for when we INSERT as the action.
    # Always try to build ONE clean row (synthesizer, else static builder), so the mock SELECT can
    # assert an exact count of 1 rather than trusting `total_rows` (which overcounts when a seed row
    # silently fails a composite FK / multi-col unique, e.g. rbac.member_permissions).
    recipe, srow, setup = _synthesize_row(conn, schema, table)
    parents, prow = ([], None)
    if recipe is None:
        parents, prow = _mock_valid_row(schema, table, fkmap, colsmap, enums, checks, relchecks, compfks, conn)
    def _exist_pre():   # statements that leave ONE valid row in q. We keep any CHECK-UDF mocks in `setup`
        # ACTIVE (not restored) through the action so an UPDATE that touches a CHECK'd column still passes;
        # the whole battery is wrapped in BEGIN..ROLLBACK so the real function is restored at the end.
        if recipe is not None: return [f"DELETE FROM {q}"] + setup + [_ins_sql(q, srow)]
        if prow is not None:    return [f"DELETE FROM {q}"] + parents + [_ins_sql(q, prow)]
        return None
    if cmd == "SELECT":
        pre = _exist_pre()
        if pre:    # seed ONE real row, prove read-visibility both ways: mock TRUE -> visible (1), FALSE -> hidden (0)
            mock_one("true",  f"SELECT is( (SELECT count(*) FROM {q})::int, 1, {desc('SELECT: authenticated, authorized when ' + fns + ' [mocked; wiring]')} );", True, preseed=pre, ident="authorized", exp=True)
            mock_one("false", f"SELECT is( (SELECT count(*) FROM {q})::int, 0, {desc('SELECT: authenticated, not authorized blocked when ' + fns + '=false [mocked; wiring]')} );", True, preseed=pre, ident="other", exp=False)
        else:      # couldn't synthesize a row -> weaker fallback, still sound
            mock_one("true",  f"SELECT is( (SELECT count(*) FROM {q})::int, {total_rows}, {desc('SELECT: authenticated, authorized when ' + fns + ' [mocked; wiring]')} );", False, ident="authorized", exp=True)
            mock_one("false", f"SELECT is( (SELECT count(*) FROM {q})::int, 0, {desc('SELECT: authenticated, not authorized blocked when ' + fns + '=false [mocked; wiring]')} );", False, ident="other", exp=False)
        return
    if cmd == "INSERT":
        icols = srow if recipe is not None else (nobody_ins or prow)
        # Clean the table first: without this the seeded row (from the prior reseed) can share the
        # insert-under-test's UNIQUE key (e.g. members' (group_id,user_id)) -> 23505, which would look
        # like a policy denial. Parents/CHECK-UDF neutralizers stay so the FKs still resolve.
        pre_ins = [f"DELETE FROM {q}"] + (((setup if recipe else parents)) or [])
        if icols is None: return
        ins = _ins_sql(q, icols)
        # mock TRUE -> WITH CHECK passes -> insert lives; mock FALSE -> WITH CHECK fails -> 42501
        mock_one("true",  f"SELECT lives_ok( $$ {ins} $$, {desc('INSERT: authenticated, authorized when ' + fns + ' [mocked; wiring]')} );", True, preseed=pre_ins, ident="authorized", exp=True)
        mock_one("false", f"SELECT throws_ok( $$ {ins} $$, '42501', NULL, {desc('INSERT: authenticated, not authorized blocked when ' + fns + '=false [mocked; wiring]')} );", True, preseed=pre_ins, ident="other", exp=False)
        return
    if cmd == "UPDATE":
        if not upd_col: return
        action = f"UPDATE {q} SET {_qi(upd_col[0])}={_upd_val(upd_col[0], upd_col[1])}"
    else:
        action = f"DELETE FROM {q}"
    preseed = _exist_pre() or []   # UPDATE/DELETE need a row present to affect
    mock_one("true",  f"SELECT isnt_empty( $$ {action} RETURNING 1 $$, {desc(cmd + ': authenticated, authorized when ' + fns + ' [mocked; wiring]')} );", True, preseed=preseed, ident="authorized", exp=True)
    mock_one("false", f"SELECT is_empty( $$ {action} RETURNING 1 $$, {desc(cmd + ': authenticated, not authorized blocked when ' + fns + '=false [mocked; wiring]')} );", True, preseed=preseed, ident="other", exp=False)


def run(ctx, baker, cmd):
    if ctx.classes:   # a classified branch owns this command; these strategies serve the unclassified case
        return PASS
    if ctx.udfs:                                                  # opaque BOOLEAN function -> MOCK it (wiring)
        mock_emit(ctx, baker, cmd)
        return AUGMENT   # falls through to the identity battery (as the old ladder did)
    return PASS
