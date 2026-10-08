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
        WHERE t.typname='bool' AND p.prokind='f' AND n.nspname NOT IN ('pg_catalog','information_schema','auth')""")
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
    def mock_one(val, ident, who, kind, action, emit_preseed, write, expect_grant):
        """MB-1 (probe-first wiring): install the policy UDF(s) as a constant `val`, PROBE the real
        outcome at generation time, and bake the OBSERVATION via the ProbeBaker -- no more guessed
        counts/lives/throws (the codebase's last probe-and-bake exception, retired). The emitted
        battery reproduces the probe's arrangement exactly (install the mock, seed as the privileged
        role, become the NB authenticated identity, assert, restore the real fn(s), re-seed), so it
        passes on first replay and turns red only if the policy's delegation to the fn later drifts.
          * expect_grant (the mock-TRUE call): a wiring proof needs mocking the fn true to actually
            grant. If it does not (the policy has another gate, or the precondition row was filtered)
            the delegation cannot be isolated -> a loud UNRELIABLE, never a misleading 'authorized
            denied' cell. Corpus mock-true always grants, so this never fires there.
          * a failed seed/precondition still degrades to UNRELIABLE via the baker -- never a false pass."""
        install = [f"CREATE OR REPLACE FUNCTION {u['q']}({u['args']}) RETURNS boolean LANGUAGE sql AS $$ SELECT {val} $$" for u in udfs]
        # Probe against the SAME pre-action state the emitted test will see: the explicit preseed when
        # there is one, else the full seed the file header / re-seed leaves ambient (no-preseed path).
        probe_arrange = install + list(emit_preseed if emit_preseed else (ctx.arrange_stmts or []))
        pid = ctx.pident(NB, "authenticated")
        o = _probe(conn, probe_arrange, pid, kind, action)
        if expect_grant and not o[2]:
            _granted = (o[0] == "count" and o[1] >= 1) if kind == "read" else (o[0] == "rows" and o[1] >= 1)
            if not _granted:
                o = (o[0], o[1], "mocking the policy function(s) TRUE did not grant this command -- the policy "
                     "does not delegate solely to the mocked function (another gate or an unmet precondition "
                     "applies), so the wiring cannot be isolated here; verify the function's own logic separately")
        assertion = (baker.read_assert(o, who, ident=ident, mocked=True) if kind == "read"
                     else baker.write_assert(o, cmd, action, who, ident=ident, mocked=True))
        n[0] += 1
        body.extend(s + ";" for s in install)
        if emit_preseed:                              # seed the precondition as the privileged role (RLS bypassed)
            body.append("RESET ROLE;")
            body.extend((s.rstrip().rstrip(';') + ";") for s in emit_preseed)
        body.extend((s.rstrip().rstrip(';') + ";") for s in pid)   # NB authenticated identity (probe used the same)
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
                  "this environment, so the delegated predicate cannot be isolated. Fix: run rlsautotest "
                  "connected as a role that owns the policy function/schema (Supabase: supabase_admin), or run "
                  "`rlsautotest doctor` to diagnose the probe environment")
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
    who_t = "authenticated, authorized when " + fns + " [mocked; wiring]"
    who_f = "authenticated, not authorized when " + fns + " forced false [mocked; wiring]"
    if cmd == "SELECT":
        act = f"SELECT count(*) FROM {q}"
        pre = _exist_pre()   # one seeded row -> mock TRUE sees it, FALSE hides it; else the ambient header-seeded rows
        mock_one("true",  "authorized", who_t, "read", act, pre, bool(pre), True)
        mock_one("false", "other",      who_f, "read", act, pre, bool(pre), False)
        return
    if cmd == "INSERT":
        icols = srow if recipe is not None else (nobody_ins or prow)
        if icols is None: return
        # Clean the table first: without this the seeded row (from the prior reseed) can share the
        # insert-under-test's UNIQUE key (e.g. members' (group_id,user_id)) -> 23505, which would look
        # like a policy denial. Parents/CHECK-UDF neutralizers stay so the FKs still resolve.
        pre_ins = [f"DELETE FROM {q}"] + (((setup if recipe else parents)) or [])
        ins = _ins_sql(q, icols)
        # mock TRUE -> WITH CHECK passes -> insert lives; mock FALSE -> WITH CHECK fails -> denied (all OBSERVED)
        mock_one("true",  "authorized", who_t, "write", ins, pre_ins, True, True)
        mock_one("false", "other",      who_f, "write", ins, pre_ins, True, False)
        return
    if cmd == "UPDATE":
        if not upd_col: return
        action = f"UPDATE {q} SET {_qi(upd_col[0])}={_upd_val(upd_col[0], upd_col[1])}"
    else:
        action = f"DELETE FROM {q}"
    preseed = _exist_pre() or []   # UPDATE/DELETE need a row present to affect
    mock_one("true",  "authorized", who_t, "write", action, preseed, True, True)
    mock_one("false", "other",      who_f, "write", action, preseed, True, False)


def run(ctx, baker, cmd):
    if ctx.classes:   # a classified branch owns this command; these strategies serve the unclassified case
        return PASS
    if ctx.udfs:                                                  # opaque BOOLEAN function -> MOCK it (wiring)
        # FIRST, real-input coverage where the function body is expandable (witness hints; the probe
        # and the baked tests run the REAL function): the solver/relstate candidates substitute the
        # parsed body predicate for the call. Emitted BEFORE the wiring block on purpose -- wiring
        # restores the generation-time function definition mid-file, so a battery emitted after it
        # would exercise the restored body instead of the live one and a drifted function would
        # slip through on replay. Also covers a solvable NON-fn policy shadowed by a fn policy.
        from .relstate import relstate_emit
        from .solver import solve_emit
        if not solve_emit(ctx, baker, cmd) and cmd == "SELECT":
            relstate_emit(ctx, baker, cmd)
        mock_emit(ctx, baker, cmd)
        return AUGMENT   # falls through to the identity battery (as the old ladder did)
    return PASS
