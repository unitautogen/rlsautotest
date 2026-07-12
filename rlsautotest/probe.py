# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""The live probe: run the action in a SAVEPOINT, observe the real outcome, roll back.

Split out of the original single-module cli.py; behavior-preserving.
"""
from __future__ import annotations
import argparse, json, re, sys
import psycopg
from pglast.parser import parse_sql_json
from .catalog import _action_table


_DDL_RE = re.compile(r"^\s*(CREATE|ALTER|DROP)\b", re.I)   # arrange statements that install mocks/helpers


def _unrel_fail(desc_fn, label, o):
    """A loud, never-passing pgTAP line for a test whose precondition could not be established. We still
    PROBED (the observation is shown in the message), but a failed precondition must never masquerade as a
    pass -- so this asserts failure and is tagged UNRELIABLE for the report + CI gate to pick up."""
    obs = (str(o[0]) + "=" + str(o[1])) if o[0] != "err" else ("error " + str(o[1]))
    return "SELECT fail( " + desc_fn("UNRELIABLE - " + label + ": " + str(o[2]) + " [probe observed " + obs + "]; precondition not established - investigate seeding") + " );"



def _probe(conn, arrange, ident_sqls, kind, action_sql):
    """Run ONE identity x command at generation time and OBSERVE the real outcome (arrange -> become
    identity -> act), then roll everything back. Returns a 3-tuple (kind, val, unreliable):
      kind/val : ('count', n) read · ('rows', n) write · ('err', sqlstate) denial/error AT ACT TIME
      unreliable: None, or a reason string when the test's PRECONDITION could not be established.

    Two design points that keep probe-and-bake honest:
      * Each arrange statement runs in its OWN savepoint, so a BENIGN seed error (e.g. a redundant
        duplicate insert) does not abort the probe -- we still proceed to the action and bake what we
        actually observe, rather than screaming at the first hiccup.
      * Post-arrange INVARIANT: if we intended to seed the acted-on table but it ends up empty, the
        precondition failed -> `unreliable` is set. The caller then bakes a LOUD, failing test that
        shows the observation but is never a silent pass -- a real seeding failure can no longer be
        mis-baked as a policy denial."""
    cur = conn.cursor()
    cur.execute("SAVEPOINT _rlsa_probe")
    def _done(kind, val, unreliable):
        try: cur.execute("ROLLBACK TO SAVEPOINT _rlsa_probe"); cur.execute("RELEASE SAVEPOINT _rlsa_probe")
        except Exception: pass
        return (kind, val, unreliable)
    try: cur.execute("RESET ROLE")
    except Exception: pass
    try: cur.execute("SELECT set_config('request.jwt.claims', '', true)")   # seed identity-neutral (auth.uid() NULL): an ownership-on-insert trigger must not attribute seeded rows to the last probed identity
    except Exception: pass
    seed_err = None
    ddl_err = None   # a failed CREATE/ALTER/DROP in arrange is NEVER benign: it means a required
    # mock/helper could not be installed (e.g. the connection role does not own the policy function),
    # so the action would run against the REAL environment and the observation would be an artifact,
    # not a policy outcome. Issue #2: baking that observation green-lights owner-denied.
    for s in arrange:                                            # per-statement isolation: tolerate benign seed errors
        if not s.strip(): continue
        cur.execute("SAVEPOINT _rlsa_seed")
        try:
            cur.execute(s); cur.execute("RELEASE SAVEPOINT _rlsa_seed")
        except Exception as e:
            ss = getattr(e, "sqlstate", None) or "XX000"
            seed_err = seed_err or ss
            if _DDL_RE.match(s) and ddl_err is None:
                ddl_err = (ss, " ".join(s.strip().split())[:120])
            try: cur.execute("ROLLBACK TO SAVEPOINT _rlsa_seed")
            except Exception: pass
    unreliable = None                                            # post-arrange invariant
    if ddl_err:
        unreliable = ("mock/helper DDL failed (" + ddl_err[0] + "): `" + ddl_err[1] + "` -- the probe "
                      "environment cannot install the required mock/helper, so the observation would be an "
                      "artifact, not a policy outcome; connect as a role that owns the function/schema "
                      "(Supabase: supabase_admin) or run `rlsautotest doctor`")
    tgt = _action_table(action_sql)
    if tgt and any(re.search(r"insert\s+into\s+" + re.escape(tgt), s or "", re.I) for s in arrange):
        try:
            cur.execute(f"SELECT count(*) FROM {tgt}")
            if int(cur.fetchone()[0]) == 0:
                unreliable = unreliable or ("seeded 0 rows in " + tgt + (f" (seed error {seed_err})" if seed_err else ""))
        except Exception as e:
            unreliable = unreliable or ("precondition check failed (" + (getattr(e, "sqlstate", None) or "XX000") + ")")
    try:
        for s in ident_sqls: cur.execute(s)
    except Exception as e:
        ss = getattr(e, "sqlstate", None) or "XX000"
        return _done("err", ss, unreliable or ("identity setup failed (" + ss + ")"))
    try:
        if kind == "read":
            cur.execute(action_sql); return _done("count", int(cur.fetchone()[0]), unreliable)
        cur.execute(action_sql); return _done("rows", cur.rowcount, unreliable)
    except Exception as e:
        return _done("err", getattr(e, "sqlstate", None) or "XX000", unreliable)



from .structs import Observation


class ProbeBaker:
    """The single canonical home for probe-then-bake (F1): sqlstate triage, the UNRELIABLE
    path, and the emit/re-seed discipline every strategy shares. A wrong observation can
    only degrade to UNRELIABLE / an honest failing assertion — never a false pass.

    Triage contract (verbatim from the four strategy copies it replaces):
      read  : unreliable -> UNRELIABLE; count -> is(count); else -> throws_ok(sqlstate)
      write : unreliable -> UNRELIABLE; non-42501 error -> UNRELIABLE (our own action was
              malformed, not a policy denial); 42501/err -> throws_ok; rows>=1 -> isnt_empty;
              else -> is_empty
    """
    def __init__(self, ctx):
        self.ctx = ctx

    def probe(self, arrange, pid, kind, act):
        return _probe(self.ctx.conn, arrange, pid, kind, act)

    # ---- emit-into-body test writers (the old read_test / mut_test / deny closures) ----
    def read_test(self, cjson, role, assertion):
        c = self.ctx
        c.n[0] += 1; c.body.extend(c.ident(cjson, role)); c.body.append(assertion); c.body.append("RESET ROLE;")

    def mut_test(self, cjson, role, assertion):
        c = self.ctx
        c.n[0] += 1; c.body.extend(c.ident(cjson, role)); c.body.append(assertion); c.body.append(c.reseed)

    def deny(self, cmd, cjson, role, who):
        """Prove an action is denied (missing grant / schema usage -> 42501)."""
        c = self.ctx
        sx = c.deny_stmt.get(cmd)
        if not sx: return
        c.observations.append(Observation(cmd=cmd, ident=("anon" if role == "anon" else "authorized"), exp=False))
        a = f"SELECT throws_ok( $$ {sx} $$, '42501', NULL, {c.desc(cmd + ': ' + who + ' has no grant - denied')} );"
        (self.read_test if cmd == "SELECT" else self.mut_test)(cjson, role, a)

    # ---- observation -> assertion triage (the four duplicated copies, unified) ----
    def read_assert(self, o, who, sees_suffix="", mock_suffix="", ident=None, mocked=False):
        c = self.ctx; desc, q = c.desc, c.q
        if o[2]:
            c.observations.append(Observation(cmd="SELECT", ident=ident, kind="unreliable", mocked=mocked))
            return _unrel_fail(desc, "SELECT: " + who, o)
        if o[0] == "count":
            c.observations.append(Observation(cmd="SELECT", ident=ident, exp=(o[1] >= 1), mocked=mocked))
            return f"SELECT is( (SELECT count(*) FROM {q})::int, {o[1]}, {desc('SELECT: ' + who + mock_suffix + ' sees ' + str(o[1]) + ' row(s)' + sees_suffix)} );"
        c.observations.append(Observation(cmd="SELECT", ident=ident, exp=False, mocked=mocked))
        return f"SELECT throws_ok( $$ SELECT 1 FROM {q} $$, '{o[1]}', NULL, {desc('SELECT: ' + who + mock_suffix + ' denied (' + o[1] + ')')} );"

    def write_assert(self, o, cmd, act, who, ident=None, mocked=False):
        c = self.ctx; desc = c.desc
        if o[2]:
            c.observations.append(Observation(cmd=cmd, ident=ident, kind="unreliable", mocked=mocked))
            return _unrel_fail(desc, cmd + ": " + who, o)
        if o[0] == "err" and o[1] != "42501":
            c.observations.append(Observation(cmd=cmd, ident=ident, kind="unreliable", mocked=mocked))
            return _unrel_fail(desc, cmd + ": " + who, ("err", o[1], "the test action raised " + o[1] + ", a constraint/validity error (not the RLS denial 42501) — the probe's own value, not a policy result"))
        if o[0] == "err":
            c.observations.append(Observation(cmd=cmd, ident=ident, exp=False, mocked=mocked))
            return f"SELECT throws_ok( $$ {act} $$, '{o[1]}', NULL, {desc(cmd + ': ' + who + ' denied (' + o[1] + ')')} );"
        if o[0] == "rows" and o[1] >= 1:
            c.observations.append(Observation(cmd=cmd, ident=ident, exp=True, mocked=mocked))
            return f"SELECT isnt_empty( $$ {act} RETURNING 1 $$, {desc(cmd + ': ' + who + ' affected ' + str(o[1]) + ' row(s)')} );"
        c.observations.append(Observation(cmd=cmd, ident=ident, exp=False, mocked=mocked))
        return f"SELECT is_empty( $$ {act} RETURNING 1 $$, {desc(cmd + ': ' + who + ' affects 0 rows')} );"
