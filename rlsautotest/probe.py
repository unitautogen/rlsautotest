# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""The live probe: run the action in a SAVEPOINT, observe the real outcome, roll back.

Split out of the original single-module cli.py; behavior-preserving.
"""
from __future__ import annotations
import re
from .catalog import _action_table
from .astutil import _qi


_DDL_RE = re.compile(r"^\s*(CREATE|ALTER|DROP)\b", re.I)   # arrange statements that install mocks/helpers


def _unrel_fail(desc_fn, label, o, sanctioned=False):
    """A loud, never-passing pgTAP line for a test whose result could not be trusted. We still PROBED (the
    observation is shown in the message), but an untrustworthy result must never masquerade as a pass -- so
    this asserts failure and is tagged UNRELIABLE for the report + CI gate to pick up. The reason (o[2])
    carries its own `Fix:` clause naming the remedy for this specific cause, so the report and the failing
    pgTAP line both tell the reader how to get ahead of it (never a blanket 'investigate seeding').

    MB-25: when the cell has been reviewed and sanctioned (`--allow-unreliable` / `.rlsautotestignore`),
    emit a pgTAP SKIP instead. SKIP is neither a fail() (which would red the committed suite) nor a passing
    assertion (which would be a false pass on an untrustworthy result) -- it records the cell as deliberately
    not-asserted, with its cause, so the suite can go green while the exception stays visible in the run.
    `sanctioned` defaults False, so every un-sanctioned cell (the whole corpus) is byte-identical."""
    obs = (str(o[0]) + "=" + str(o[1])) if o[0] != "err" else ("error " + str(o[1]))
    body = label + " [probe observed " + obs + "]: " + str(o[2])
    if sanctioned:
        return "SELECT skip( " + desc_fn("UNRELIABLE (sanctioned) - " + body) + ", 1 );"
    return "SELECT fail( " + desc_fn("UNRELIABLE - " + body) + " );"



def _seeded_zero_reason(tgt, seed_err):
    """Fix text for a 'seeded 0 rows' UNRELIABLE -- two causes with two different remedies. If the seed
    INSERT itself failed (seed_err set) the row was NEVER planted, so identity binding is not the
    problem: the table's own constraints (or an arrange that cannot build a conforming value) blocked
    the probe row. If the INSERT succeeded but nothing is visible (seed_err None) the row exists yet
    the identity cannot see it -- an owner-claim / RLS mismatch. Advising 'check the identity binding'
    when the seed never inserted sends the reader down the wrong path, so the branches are kept apart."""
    if seed_err:
        return ("seeded 0 rows in " + tgt + " (seed error " + seed_err + "). Fix: the seed INSERT for "
                "this identity failed with " + seed_err + ", so the row that would make this cell "
                "measurable was never planted -- it violates a table CHECK/constraint, or the arrange "
                "could not synthesize a conforming value. Give " + tgt + " a fixture row that satisfies "
                "the table's constraints (rlsautotest infers many column values automatically, but not "
                "back-referencing or function-delegated CHECKs), or treat this cell as not auto-probable")
    return ("seeded 0 rows in " + tgt + ". Fix: the row planted for this identity was filtered out or "
            "never became visible -- check the seed for " + tgt + " and the identity binding, since a "
            "row whose owner claim auth.uid() does not resolve to is invisible to that identity; confirm "
            "the claim style (JSON request.jwt.claims vs flat request.jwt.claim.*) matches what the "
            "policy reads")


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
                      "artifact, not a policy outcome. Fix: run rlsautotest connected as a role that owns the "
                      "policy function/schema (Supabase: supabase_admin), or run `rlsautotest doctor` to see "
                      "which object could not be created")
    tgt = _action_table(action_sql)
    if tgt and any(re.search(r"insert\s+into\s+" + re.escape(tgt), s or "", re.I) for s in arrange):
        try:
            cur.execute(f"SELECT count(*) FROM {tgt}")
            if int(cur.fetchone()[0]) == 0:
                unreliable = unreliable or _seeded_zero_reason(tgt, seed_err)
        except Exception as e:
            unreliable = unreliable or ("precondition check failed (" + (getattr(e, "sqlstate", None) or "XX000")
                          + "). Fix: the acted-on table could not be counted before the probe -- check the "
                          "arrange/seed for this table and that the connecting role can read it")
    try:
        for s in ident_sqls: cur.execute(s)
    except Exception as e:
        ss = getattr(e, "sqlstate", None) or "XX000"
        return _done("err", ss, unreliable or ("identity setup failed (" + ss + "). Fix: the role or JWT "
                     "claims for this identity could not be set -- confirm the role exists and is grantable "
                     "(SET ROLE-able) by the connecting role, and that the claim GUCs are settable"))
    try:
        if kind == "read":
            cur.execute(action_sql); return _done("count", int(cur.fetchone()[0]), unreliable)
        cur.execute(action_sql); return _done("rows", cur.rowcount, unreliable)
    except Exception as e:
        return _done("err", getattr(e, "sqlstate", None) or "XX000", unreliable)



def _update_selfassign_retry(conn, arrange, ident_sqls, o, action, setcol, q):
    """Recover an UPDATE probe whose OWN synthesized SET value tripped a constraint instead of
    measuring the policy. The CHECK-aware filler cannot construct a satisfying value for every CHECK
    (back-references, look-around, function-delegated), so `SET <neutral> = <literal>` can raise
    23514 check_violation (or a length/format error) -- the probe's own value failing, NOT the RLS
    denial 42501, which write_assert would (correctly) route to UNRELIABLE. Before conceding, RETRY
    with `SET col = DEFAULT`: the neutral column is one the policy never reads, so we are free to
    re-write the value seeding already left in the row (the column was OMITTED from the seed INSERT,
    so it holds its DEFAULT / NULL, valid by construction). Crucially the DEFAULT keyword is a RHS
    that needs NO read of the column, unlike `col = col`, so an identity holding UPDATE but not SELECT
    on the column is measured correctly instead of a false 42501-on-read deny. Postgres still enforces
    the UPDATE privilege and re-evaluates USING / WITH CHECK. Returns the (action, observation) to bake.

    Sound-by-construction: the retry is adopted ONLY when it resolves cleanly (not unreliable, no
    non-42501 error). If the DEFAULT write also fails, or the original outcome was already a clean
    result / denial / unreliable-precondition, the ORIGINAL observation is returned unchanged -- so
    this can turn an UNRELIABLE into a real pass or deny, but never a genuine failure into a false
    pass. (seedfail, whose row cannot be seeded at all, keeps o[2] set and so is left UNRELIABLE
    here -- the regression guard that this fallback masks nothing.)"""
    if not (setcol and not o[2] and o[0] == "err" and o[1] != "42501"):
        return action, o
    selfact = f"UPDATE {q} SET {_qi(setcol)}=DEFAULT"
    o2 = _probe(conn, arrange, ident_sqls, "write", selfact)
    if o2[2] or (o2[0] == "err" and o2[1] != "42501"):
        return action, o
    return selfact, o2



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
        c.observations.append(Observation(cmd=cmd, ident=("anon" if role in ("anon", "anonymous") else "authorized"), exp=False))
        a = f"SELECT throws_ok( $$ {sx} $$, '42501', NULL, {c.desc(cmd + ': ' + who + ' has no grant - denied')} );"
        (self.read_test if cmd == "SELECT" else self.mut_test)(cjson, role, a)

    def _bypass_probed_reason(self, o, ident):
        """MB-9b: when the PROBED constrained client role itself carries BYPASSRLS it sees every row
        regardless of policy, so the observation cannot tell a working policy from a broken one -> return
        a reason to force UNRELIABLE (never a green cell). The sanctioned bypass row (ident 'service_role')
        is exempt: showing it bypasses IS the point of that row. None when nothing bypasses -- so for every
        normal schema (empty ctx.bypass_probed) this is inert and the emitted suite is byte-identical."""
        c = self.ctx
        if o[2] is not None or ident == "service_role" or not c.bypass_probed:
            return None
        _br = c.unauth_role if ident == "anon" else "authenticated"
        if _br not in c.bypass_probed:
            return None
        return ("probing as '" + _br + "' bypasses RLS: the role carries BYPASSRLS, so it sees every row "
                "regardless of policy -- a passing observation here cannot distinguish a correct policy from "
                "a broken one. Fix: ALTER ROLE " + _br + " NOBYPASSRLS so the policy actually applies (or, if "
                "the bypass is intentional, do not probe it as a constrained user -- it is a sanctioned "
                "bypass, reported separately as the L014 finding)")

    # ---- observation -> assertion triage (the four duplicated copies, unified) ----
    def _sanctioned(self, cmd):
        """MB-25: is THIS table's <cmd> UNRELIABLE cell sanctioned (--allow-unreliable / .rlsautotestignore)?
        ctx.sanctioned_unreliable is the set of UPPERCASE commands accepted for this table (empty/None = none,
        so this is False for the whole corpus and the emit stays byte-identical). getattr keeps it safe for a
        minimal context stub that predates the field (e.g. test doubles)."""
        s = getattr(self.ctx, "sanctioned_unreliable", None)
        return bool(s) and cmd.upper() in s

    def read_assert(self, o, who, sees_suffix="", mock_suffix="", ident=None, mocked=False):
        c = self.ctx; desc, q = c.desc, c.q
        _bp = self._bypass_probed_reason(o, ident)
        if _bp: o = (o[0], o[1], _bp)
        if o[2]:
            _sx = self._sanctioned("SELECT")
            c.observations.append(Observation(cmd="SELECT", ident=ident, kind="unreliable", mocked=mocked, sanctioned=_sx))
            return _unrel_fail(desc, "SELECT: " + who, o, sanctioned=_sx)
        if o[0] == "count":
            c.observations.append(Observation(cmd="SELECT", ident=ident, exp=(o[1] >= 1), mocked=mocked))
            return f"SELECT is( (SELECT count(*) FROM {q})::int, {o[1]}, {desc('SELECT: ' + who + mock_suffix + ' sees ' + str(o[1]) + ' row(s)' + sees_suffix)} );"
        c.observations.append(Observation(cmd="SELECT", ident=ident, exp=False, mocked=mocked))
        return f"SELECT throws_ok( $$ SELECT 1 FROM {q} $$, '{o[1]}', NULL, {desc('SELECT: ' + who + mock_suffix + ' denied (' + o[1] + ')')} );"

    def write_assert(self, o, cmd, act, who, ident=None, mocked=False):
        c = self.ctx; desc = c.desc
        _bp = self._bypass_probed_reason(o, ident)
        if _bp: o = (o[0], o[1], _bp)
        if o[2]:
            _sx = self._sanctioned(cmd)
            c.observations.append(Observation(cmd=cmd, ident=ident, kind="unreliable", mocked=mocked, sanctioned=_sx))
            return _unrel_fail(desc, cmd + ": " + who, o, sanctioned=_sx)
        if o[0] == "err" and o[1] != "42501":
            _sx = self._sanctioned(cmd)
            c.observations.append(Observation(cmd=cmd, ident=ident, kind="unreliable", mocked=mocked, sanctioned=_sx))
            return _unrel_fail(desc, cmd + ": " + who, ("err", o[1], "the test action raised " + o[1] + ", a constraint/validity error (not the RLS denial 42501) -- the probe's own synthesized value, not a policy result. Fix: the write value tripped a table CHECK/constraint before RLS was reached -- give the column a CHECK-satisfying value (rlsautotest infers many automatically) or add a policy-neutral column so the write can reach the policy"), sanctioned=_sx)
        if o[0] == "err":
            c.observations.append(Observation(cmd=cmd, ident=ident, exp=False, mocked=mocked))
            return f"SELECT throws_ok( $$ {act} $$, '{o[1]}', NULL, {desc(cmd + ': ' + who + ' denied (' + o[1] + ')')} );"
        if o[0] == "rows" and o[1] >= 1:
            c.observations.append(Observation(cmd=cmd, ident=ident, exp=True, mocked=mocked))
            return f"SELECT isnt_empty( $$ {act} RETURNING 1 $$, {desc(cmd + ': ' + who + ' affected ' + str(o[1]) + ' row(s)')} );"
        c.observations.append(Observation(cmd=cmd, ident=ident, exp=False, mocked=mocked))
        return f"SELECT is_empty( $$ {act} RETURNING 1 $$, {desc(cmd + ': ' + who + ' affects 0 rows')} );"
