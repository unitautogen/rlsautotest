# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""Custom-role strategy (F5): a policy granted `TO some_custom_role` used to be silently excluded
from the client matrix (the DNF only models PUBLIC/authenticated/anon). This strategy probes each
custom role named by ANY of the table's policies via a real `SET ROLE` (no JWT identity) and surfaces
the role as its own row in the report — the policy stops vanishing.

The existence row it probes against is built to SATISFY that role's own row filter (the `col = const`
equalities in its USING), so a FILTERED role (e.g. `USING (region = 'north')`) actually sees its
permitted row instead of a generic row it filters to zero. When the filter names a concrete value, a
second, deliberately NON-matching ("forbidden") row is also seeded and the SELECT count is asserted to
equal ONLY the permitted rows — so a role that can see a row its policy forbids fails that assertion
(a per-role row-level LEAK test, the analogue of the authenticated "not authorized" negative control).

Runs additively (CONTINUE): the normal client battery still runs after it. It is a strict no-op for a
table whose policies name only standard roles (`_custom_roles` returns []), so Supabase/Neon suites —
which never grant TO a custom role — are byte-for-byte unaffected."""
from __future__ import annotations

from ..probe import _probe, _update_selfassign_retry
from ..seeding import _mock_valid_row, _synthesize_row
from ..structs import Observation
from .base import CONTINUE
from .mock import _ins_sql
from ..astutil import _qi, _where, _and_conjuncts, _t, _v, _unwrap, _colname, _names

# roles that are the modeled client set or platform plumbing, never a "custom" policy audience
_STANDARD = {"public", "authenticated", "anon", "anonymous", "service_role", "authenticator",
             "supabase_auth_admin", "supabase_admin", "postgres", "pgbouncer"}


def _custom_roles(conn, schema, table):
    """Roles named by ANY of this table's policies beyond the client set / platform plumbing, in
    first-seen order (the role is probed for every command: a command its policies don't cover is
    an observed deny, not a blind spot). pg_policies.roles is a name[]; tolerate '{a,b}' text."""
    cur = conn.cursor()
    cur.execute("SELECT roles FROM pg_policies WHERE schemaname=%s AND tablename=%s", (schema, table))
    out = []
    for (roles,) in cur.fetchall():
        if isinstance(roles, str):
            roles = [r.strip().strip('"') for r in roles.strip("{}").split(",") if r.strip()]
        for r in (roles or []):
            # RA-7: pg_* predefined group roles (pg_read_all_data, pg_database_owner, ...) are not
            # SET ROLE-able audiences: membership is computed (pg_database_owner refuses SET ROLE
            # outright) so probing them as custom roles either fails or proves nothing. Excluded
            # here; analyze() surfaces an informational note instead.
            if r not in _STANDARD and not r.startswith("pg_") and r not in out:
                out.append(r)
    return out


def _public_grant_roles(conn, schema, table, exclude):
    """MB-27: custom client roles that hold a DIRECT table grant on this table AND are admitted by a
    no-`TO` PUBLIC policy on it -- so they genuinely reach the table even though NO policy names them.
    The anon slot is already shown, but a second role granted alongside it under a `USING (true)` policy
    used to be invisible despite identical access (e.g. pto.settings granted TO pto_member + pto_visitor).
    aclexplode reads only DIRECT grants (grantee <> 0), so a table granted to PUBLIC does NOT pull in every
    role. [] when the table has no PUBLIC policy or no such direct-grant role -> byte-identical for every
    schema without this exact shape. `exclude` drops the standard slots (already shown) + platform roles."""
    cur = conn.cursor()
    cur.execute("""
        WITH tbl AS (SELECT c.oid, c.relacl FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                     WHERE n.nspname = %s AND c.relname = %s),
        pub AS (SELECT EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = (SELECT oid FROM tbl)
                               AND p.polroles @> ARRAY[0]::oid[]) AS yes)
        SELECT DISTINCT r.rolname
        FROM tbl, LATERAL aclexplode(tbl.relacl) a JOIN pg_roles r ON r.oid = a.grantee
        WHERE (SELECT yes FROM pub)
          AND a.privilege_type IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE')
          AND NOT r.rolsuper AND left(r.rolname, 3) <> 'pg_' AND r.rolname <> current_user
        ORDER BY r.rolname
    """, (schema, table))
    return [r for (r,) in cur.fetchall() if r not in exclude]


def _const_lit(node):
    """An A_Const (optionally cast, e.g. 'north'::text) -> its SQL literal ('north' | 5 | true), else None."""
    node = _unwrap(node)
    if _t(node) == "TypeCast":
        node = _unwrap(_v(node).get("arg"))
    if _t(node) != "A_Const":
        return None
    v = _v(node)
    if "sval" in v:
        return "'" + v["sval"].get("sval", "").replace("'", "''") + "'"
    if "ival" in v:
        return str(v["ival"].get("ival", 0))
    if "boolval" in v:
        return "true" if v["boolval"].get("boolval") else "false"
    return None


def _policy_fixed(conn, schema, table, role):
    """{col: sql_literal} for the `col = const` equalities in this role's SELECT/ALL USING predicates.
    A row carrying these values satisfies the role's row filter, so the role can actually SEE it. Only
    plain top-level AND-ed equalities are read (the sound subset) — an OR / function / comparison policy
    yields {} and the role just gets a generic existence row, never a fabricated pass."""
    cur = conn.cursor()
    cur.execute("SELECT roles, cmd, qual FROM pg_policies WHERE schemaname=%s AND tablename=%s", (schema, table))
    fixed = {}
    for (roles, cmd, qual) in cur.fetchall():
        if isinstance(roles, str):
            roles = [r.strip().strip('"') for r in roles.strip("{}").split(",") if r.strip()]
        if role not in (roles or []) or cmd not in ("ALL", "SELECT") or not qual:
            continue
        try:
            w = _where(qual)
        except Exception:
            w = None
        if w is None:
            continue
        for cj in (_and_conjuncts(w) or [w]):
            if _t(cj) != "A_Expr" or _names(_v(cj).get("name")) != "=":
                continue
            l, r = _v(cj).get("lexpr"), _v(cj).get("rexpr")
            for a, b in ((l, r), (r, l)):
                col = _colname(a)
                lit = _const_lit(b)
                if col and lit is not None and col not in fixed:
                    fixed[col] = lit
    return fixed


def _forbid_of(fixed):
    """A one-column variant of `fixed` that VIOLATES the filter (so a correctly-scoped role must NOT see
    the row): flip the first equality to a value that cannot equal the required one. None if not possible."""
    for col, lit in fixed.items():
        if lit.startswith("'"):
            return {col: "'__rlsa_forbidden__'"}
        if lit.lstrip("-").isdigit():
            return {col: str(int(lit) + 987654)}
    return None


def run(ctx, baker, cmd):
    conn, q, schema, table = ctx.conn, ctx.q, ctx.schema, ctx.table
    body, n, reseed = ctx.body, ctx.n, ctx.reseed
    roles = _custom_roles(conn, schema, table)
    # MB-27: ALSO probe a custom role that reaches the table by a DIRECT grant + a no-`TO` PUBLIC policy,
    # even though no policy NAMES it (identical access to the anon slot, previously invisible). Additive +
    # deduped; [] for tables without this shape, so every other schema stays byte-identical.
    _excl = _STANDARD | {ctx.unauth_role, ctx.service_role_name or "service_role"}
    for _pr in _public_grant_roles(conn, schema, table, _excl):
        if _pr not in roles:
            roles.append(_pr)
    if not roles:
        return CONTINUE

    def emit_test(role, arrange, asrt):
        """Emit ONE probed test: reset, arrange (scratch rows), SET ROLE, assert, reset, restore baseline."""
        n[0] += 1
        body.append("RESET ROLE;")
        body.extend(s0 + ";" for s0 in arrange)
        body.append("SELECT set_config('request.jwt.claims', '', true);")
        body.append(f'SET LOCAL ROLE "{role}";')
        body.append(asrt)
        body.append("RESET ROLE;")
        body.append(reseed)   # scratch existence rows are torn down; restore the battery baseline

    for role in roles:
        who = f"custom role {role}"
        ident_key = f"role:{role}"
        pid = ["SELECT set_config('request.jwt.claims', '', true)", f'SET LOCAL ROLE "{role}"']
        permit = _policy_fixed(conn, schema, table, role)
        # An existence row that SATISFIES the role's own row filter (so a filtered role SEES it);
        # fall back to a generic valid row (a read-everything role still proves visibility).
        recipe, srow, setup = _synthesize_row(conn, schema, table, fixed=permit)
        if recipe is not None:
            base_pre = (setup or []) + [_ins_sql(q, srow)]
            ins_cols = srow
        else:
            parents, prow = _mock_valid_row(schema, table, ctx.fkmap, ctx.colsmap, ctx.enums, ctx.checks,
                                            ctx.relchecks, ctx.compfks, conn)
            base_pre = parents + ([_ins_sql(q, prow)] if prow is not None else [])
            ins_cols = prow if prow is not None else ctx.nobody_ins

        if cmd == "SELECT":
            # (1) POSITIVE: the role must SEE its own permitted row (seed the permit row only). read_assert
            #     bakes the observed count -> a ✓ (can) cell when it reads its permitted row, · / throws otherwise.
            arrange = [f"DELETE FROM {q}"] + base_pre
            o = _probe(conn, arrange, pid, "read", f"SELECT count(*) FROM {q}")
            emit_test(role, arrange, baker.read_assert(o, who, ident=ident_key))
            # (2) LEAK GUARD: seed a deliberately-forbidden row too; the role must see ONLY its permitted
            #     row(s). A role that can ALSO see the forbidden row is over-exposed -> a row-level LEAK.
            #     Recorded as kind="leak" so the report files a failure into leak_cells (a ✓! DANGER cell),
            #     not a plain can/can't outcome — over-exposure reads as a hole, never as "too strict".
            if recipe is not None and permit and o[0] == "count":
                fb = _forbid_of(permit)
                if fb:
                    fr, fsrow, fsetup = _synthesize_row(conn, schema, table, fixed={**permit, **fb})
                    if fr is not None:
                        arr2 = [f"DELETE FROM {q}"] + base_pre + (fsetup or []) + [_ins_sql(q, fsrow)]
                        o2 = _probe(conn, arr2, pid, "read", f"SELECT count(*) FROM {q}")
                        if o2[0] == "count":   # the role can read; a forbidden-row sighting is the leak
                            ctx.observations.append(Observation(cmd="SELECT", ident=ident_key, kind="leak"))
                            asrt2 = ("SELECT is( (SELECT count(*) FROM " + q + ")::int, 1, "
                                     + ctx.desc("SELECT: " + who + " must see ONLY its permitted row; a forbidden row it can also see is a policy LEAK [leak check]")
                                     + " );")
                            emit_test(role, arr2, asrt2)
        else:
            if cmd == "INSERT":
                if ins_cols is None:
                    continue
                act = _ins_sql(q, ins_cols)
                # do NOT pre-seed the row the INSERT itself creates (avoid a 23505 the probe would mis-read)
                arrange = [f"DELETE FROM {q}"] + (base_pre[:-1] if base_pre and base_pre[-1].startswith("INSERT") else base_pre)
            elif cmd == "UPDATE":
                if not ctx.upd_col:
                    continue
                act = f"UPDATE {q} SET {_qi(ctx.upd_col[0])}={ctx.upd_val(ctx.upd_col[0], ctx.upd_col[1])}"
                arrange = [f"DELETE FROM {q}"] + base_pre
            else:
                act = f"DELETE FROM {q}"
                arrange = [f"DELETE FROM {q}"] + base_pre
            o = _probe(conn, arrange, pid, "write", act)
            if cmd == "UPDATE" and ctx.upd_col:   # neutral-column CHECK the filler can't satisfy -> self-assign, not UNRELIABLE
                act, o = _update_selfassign_retry(conn, arrange, pid, o, act, ctx.upd_col[0], q)
            emit_test(role, arrange, baker.write_assert(o, cmd, act, who, ident=ident_key))
    return CONTINUE   # additive: the client battery (and other strategies) still run
