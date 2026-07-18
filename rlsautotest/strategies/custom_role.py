# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""Custom-role strategy (F5): a policy granted `TO some_custom_role` used to be silently excluded
from the client matrix (the DNF only models PUBLIC/authenticated/anon). This strategy probes each
custom role named by ANY of the table's policies via a real `SET ROLE` (no JWT identity), against a
synthesized existence row, bakes the observed grant/deny for every command, and surfaces the role
as its own row in the report — the policy stops vanishing. Runs additively (CONTINUE): the normal
client battery still runs after it."""
from __future__ import annotations

from ..probe import _probe
from ..seeding import _mock_valid_row, _synthesize_row
from .base import CONTINUE
from .mock import _ins_sql
from ..astutil import _qi

# roles that are the modeled client trio or platform plumbing, never a "custom" policy audience
_STANDARD = {"public", "authenticated", "anon", "service_role", "authenticator",
             "supabase_auth_admin", "supabase_admin", "postgres", "pgbouncer"}


def _custom_roles(conn, schema, table):
    """Roles named by ANY of this table's policies beyond the client trio / platform plumbing, in
    first-seen order (the role is probed for every command: a command its policies don't cover is
    an observed deny, not a blind spot). pg_policies.roles is a name[]; tolerate '{a,b}' text."""
    cur = conn.cursor()
    cur.execute("SELECT roles FROM pg_policies WHERE schemaname=%s AND tablename=%s", (schema, table))
    out = []
    for (roles,) in cur.fetchall():
        if isinstance(roles, str):
            roles = [r.strip().strip('"') for r in roles.strip("{}").split(",") if r.strip()]
        for r in (roles or []):
            if r not in _STANDARD and r not in out:
                out.append(r)
    return out


def run(ctx, baker, cmd):
    conn, q, schema, table = ctx.conn, ctx.q, ctx.schema, ctx.table
    body, n, reseed = ctx.body, ctx.n, ctx.reseed
    roles = _custom_roles(conn, schema, table)
    if not roles:
        return CONTINUE
    # One valid existence row (probe-and-repair synthesizer first, static builder as fallback), so a
    # read-everything role proves real visibility even when no CLIENT policy seeded any rows.
    recipe, srow, setup = _synthesize_row(conn, schema, table)
    if recipe is not None:
        pre = [f"DELETE FROM {q}"] + (setup or []) + [_ins_sql(q, srow)]
        ins_cols = srow
    else:
        parents, prow = _mock_valid_row(schema, table, ctx.fkmap, ctx.colsmap, ctx.enums, ctx.checks,
                                        ctx.relchecks, ctx.compfks, conn)
        pre = [f"DELETE FROM {q}"] + parents + ([_ins_sql(q, prow)] if prow is not None else [])
        ins_cols = prow if prow is not None else ctx.nobody_ins
    for role in roles:
        who = f"custom role {role}"
        ident_key = f"role:{role}"
        pid = ["SELECT set_config('request.jwt.claims', '', true)", f'SET LOCAL ROLE "{role}"']
        if cmd == "SELECT":
            o = _probe(conn, pre, pid, "read", f"SELECT count(*) FROM {q}")
            asrt = baker.read_assert(o, who, ident=ident_key)
        else:
            if cmd == "INSERT":
                if ins_cols is None:
                    continue
                act = _ins_sql(q, ins_cols)
            elif cmd == "UPDATE":
                if not ctx.upd_col:
                    continue
                act = f"UPDATE {q} SET {_qi(ctx.upd_col[0])}={ctx.upd_val(ctx.upd_col[0], ctx.upd_col[1])}"
            else:
                act = f"DELETE FROM {q}"
            arrange = pre[:-1] if (cmd == "INSERT" and pre and pre[-1].startswith("INSERT")) else pre
            o = _probe(conn, arrange, pid, "write", act)
            asrt = baker.write_assert(o, cmd, act, who, ident=ident_key)
        n[0] += 1
        body.append("RESET ROLE;")
        _arr = (pre[:-1] if (cmd == "INSERT" and pre and pre[-1].startswith("INSERT")) else pre)
        body.extend(s0 + ";" for s0 in _arr)
        body.append("SELECT set_config('request.jwt.claims', '', true);")
        body.append(f'SET LOCAL ROLE "{role}";')
        body.append(asrt)
        body.append("RESET ROLE;")
        body.append(reseed)   # the existence row is scratch state; restore the battery baseline
    return CONTINUE   # additive: the client battery (and other strategies) still run
