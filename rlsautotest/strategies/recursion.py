# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""Self-referential-hierarchy strategy: seed an ancestor chain (root owned by the user +
a descendant) so a WITH RECURSIVE policy admits the descendant; probe-verify. SELECT only."""
from __future__ import annotations
import json

from ..astutil import _colname, _is_func, _names, _qi, _qlit, _t, _v, _where
from ..values import REC_OTHER, REC_ROOT
from ..probe import _probe
from ..seeding import _synth_required_cols
from .base import HANDLED, PASS


def _synth_recursion_gate(conn, schema, table, fkmap):
    """A SELECT policy that walks a self-referential hierarchy (WITH RECURSIVE over this table) from an
    owner=auth.uid() base. Returns {owner, self_fk, pk} to seed an ancestor chain, or None."""
    fks = fkmap.get(f"{schema}.{table}", {})
    self_fk = pk = None
    for col, (parent, pcol) in fks.items():
        if parent in (f"{schema}.{table}", table):
            self_fk, pk = col, pcol; break
    if not self_fk:
        return None
    cur = conn.cursor()
    cur.execute("SELECT qual FROM pg_policies WHERE schemaname=%s AND tablename=%s AND cmd IN ('SELECT','ALL')", (schema, table))
    for (qy,) in cur.fetchall():
        if not qy:
            continue
        w = _where(qy)
        # F6: detection reads the parse tree — the WITH RECURSIVE flag and the `owner = auth.uid()`
        # equality (either side, casts/sublinks unwrapped) — not regexes over the deparsed text.
        if w is None or not _has_recursive_with(w):
            continue
        owner = _owner_eq_uid(w)
        if owner:
            return {"owner": owner, "self_fk": self_fk, "pk": pk}
    return None


def _has_recursive_with(n):
    """Any WITH clause in the tree marked recursive."""
    if isinstance(n, dict):
        wc = n.get("withClause")
        if isinstance(wc, dict) and wc.get("recursive"):
            return True
        return any(_has_recursive_with(v) for v in n.values())
    if isinstance(n, list):
        return any(_has_recursive_with(x) for x in n)
    return False


def _owner_eq_uid(n):
    """The column compared (either side) to auth.uid() anywhere in the tree, or None."""
    if isinstance(n, dict):
        if _t(n) == "A_Expr" and _names(_v(n).get("name")) == "=":
            l, r = _v(n).get("lexpr"), _v(n).get("rexpr")
            if _is_func(l, "auth.uid") and _colname(r): return _colname(r)
            if _is_func(r, "auth.uid") and _colname(l): return _colname(l)
        for v in n.values():
            c = _owner_eq_uid(v)
            if c: return c
    elif isinstance(n, list):
        for x in n:
            c = _owner_eq_uid(x)
            if c: return c
    return None


def synth_recursion_emit(ctx, baker, cmd, rg):
    """Seed an ancestor chain (root owned by the user + a descendant) so a self-referential
    hierarchy policy admits the descendant; probe-verify. SELECT only."""
    conn, schema, table, q = ctx.conn, ctx.schema, ctx.table, ctx.q
    body, n, reseed, fill, fkmap = ctx.body, ctx.n, ctx.reseed, ctx.fill, ctx.fkmap
    desc = ctx.desc
    if cmd != "SELECT": return False
    owner, sfk, pk = rg["owner"], rg["self_fk"], rg["pk"]
    req, _ = _synth_required_cols(conn, schema, table, fkmap)
    fkc = set(fkmap.get(f"{schema}.{table}", {}))
    extra = {}
    for rn, rt in req:
        if rn in (owner, sfk): continue
        if rn in fkc: return False   # another required FK we can't parent -> honest fall-through
        extra[rn] = fill(rt)
    xc = ("" if not extra else ", " + ", ".join(_qi(c) for c in extra))
    xv = ("" if not extra else ", " + ", ".join(extra.values()))
    U, U2 = REC_ROOT, REC_OTHER   # canonical home: values.ALL_SENTINELS (F10)
    arrange = [f"DELETE FROM {q}",
               f"INSERT INTO auth.users(id) VALUES ('{U}') ON CONFLICT DO NOTHING",
               f"INSERT INTO {q}({_qi(owner)}{xc}) VALUES ('{U}'{xv})",                                   # root owned by U
               f"INSERT INTO {q}({_qi(sfk)}{xc}) VALUES ((SELECT {_qi(pk)} FROM {q} WHERE {_qi(owner)}='{U}' ORDER BY {_qi(pk)} LIMIT 1){xv})"]  # descendant under root
    def one(who, sub, role, ident):
        claims = None if role == "anon" else json.dumps({"sub": sub, "role": "authenticated"})
        pidl = (["SELECT set_config('request.jwt.claims', '', true)", "SET LOCAL ROLE anon"] if role == "anon"
                else [f"SELECT set_config('request.jwt.claims', {_qlit(claims)}, true)", "SET LOCAL ROLE authenticated"])
        o = _probe(conn, arrange, pidl, "read", f"SELECT count(*) FROM {q}")
        asrt = baker.read_assert(o, who, sees_suffix=" (recursive hierarchy)", ident=ident)
        n[0] += 1
        body.append("RESET ROLE;")
        body.extend(a + ";" for a in arrange)
        body.extend(s + ";" for s in pidl)
        body.append(asrt); body.append("RESET ROLE;"); body.append(reseed)
    one("authenticated, authorized", U, "authenticated", "authorized")
    one("authenticated, not authorized", U2, "authenticated", "other")
    one("anon", None, "anon", "anon")
    return True


def run(ctx, baker, cmd):
    if ctx.classes:   # a classified branch owns this command; these strategies serve the unclassified case
        return PASS
    rg = _synth_recursion_gate(ctx.conn, ctx.schema, ctx.table, ctx.fkmap)   # self-referential hierarchy -> SEED an ancestor chain
    if rg and synth_recursion_emit(ctx, baker, cmd, rg):
        return HANDLED
    return PASS
