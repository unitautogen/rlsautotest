# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""Typed core structures (F8): the EmitContext every witness strategy consumes.

EmitContext replaces the closure-captured locals of the old monolithic emit_flat: the
static table facts, the seed plan, the derived probe facts, and the shared output
buffer, plus the small identity/description helpers that used to be nested closures.
Behavior-preserving: method bodies are verbatim from the old closures.
"""
from __future__ import annotations
import json
from dataclasses import dataclass, field
from typing import Any

from .astutil import _qlit, _is_uuid
from .values import NOBODY, _nonempty_array_lit


@dataclass
class Observation:
    """One emitted test, machine-readable (F4): what command/identity it exercises and the
    outcome it asserts. The report files matrix cells from THIS, not from parsing the English
    test description — so a strategy's label wording is no longer load-bearing.

    kind: "cell" (a grant/deny matrix cell) | "unreliable" (seed/precondition failed; the baked
    assertion fails loudly) | "leak" (cross-policy WITH CHECK transition audit) | "unknown"
    (recorded for index alignment only; the report falls back to label parsing)."""
    cmd: str = None
    ident: str = None        # "authorized" | "other" | "anon" | None
    exp: bool = True         # the OBSERVED outcome baked into the assertion (can=True / blocked=False)
    kind: str = "cell"
    mocked: bool = False


@dataclass
class EmitContext:
    """Everything a strategy needs to arrange, probe, and bake tests for one table."""
    # ---- table facts (from _load_ctx) ----
    schema: str = None
    table: str = None
    q: str = None                      # quoted "schema"."table"
    per: dict = None                   # per-command classes (analyze)
    cmds: list = None
    cols: list = None                  # [(name, type, colno?, has_default_or_identity)]
    coltypes: dict = None              # {col: type} (probe path)
    fkmap: dict = None
    colsmap: dict = None
    enums: dict = None
    unique_cols: set = None
    checks: dict = None
    cuniques: dict = None
    relchecks: dict = None
    compfks: dict = None
    helpers: bool = True
    gmap: dict = None                  # real effective grants {(role, cmd): bool}
    conn: Any = None
    # ---- seed plan (from _seed_plan) ----
    S: dict = None
    seed: str = None
    seed_emit: str = None
    reseed: str = None
    total_rows: int = 0
    insert_plan: dict = None
    nobody_ins: dict = None
    fill: Any = None                   # fill(type) -> literal
    rowlinked: list = None
    seed_fn_mock: bool = False
    NB: str = None                     # "nobody" claims json
    # ---- derived probe facts ----
    arrange_stmts: list = None
    fk_cols: set = None
    upd_col: tuple = None              # (name, type) policy-neutral UPDATE column, or None
    udfs: list = None                  # opaque boolean policy fns (mock candidates)
    deny_stmt: dict = None             # cmd -> denial statement (no-grant proof)
    classes: list = None               # the CURRENT command's handled identity classes (set per command)
    # ---- output ----
    body: list = field(default_factory=list)
    n: list = field(default_factory=lambda: [0])   # pgTAP plan counter (mutable cell)
    umap: dict = field(default_factory=dict)       # sub-uuid -> helper test-user name
    observations: list = field(default_factory=list)  # one Observation per emitted test, in plan order (F4)

    # ---- identity / description helpers (verbatim from the old closures) ----
    def cj(self, c):
        return json.dumps(c["claims"])

    def user_for(self, sub):
        if sub not in self.umap: self.umap[sub] = f"u_{len(self.umap)}"
        return self.umap[sub]

    def ident(self, cjson, role):
        if role == "service_role":
            return ["SELECT tests.authenticate_as_service_role();"] if self.helpers else ["SELECT set_config('request.jwt.claims', '', true);", "SET LOCAL ROLE service_role;"]
        if role == "anon" or cjson == "":
            return ["SELECT tests.clear_authentication();"] if self.helpers else ["SELECT set_config('request.jwt.claims', '', true);", "SET LOCAL ROLE anon;"]
        if self.helpers:
            d = json.loads(cjson)
            if set(d) <= {"sub", "role"} and d.get("role") == "authenticated" and d.get("sub") and _is_uuid(d["sub"]):
                return [f"SELECT tests.authenticate_as('{self.user_for(d['sub'])}');"]
        return [f"SELECT set_config('request.jwt.claims', {_qlit(cjson)}, true);", f"SET LOCAL ROLE {role};"]

    def pident(self, cjson, role):
        if role == "anon" or cjson == "":
            return ["SELECT set_config('request.jwt.claims', '', true)", f"SET LOCAL ROLE {role if cjson == '' else 'anon'}"]
        return [f"SELECT set_config('request.jwt.claims', {_qlit(cjson)}, true)", f"SET LOCAL ROLE {role}"]

    def desc(self, d):
        return _qlit(d)

    def geff(self, role, cmd):
        return self.gmap.get((role, cmd), True)   # default True when no DB context

    def upd_val(self, col, typ):   # a CHECK-satisfying literal for the SET when known, else a type-based fill
        v = (self.checks.get(self.q) or {}).get(col)
        if v: return v
        # arrays: use a NON-EMPTY literal so a `cardinality(col) > 0` CHECK isn't violated by the SET
        # (an empty '{}' would raise 23514, which is_empty/isnt_empty don't trap -> aborts the pgTAP file).
        return _nonempty_array_lit(typ) if (typ or "").endswith("[]") else self.fill(typ)

    def identities(self, classes):
        # who-labels feed both the baked test descriptions and the report parser (_table_report).
        # 'authenticated, authorized/not authorized' = same `authenticated` role, different JWT claims.
        # service_role FIRST: the report's top row becomes a TESTED observation (probe-and-baked
        # like every other row), not a grants-map inference — every report cell has a test behind it.
        out = [("service_role", "", "service_role", None)]
        out += [(f"authenticated, authorized (branch {c['idx']})", self.cj(c), "authenticated", c) for c in classes]
        # negative control: a legitimate user of a DIFFERENT tenant when the table is tenant/membership-scoped,
        # else a generic other authenticated user (NOBODY).
        if self.S.get("rival", {}).get("on"):
            out.append(("authenticated, not authorized (other tenant)", self.S["rival"]["claims"], "authenticated", None))
        else:
            out.append(("authenticated, not authorized", self.NB, "authenticated", None))
        out.append(("anon", "", "anon", None))
        return out

    @staticmethod
    def spair(typ):
        t = typ.lower()
        if "uuid" in t: return ("aaaaaaaa-0000-4000-8000-00000000aaaa", "bbbbbbbb-0000-4000-8000-00000000bbbb")
        if any(k in t for k in ("int", "numeric", "double", "real", "decimal")): return ("424242", "515151")
        return ("rls_synth_a", "rls_synth_b")

    @staticmethod
    def vlit(typ, s):
        t = typ.lower()
        return s if any(k in t for k in ("int", "numeric", "double", "real", "decimal")) else "'" + s + "'"

    def claims_for(self, gate, V):
        base = {"sub": NOBODY, "role": "authenticated"}
        if gate["kind"] not in ("guc", "mockfn"):   # mockfn drives the predicate via the function mock, not a claim
            node = [V] if gate["kind"] == "claim_array" else V
            for k in reversed(gate["path"]):
                node = {k: node}
            base.update(node)
        return json.dumps(base)

class _DictCompat:
    """Dict-style access shim (F8): the typed structures drop into the existing dict-consuming
    code unchanged — `at["kind"]`, `c.get("mock_fns", [])`, `ctx["row"][col] = v` all keep working.
    get()/in treat a None field like an absent dict key (the shapes never store a meaningful None)."""
    def __getitem__(self, k): return getattr(self, k)
    def __setitem__(self, k, v): setattr(self, k, v)
    def get(self, k, default=None):
        v = getattr(self, k, None)
        return default if v is None else v
    def __contains__(self, k):
        return getattr(self, k, None) is not None


@dataclass
class Atom(_DictCompat):
    """One classified predicate leaf (the classifier's label over the shared signature)."""
    kind: str = None
    text: str = None           # unknown atoms: the human-readable shape for the NT reason
    col: str = None
    value: Any = None
    values: list = None        # col_in_set / col_not_in_set
    keys: list = None          # JWT claim path (tenant / claim_const)
    op: str = None             # temporal comparison operator
    # membership
    mtable: str = None
    muser_col: str = None
    mscope_col: str = None
    row_scope_col: str = None
    mock_fns: list = None
    # rbac introspection
    fn: str = None
    arg: Any = None
    claim: str = None
    rtable: str = None
    role_col: str = None
    perm_col: str = None
    role_label: str = None
    # scalar lookup
    ltable: str = None
    lkey: str = None
    lcol: str = None


@dataclass
class WitnessCtx(_DictCompat):
    """A witness the solver wants to try: session + row + aux-row demands (DB-verified before baking)."""
    sub: str = None
    claims: list = field(default_factory=list)   # [(keys_path, value)]
    guc: dict = field(default_factory=dict)
    row: dict = field(default_factory=dict)
    aux: list = field(default_factory=list)
    role: str = "authenticated"


@dataclass
class IdentityClass(_DictCompat):
    """One derived identity class (a DNF min-term turned into claims + row seed + aux rows)."""
    idx: int = 0
    claims: dict = None
    rowseed: dict = None
    aux: list = None
    scalar_link: str = None
    fk_val: Any = None
    rowlinked: bool = False
    handled: bool = True
    reason: str = None
    has_temporal: bool = False
    kinds: list = None
    tenant_keys: list = None
    fn_mocks: list = None
