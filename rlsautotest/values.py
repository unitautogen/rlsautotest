# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""Type-aware literal synthesis (static table + DB-oracle _castable_lit) and reserved sentinel values.

Split out of the original single-module cli.py; behavior-preserving.
"""
from __future__ import annotations
import argparse, json, re, sys
import psycopg
from pglast.parser import parse_sql_json



def _lit(typ):
    t = typ.lower()
    if t.endswith("[]"): return "'{}'"   # empty-array literal, valid for ANY array type (text[] etc.); avoids 'x', which is a malformed array literal
    if "char" in t or "text" in t: return "'x'"
    if "uuid" in t: return "'000000ff-0000-0000-0000-0000000000ff'"
    if "bool" in t: return "false"
    if any(k in t for k in ("int", "numeric", "real", "double", "decimal")): return "1"
    if "timestamp" in t or "date" in t: return "now()"
    if "json" in t: return "'{}'"
    return "'x'"


def _nonempty_array_lit(arrtyp):
    """A valid ONE-element array literal for an array type — satisfies a cardinality(col) > 0 CHECK."""
    el = (arrtyp[:-2] if arrtyp.endswith("[]") else arrtyp).strip().lower()
    if "uuid" in el: return "'{000000ff-0000-0000-0000-0000000000ff}'"
    if any(k in el for k in ("int", "numeric", "real", "double", "decimal", "serial")): return "'{1}'"
    if "bool" in el: return "'{true}'"
    return "'{x}'"


_CASTABLE_CACHE = {}

def _castable_lit(conn, typ, salt=0):
    """A literal VALID for column type `typ`, verified against the DB (F3: the type analog of the
    probe-and-repair seeding philosophy). It tries the fast substring guess `_lit(typ)` FIRST, so every
    type the static tables already handle yields the exact same literal and emitted SQL is unchanged;
    only an exotic/unknown type (inet, bytea, citext, a DOMAIN, a range, a custom type) falls through to
    a small DB-probed candidate list. Returns the guess unchanged if nothing casts, so the caller still
    degrades to NOT_TESTABLE rather than fabricating a value."""
    if typ is None:
        typ = "text"
    key = (typ, salt)
    if key in _CASTABLE_CACHE:
        return _CASTABLE_CACHE[key]
    guess = _bump_lit(typ, salt) if salt else _lit(typ)
    cur = conn.cursor()
    def casts(lit):
        cur.execute("SAVEPOINT _cl")
        try:
            cur.execute(f"SELECT ({lit})::{typ}")
            cur.execute("RELEASE SAVEPOINT _cl")
            return True
        except psycopg.Error:
            try:
                cur.execute("ROLLBACK TO SAVEPOINT _cl")
            except psycopg.Error:
                pass
            return False
    for cand in [guess, "'x'", "1", "0", "false", "now()", "'{}'", "'0.0.0.0'",
                 "'00:00:00:00:00:00'", "'\\x00'", "'[0,1)'", "'a'"]:
        if casts(cand):
            _CASTABLE_CACHE[key] = cand
            return cand
    # F3 last resort: resolve the type through the catalog (a DOMAIN's base type, an array's element
    # type) and try THAT type's literal — covers a domain over a type the candidate list can't hit.
    base = _pg_base_type(conn, typ)
    if base and base != typ:
        cand = _castable_lit(conn, base, salt)
        if casts(cand):
            _CASTABLE_CACHE[key] = cand
            return cand
    _CASTABLE_CACHE[key] = guess
    return guess


def _pg_base_type(conn, typ):
    """Catalog resolution for _castable_lit's last resort: a DOMAIN's base type or an array's
    element type (format_type text), else None."""
    try:
        cur = conn.cursor()
        cur.execute("""SELECT CASE WHEN t.typtype = 'd' THEN format_type(t.typbasetype, t.typtypmod)
                                   WHEN t.typelem <> 0 AND t.typlen = -1 THEN format_type(t.typelem, NULL)
                              END
                       FROM pg_type t WHERE t.oid = %s::regtype""", (typ,))
        r = cur.fetchone()
        return r[0] if r else None
    except psycopg.Error:
        try:
            conn.cursor().execute("ROLLBACK TO SAVEPOINT _cl")
        except psycopg.Error:
            pass
        return None


class TypeValueProvider:
    """F3: THE entry point for 'a valid literal for column type T' (the review's TypeValueProvider).
    Bundles the static guess tables, the salted variant, the DB-verified check and the DB-oracle
    candidate search (plus the catalog domain/array-element resolution) behind one object. The
    module-level functions remain the implementation; this class is the documented seam a future
    dialect/provider swaps out."""
    def __init__(self, conn=None):
        self.conn = conn

    def lit(self, typ):                    # fast static guess (enum-unaware)
        return _lit(typ)

    def salted(self, typ, salt):           # distinct-per-class variant
        return _bump_lit(typ, salt)

    def verified(self, typ, guess):        # keep the guess iff the DB confirms it casts
        return _verified_lit(self.conn, typ, guess)

    def castable(self, typ, salt=0):       # DB-oracle search (guess first; exotic types repaired)
        return _castable_lit(self.conn, typ, salt) if self.conn is not None else _lit(typ)

    def nonempty_array(self, arrtyp):
        return _nonempty_array_lit(arrtyp)


def _verified_lit(conn, typ, guess):
    """F3: keep `guess` when the DB confirms it casts to `typ` (so every already-handled type is
    byte-for-byte unchanged); an exotic type falls through to the `_castable_lit` DB-oracle candidates.
    No conn / no type -> the guess unchanged (the caller degrades to NOT_TESTABLE as before)."""
    if conn is None or typ is None:
        return guess
    key = (typ, "verified", guess)
    if key in _CASTABLE_CACHE:
        return _CASTABLE_CACHE[key]
    cur = conn.cursor()
    cur.execute("SAVEPOINT _vl")
    try:
        cur.execute(f"SELECT ({guess})::{typ}")
        cur.execute("RELEASE SAVEPOINT _vl")
        _CASTABLE_CACHE[key] = guess
        return guess
    except psycopg.Error:
        try:
            cur.execute("ROLLBACK TO SAVEPOINT _vl")
        except psycopg.Error:
            pass
    out = _castable_lit(conn, typ)
    _CASTABLE_CACHE[key] = out
    return out


CV = ["11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", "33333333-3333-3333-3333-333333333333"]

MV = ["a0000001-0000-0000-0000-000000000001", "a0000002-0000-0000-0000-000000000002", "a0000003-0000-0000-0000-000000000003"]

FOREIGN = "ffffffff-ffff-ffff-ffff-ffffffffffff"

FUTURE_EXP = 4102444800   # 2100-01-01 (unix): synthetic authenticated JWTs carry an 'exp' so expiry-aware policy

                          # helpers (e.g. supabase_rbac's _jwt_is_expired) return false instead of RAISE'ing on our tokens
NOBODY = "99999999-9999-9999-9999-999999999999"

RIVAL_SUB = "b0000000-0000-0000-0000-0000000000bb"   # a DIFFERENT authenticated user who belongs to a DIFFERENT tenant (org B)

RIVAL_ORG = "b0000000-0000-0000-0000-00000000b0b0"   # tenant B's scope value — proves "has tenancy, just not A's"

INS = "cccccccc-cccc-cccc-cccc-cccccccccccc"   # fresh value for insert-into-own-scope tests

WV_UID = "5ce1a000-0000-4000-8000-000000000001"   # the witness solver's acting identity (auth.uid())

WV_SCOPE = "5c09e000-0000-4000-8000-000000000001"   # the witness solver's scope/correlation value

WV_MISS = "5c09e000-0000-4000-8000-0000000000ff"    # the falsifier: a scope value that matches nothing

REC_ROOT = "cccccccc-0000-4000-8000-00000000cccc"   # recursion strategy: the hierarchy root's owner

REC_OTHER = "dddddddd-0000-4000-8000-00000000dddd"  # recursion strategy: the not-authorized user


# F10: ONE auditable registry of every reserved uuid the engine may write during probes.
# A new strategy picks its sentinels here (and the collision test in test_smoke keeps them unique) —
# two strategies silently sharing a value would let one strategy's seed satisfy another's predicate.
ALL_SENTINELS = {
    "CV0": CV[0], "CV1": CV[1], "CV2": CV[2],
    "MV0": MV[0], "MV1": MV[1], "MV2": MV[2],
    "FOREIGN": FOREIGN, "NOBODY": NOBODY, "RIVAL_SUB": RIVAL_SUB, "RIVAL_ORG": RIVAL_ORG, "INS": INS,
    "WV_UID": WV_UID, "WV_SCOPE": WV_SCOPE, "WV_MISS": WV_MISS,
    "REC_ROOT": REC_ROOT, "REC_OTHER": REC_OTHER,
    "SPAIR_A": "aaaaaaaa-0000-4000-8000-00000000aaaa", "SPAIR_B": "bbbbbbbb-0000-4000-8000-00000000bbbb",
    "FORCE_A": "5cf00000-0000-4000-8000-0000000000a1", "FORCE_B": "5cf00000-0000-4000-8000-0000000000b2",
    "PICK": "000000c1-0000-0000-0000-0000000000c1", "LIT": "000000ff-0000-0000-0000-0000000000ff",
}



def _bump_lit(typ, salt):
    t = (typ or "").lower()
    if "uuid" in t: return f"'{salt:08x}-0000-0000-0000-000000000000'"
    if any(k in t for k in ("int", "numeric", "real", "double", "serial", "decimal")): return str(1000 + salt)
    if "char" in t or "text" in t: return f"'syn{salt}'"
    return _lit(typ)

