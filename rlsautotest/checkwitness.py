# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""Construct a seed value that satisfies a single-column CHECK constraint, so a table whose only
obstacle to seeding is a format/length CHECK becomes testable instead of UNRELIABLE.

Same principle as the rest of the engine: CONSTRUCT a candidate from the constraint's shape and let
Postgres be the judge. This module only builds a candidate; the seed probe INSERTs it and observes the
real outcome. A wrong candidate simply re-fails the INSERT, so the cell stays loudly UNRELIABLE -- this
can only ever turn an UNRELIABLE cell into a real, probe-baked green, never manufacture a false pass.

Tractable shapes (single column): a POSIX regex match (`~` / `~*`), a SQL LIKE (`~~` / `~~*`), and a
length bound via length()/char_length()/octet_length(). Anything outside the subset (arbitrary regex
with back-references or look-around, a function-delegated CHECK, a multi-column CHECK) returns None and
the column stays honestly UNRELIABLE.
"""
from __future__ import annotations
import re
from .astutil import _and_conjuncts, _colname, _const, _names, _t, _unwrap, _v, _where


# ============================================================================================
# PURE STRING GENERATORS -- construct one value; DB-verified downstream by the seed probe.
# ============================================================================================

class _RxUnsupported(Exception):
    pass


def _rx_class_char(cls):
    """The inside-plus-brackets of a char class [...] -> the first alphabet char it accepts."""
    try:
        rx = re.compile(cls)
    except re.error:
        raise _RxUnsupported()
    for c in "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ._-@ ":
        if rx.match(c):
            return c
    raise _RxUnsupported()


def _rx_class(s, i, end):
    j = i + 1
    if j < end and s[j] == "^":
        j += 1
    if j < end and s[j] == "]":
        j += 1   # a literal ] as the first class member
    while j < end and s[j] != "]":
        if s[j] == "\\":
            j += 1
        j += 1
    if j >= end:
        raise _RxUnsupported()
    return s[i:j + 1], j + 1


def _rx_atom(s, i, end):
    ch = s[i]
    if ch == "(":
        j = i + 1
        if s[j:j + 2] == "?:":
            j += 2
        elif s[j:j + 1] == "?":
            raise _RxUnsupported()          # look-around / named group
        branch, j = _rx_seq(s, j, end)      # first alternation branch
        depth, k = 1, j
        while k < end and depth > 0:        # skip to the matching close paren
            if s[k] == "\\":
                k += 2
                continue
            if s[k] == "(":
                depth += 1
            elif s[k] == ")":
                depth -= 1
            k += 1
        if depth != 0:
            raise _RxUnsupported()
        return branch, k
    if ch == "[":
        cls, j = _rx_class(s, i, end)
        return _rx_class_char(cls), j
    if ch == "\\":
        if i + 1 >= end:
            raise _RxUnsupported()
        nx = s[i + 1]
        shorthand = {"d": "0", "w": "a", "s": " ", "D": "a", "W": " ", "S": "a"}
        if nx in shorthand:
            return shorthand[nx], i + 2
        if nx.isdigit():
            raise _RxUnsupported()          # back-reference
        return nx, i + 2                    # escaped literal
    if ch == ".":
        return "a", i + 1
    if ch in "*+?{":
        raise _RxUnsupported()             # quantifier with no preceding atom
    return ch, i + 1                        # plain literal


def _rx_quant(s, i, end):
    """Return (min_repeat, next_i). We always take the minimum count that keeps the string valid."""
    if i >= end:
        return 1, i
    ch = s[i]
    if ch == "+":
        return 1, i + 1
    if ch == "*":
        return 0, i + 1
    if ch == "?":
        return 0, i + 1
    if ch == "{":
        j = s.find("}", i)
        if j == -1:
            raise _RxUnsupported()
        a = s[i + 1:j].split(",")[0].strip()
        if not a.isdigit():
            raise _RxUnsupported()
        return int(a), j + 1
    return 1, i


def _rx_seq(s, i, end, maxlen=256):
    out = []
    while i < end and s[i] not in "|)":
        atom, i = _rx_atom(s, i, end)
        lo, i = _rx_quant(s, i, end)
        out.append(atom * lo)
        if sum(len(x) for x in out) > maxlen:
            raise _RxUnsupported()
    return "".join(out), i


def _regex_witness(pat, maxlen=256):
    """Construct ONE string matching a POSIX-ish regex, for a tractable subset; None if unsupported.
    Best-effort: the seed probe is the authoritative judge, so a subtle POSIX-vs-Python difference just
    degrades to UNRELIABLE (a non-matching value re-fails the INSERT), never a false pass."""
    if not isinstance(pat, str) or pat == "":
        return None
    s = pat
    if s.startswith("^"):
        s = s[1:]
    if s.endswith("$"):
        bs, k = 0, len(s) - 2
        while k >= 0 and s[k] == "\\":
            bs += 1
            k -= 1
        if bs % 2 == 0:
            s = s[:-1]
    try:
        out, consumed = _rx_seq(s, 0, len(s), maxlen)
    except _RxUnsupported:
        return None
    if consumed != len(s) or out is None or len(out) > maxlen:
        return None
    try:
        if re.search(pat, out) is None:   # self-check against Python's engine before trusting it
            return None
    except re.error:
        return None
    return out


def _like_witness(pat):
    """One string matching a SQL LIKE pattern: % -> zero chars, _ -> one char, literals verbatim."""
    if not isinstance(pat, str):
        return None
    out, i = [], 0
    while i < len(pat):
        c = pat[i]
        if c == "\\" and i + 1 < len(pat):
            out.append(pat[i + 1]); i += 2; continue
        if c == "%":
            i += 1; continue
        if c == "_":
            out.append("a"); i += 1; continue
        out.append(c); i += 1
    return "".join(out)


# ============================================================================================
# LENGTH-BOUND arithmetic (pure)
# ============================================================================================

def _len_ok(L, bounds):
    for op, n in bounds:
        if op == "=" and L != n:
            return False
        if op == ">" and not L > n:
            return False
        if op == ">=" and not L >= n:
            return False
        if op == "<" and not L < n:
            return False
        if op == "<=" and not L <= n:
            return False
    return True


def _len_pick(bounds):
    lo, hi, exact = 1, 256, None
    for op, n in bounds:
        if op == "=":
            exact = n
        elif op == ">":
            lo = max(lo, n + 1)
        elif op == ">=":
            lo = max(lo, n)
        elif op == "<":
            hi = min(hi, n - 1)
        elif op == "<=":
            hi = min(hi, n)
    if exact is not None:
        return exact if exact >= 0 and _len_ok(exact, bounds) else None
    L = max(lo, 1)
    return L if L <= hi else None


# ============================================================================================
# AST DRIVER -- find a single-column format/length atom in a CHECK def and construct for it.
# ============================================================================================

def _int_const(n):
    c = _const(n)
    if c is None:
        return None
    try:
        return int(str(c))
    except ValueError:
        return None


def _lenfn_col(n):
    """length(col) / char_length(col) / octet_length(col) / bit_length(col) -> col, else None."""
    n = _unwrap(n)
    if _t(n) == "FuncCall":
        fn = _names(_v(n).get("funcname")).split(".")[-1].lower()
        if fn in ("length", "char_length", "character_length", "octet_length", "bit_length"):
            args = _v(n).get("args", [])
            if len(args) == 1:
                return _colname(args[0])
    return None


def _fmt_check_witness(cdef):
    """A single-column string-format CHECK -> (col, value) satisfying it, or None. Handles a POSIX regex
    (`~`/`~*`), a LIKE (`~~`/`~~*`), and length bounds (length/char_length ... <op> int). Regex wins over
    LIKE (it usually pins the whole format including length). OR anywhere, or any unrecognized shape,
    yields None -> the column stays honestly UNRELIABLE (the seed probe is the final judge)."""
    body = cdef or ""
    if body[:5].upper() == "CHECK":
        body = body[5:].strip()
    w = _where(body)
    if w is None:
        return None
    conjs = _and_conjuncts(w)
    if not conjs:                                  # None (OR present) or empty
        return None
    prefer = None                                  # (col, kind, pattern); regex beats like
    lens = {}                                      # col -> [(op, n)]
    for cj in conjs:
        if _t(cj) != "A_Expr":
            continue
        op = _names(_v(cj).get("name"))
        l, r = _v(cj).get("lexpr"), _v(cj).get("rexpr")
        if op in ("~", "~*", "~~", "~~*"):
            col = _colname(l)
            pat = _const(_unwrap(r))
            if col and isinstance(pat, str):
                kind = "regex" if op in ("~", "~*") else "like"
                if prefer is None or (kind == "regex" and prefer[1] == "like"):
                    prefer = (col, kind, pat)
            continue
        if op in ("<", "<=", ">", ">=", "="):
            col = _lenfn_col(l); k = _int_const(r); flip = False
            if col is None:
                col = _lenfn_col(r); k = _int_const(l); flip = True
            if col is not None and k is not None:
                o = {"<": ">", "<=": ">=", ">": "<", ">=": "<="}[op] if flip else op
                lens.setdefault(col, []).append((o, k))
    if prefer:
        col, kind, pat = prefer
        val = _regex_witness(pat) if kind == "regex" else _like_witness(pat)
        if val is None:
            return None
        if col in lens and not _len_ok(len(val), lens[col]):
            return None                            # regex/like value violates a length bound -> let the probe flag it
        return (col, val)
    for col, bounds in lens.items():               # length-only column
        L = _len_pick(bounds)
        if L is not None:
            return (col, "a" * L)
    return None
