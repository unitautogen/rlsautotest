# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""Construct a seed value that satisfies a single-column CHECK constraint, so a table whose only
obstacle to seeding is a format/length CHECK becomes testable instead of UNRELIABLE.

Same principle as the rest of the engine: CONSTRUCT a candidate from the constraint's shape and let
Postgres be the judge. This module only builds a candidate; the seed probe INSERTs it and observes the
real outcome. A wrong candidate simply re-fails the INSERT, so the cell stays loudly UNRELIABLE -- this
can only ever turn an UNRELIABLE cell into a real, probe-baked green, never manufacture a false pass.

Tractable shapes (single column): a POSIX regex match (`~` / `~*`), including back-references (a
capturing group repeated later, e.g. four identical digits); a SQL LIKE (`~~` / `~~*`); and a length
bound via length()/char_length()/octet_length(). A look-around regex, a function-delegated CHECK, or a
multi-column CHECK returns None and the column stays honestly UNRELIABLE.
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


def _rx_atom(s, i, end, groups):
    ch = s[i]
    if ch == "(":
        j = i + 1
        capturing = True
        if s[j:j + 2] == "?:":
            j += 2
            capturing = False
        elif s[j:j + 1] == "?":
            raise _RxUnsupported()          # look-around / named group
        gi = len(groups) if capturing else None
        if gi is not None:
            groups.append(None)             # reserve this group's number before its branch (nesting-safe)
        branch, j = _rx_seq(s, j, end, groups)      # first alternation branch (may nest more groups)
        if gi is not None:
            groups[gi] = branch
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
        if nx.isdigit():                    # back-reference: emit the value the remembered group produced
            gn = int(nx)
            if 1 <= gn <= len(groups) and groups[gn - 1] is not None:
                return groups[gn - 1], i + 2
            raise _RxUnsupported()          # forward / out-of-range back-reference
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


def _rx_seq(s, i, end, groups, maxlen=256):
    out = []
    while i < end and s[i] not in "|)":
        atom, i = _rx_atom(s, i, end, groups)
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
    groups = []
    try:
        out, consumed = _rx_seq(s, 0, len(s), groups, maxlen)
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


# ============================================================================================
# FORMAT-GENERATOR REGISTRY -- pluggable: each generator maps a parsed single-column CHECK (FmtCtx)
# to a candidate value, or None to defer. Built-ins cover regex / LIKE / length; register your own
# with register_format_generator (front=True to run before the built-ins). The seed probe stays the
# judge, so a custom generator can only ever turn an UNRELIABLE cell into a real, probe-baked green.
# ============================================================================================

class FmtCtx:
    """The parsed facts of a single-column format/length CHECK, handed to each generator."""
    __slots__ = ("col", "coltype", "kind", "pattern", "lens", "cdef")

    def __init__(self, col, coltype=None, kind=None, pattern=None, lens=None, cdef=None):
        self.col = col          # column the CHECK constrains
        self.coltype = coltype  # its declared type, when known (for type-keyed format generators)
        self.kind = kind        # "regex" | "like" | None  (the primary pattern's kind, if any)
        self.pattern = pattern  # the regex / LIKE pattern string, if any
        self.lens = lens or []  # length bounds [(op, n), ...] that also apply to this column
        self.cdef = cdef        # the raw CHECK definition (for a generator that wants to re-parse)


_GENERATORS = []


def register_format_generator(fn, front=False):
    """Register a seed-value generator: fn(FmtCtx) -> str | None (None = defer to the next one).
    front=True runs it before the built-ins (regex / LIKE / length), so a plugin can extend or override
    the constructor without touching the engine. The value is still DB-verified by the seed probe."""
    if front:
        _GENERATORS.insert(0, fn)
    else:
        _GENERATORS.append(fn)


def _run_generators(ctx):
    for fn in _GENERATORS:
        try:
            v = fn(ctx)
        except Exception:
            v = None
        if v is not None:
            return v
    return None


def _gen_regex(ctx):
    if ctx.kind == "regex" and ctx.pattern:
        v = _regex_witness(ctx.pattern)
        if v is not None and (not ctx.lens or _len_ok(len(v), ctx.lens)):
            return v
    return None


def _gen_like(ctx):
    if ctx.kind == "like" and ctx.pattern:
        v = _like_witness(ctx.pattern)
        if v is not None and (not ctx.lens or _len_ok(len(v), ctx.lens)):
            return v
    return None


def _gen_length(ctx):
    if ctx.kind is None and ctx.lens:
        L = _len_pick(ctx.lens)
        if L is not None:
            return "a" * L
    return None


register_format_generator(_gen_regex)
register_format_generator(_gen_like)
register_format_generator(_gen_length)


def _fmt_check_witness(cdef, coltype=None):
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
        ctx = FmtCtx(col=col, coltype=coltype, kind=kind, pattern=pat, lens=lens.get(col, []), cdef=cdef)
        v = _run_generators(ctx)
        return (col, v) if v is not None else None
    for col, bounds in lens.items():               # length-only column
        ctx = FmtCtx(col=col, coltype=coltype, kind=None, pattern=None, lens=bounds, cdef=cdef)
        v = _run_generators(ctx)
        if v is not None:
            return (col, v)
    return None


# ============================================================================================
# FAKER-BACKED NAMED-FORMAT GENERATOR (optional extra) -- realistic values for named real-world
# formats: email, URL, IPv4/IPv6, MAC, UUID, hostname, slug, username, phone, postcode, IBAN, card.
#
# Enabled only when the optional `faker` dependency is installed (`pip install rlsautotest[faker]`).
# Absent, it is a NO-OP: every case is handled by the built-in regex / LIKE / length constructors
# above exactly as before, so emitted SQL is unchanged in any environment without the extra.
#
# It is registered at the FRONT for the named formats it recognises, so such a column seeds with a
# realistic value ("ivy.doe@example.org") instead of the minimal one the plain constructor emits
# ("aa@aa.aa"); it also RESCUES named formats the built-in constructor cannot build at all (e.g. an
# email regex with a look-around length guard). For every OTHER shape it returns None and defers, so
# the generic corpus (digit codes, AA-0000, back-references, length ranges) is byte-for-byte
# unchanged -- verified by the checkfmt regression baseline.
#
# Soundness is identical to the rest of this module: the candidate must still match the column's OWN
# pattern under Python's regex engine (which, unlike the built-in constructor, handles look-around)
# and any length bound, and the seed probe remains the FINAL judge -- so this can only ever turn an
# UNRELIABLE cell into a real, probe-baked green, never manufacture a false pass. Output is
# DETERMINISTIC: the faker draw is seeded from (column, pattern) with a process-independent hash, so
# a given schema always seeds the same value (no dependence on PYTHONHASHSEED or call order).
# ============================================================================================

import hashlib as _hashlib

try:
    from faker import Faker as _Faker
    _FAKER_OK = True
except Exception:                      # faker extra not installed -> the generator is a no-op
    _Faker = None
    _FAKER_OK = False

_FAKER_INSTANCE = None
_FAKER_TRIES = 16                      # deterministic candidates to try per provider before deferring


def _faker_instance():
    global _FAKER_INSTANCE
    if _FAKER_INSTANCE is None and _FAKER_OK:
        _FAKER_INSTANCE = _Faker("en_US")      # ASCII locale -> values stay inside typical ASCII CHECKs
    return _FAKER_INSTANCE


def _stable_seed(*parts):
    """A process-independent 48-bit seed from the parts. NOT builtin hash() -- that is salted per run
    (PYTHONHASHSEED), which would make the emitted seed value differ between runs and break determinism."""
    h = _hashlib.sha256("\x1f".join(str(p) for p in parts).encode("utf-8")).hexdigest()
    return int(h[:12], 16)


# Each entry: (faker method names to try, column-name keywords, pattern substrings). A format is a
# candidate when the column NAME contains one of its keywords OR the PATTERN contains one of its
# substrings. Providers are tried in order; the mandatory pattern match makes a wrong guess harmless.
_NAMED_FORMATS = (
    (("email", "safe_email", "ascii_email", "company_email"),
     ("email", "e_mail", "mail"), ("@",)),
    (("url",),
     ("url", "website", "homepage", "weblink", "link", "web", "site"), ("http", "://", "www.")),
    (("ipv4", "ipv4_private", "ipv4_public"),
     ("ipv4", "ip_address", "ipaddr", "ipaddress", "client_ip", "remote_ip", "remote_addr", "host_ip"), ()),
    (("ipv6",),
     ("ipv6",), ()),
    (("mac_address",),
     ("mac_address", "macaddr", "hwaddr"), ()),
    (("uuid4",),
     ("uuid", "guid"), ()),
    (("hostname", "domain_name"),
     ("hostname", "fqdn", "domainname"), ()),
    (("slug",),
     ("slug", "permalink"), ()),
    (("user_name",),
     ("username", "user_name", "login", "handle", "nickname"), ()),
    (("phone_number", "msisdn"),
     ("phone", "telephone", "mobile", "msisdn", "fax", "e164"), ()),
    (("postcode",),
     ("zipcode", "postcode", "postal_code", "postalcode"), ()),
    (("iban",),
     ("iban",), ()),
    (("credit_card_number",),
     ("credit_card", "card_number", "ccnumber", "cardnum"), ()),
)


def _ip_dotted(pat_l):
    """Loose 'this pattern targets a dotted IPv4' hint. Matches both the spelled-out form (three or more
    escaped dots) and the common repetition form `(...\\.){3}` / `{4}` -- one escaped dot, a `){3}`/`){4}`
    quantifier -- amongst digit runs. Best-effort only; the mandatory pattern match keeps a miss harmless."""
    if not ("[0-9]" in pat_l or r"\d" in pat_l) or r"\." not in pat_l:
        return False
    return pat_l.count(r"\.") >= 3 or "){3}" in pat_l or "){4}" in pat_l


def _faker_candidate_providers(pat_l, col_l):
    """Ordered, de-duplicated faker method names to try for this (pattern, column), or [] to defer."""
    out = []
    for methods, cols, subs in _NAMED_FORMATS:
        if any(c in col_l for c in cols) or any(s in pat_l for s in subs):
            out.extend(methods)
    if _ip_dotted(pat_l) and "ipv4" not in out:
        out.insert(0, "ipv4")
    seen, uniq = set(), []
    for m in out:
        if m not in seen:
            seen.add(m); uniq.append(m)
    return uniq


def _gen_faker(ctx):
    """Registry generator: a realistic, DETERMINISTIC value for a named-format regex CHECK, else None.
    No-op without the `faker` extra. Fires only for a regex whose column name or pattern names a known
    real-world format, and only returns a candidate that actually matches the pattern (and length)."""
    if not _FAKER_OK or ctx.kind != "regex" or not ctx.pattern:
        return None
    providers = _faker_candidate_providers(ctx.pattern.lower(), (ctx.col or "").lower())
    if not providers:
        return None
    try:
        rx = re.compile(ctx.pattern)
    except re.error:
        return None                    # can't self-check in Python -> defer rather than guess blind
    fake = _faker_instance()
    for meth in providers:
        fn = getattr(fake, meth, None)
        if fn is None:
            continue
        for k in range(_FAKER_TRIES):
            fake.seed_instance(_stable_seed(ctx.col, ctx.pattern, meth, k))
            try:
                val = str(fn())
            except Exception:
                break                  # provider unusable -> next provider
            if ctx.lens and not _len_ok(len(val), ctx.lens):
                continue
            if rx.search(val) is not None:
                return val
    return None


register_format_generator(_gen_faker, front=True)   # named formats prefer a realistic value; others defer
