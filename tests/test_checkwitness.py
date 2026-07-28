"""No-DB unit tests for the CHECK-aware seed value synthesis (rlsautotest.checkwitness).

These assert the CONSTRUCTION: the pure regex/LIKE/length generators, and the AST driver over
pg_get_constraintdef-style CHECK definitions. The constructed value is only a candidate; the seed probe
is the authoritative judge, so end-to-end behaviour (checkfmt greens, seedfail stays UNRELIABLE) is
proven by the regression corpus against a live database, not here.
"""
import re
from rlsautotest.checkwitness import _regex_witness, _like_witness, _fmt_check_witness, _len_pick


# ---------------------------------------------------------------- regex generator
def test_regex_fixed_digits():
    v = _regex_witness(r"^[0-9]{10}$")
    assert v is not None and re.search(r"^[0-9]{10}$", v) and len(v) == 10

def test_regex_structured_formats():
    for pat in (r"^[A-Z]{2}-[0-9]{4}$", r"^\d{3}-\d{4}$", r"^#[0-9a-f]{6}$", r"^[a-z]{3,8}$",
                r"^[^@]+@[^@]+\.[a-z]{2,}$"):
        v = _regex_witness(pat)
        assert v is not None and re.search(pat, v), pat

def test_regex_alternation_takes_first_branch():
    v = _regex_witness(r"^(foo|bar)$")
    assert v is not None and re.search(r"^(foo|bar)$", v)

def test_regex_backreference_is_unsupported():
    assert _regex_witness(r"^(.)\1$") is None
    assert _regex_witness(r"^([0-9])\1{9}$") is None

def test_regex_lookaround_is_unsupported():
    assert _regex_witness(r"^(?=.*[0-9]).{8,}$") is None

def test_regex_empty_or_none():
    assert _regex_witness("") is None
    assert _regex_witness(None) is None


# ---------------------------------------------------------------- LIKE generator
def test_like_prefix():
    assert _like_witness("doc-%") == "doc-"

def test_like_underscore_is_one_char():
    v = _like_witness("a_c")
    assert len(v) == 3 and v[0] == "a" and v[2] == "c"


# ---------------------------------------------------------------- length picker
def test_len_pick_range_takes_lower_bound():
    assert _len_pick([(">=", 5), ("<=", 100)]) == 5

def test_len_pick_exact():
    assert _len_pick([("=", 8)]) == 8

def test_len_pick_unsatisfiable():
    assert _len_pick([(">=", 10), ("<=", 5)]) is None


# ---------------------------------------------------------------- AST driver over CHECK definitions
def test_fmt_witness_regex_cdef():
    w = _fmt_check_witness("CHECK ((code ~ '^[0-9]{10}$'::text))")
    assert w and w[0] == "code" and re.search(r"^[0-9]{10}$", w[1])

def test_fmt_witness_like_cdef():
    w = _fmt_check_witness("CHECK ((slug ~~ 'doc-%'::text))")
    assert w and w[0] == "slug" and w[1].startswith("doc-")

def test_fmt_witness_length_cdef():
    w = _fmt_check_witness("CHECK (((char_length(note) >= 5) AND (char_length(note) <= 40)))")
    assert w and w[0] == "note" and 5 <= len(w[1]) <= 40

def test_fmt_witness_backreference_returns_none():
    assert _fmt_check_witness(r"CHECK ((code ~ '^([0-9])\1{9}$'::text))") is None

def test_fmt_witness_valueset_is_deferred():
    # a value-set CHECK (col = ANY(...)) is handled by _check_seed_meta, not the format witness path
    assert _fmt_check_witness("CHECK ((status = ANY (ARRAY['a'::text, 'b'::text])))") is None

def test_fmt_witness_multicolumn_or_unknown_returns_none():
    # cross-column comparison is not a single-column format/length shape -> None here
    assert _fmt_check_witness("CHECK ((lo < hi))") is None
