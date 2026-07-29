# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""No-DB unit tests for the OPTIONAL Faker-backed named-format seed generator (rlsautotest.checkwitness).

Faker only PROPOSES a candidate; the seed probe is the authoritative judge. So these assert the
construction contract, not end-to-end greening (that is proven by the live regression corpus):
  * a realistic value that actually matches the column's own pattern, for named formats -- including
    a look-around the built-in constructor cannot build;
  * determinism (same column+pattern -> same value, independent of PYTHONHASHSEED / call order);
  * and -- crucially -- that it DEFERS (returns None) on generic patterns and non-regex shapes, so the
    built-in regex/LIKE/length constructors stay byte-identical and the checkfmt baseline is untouched.
"""
import re
import pytest

pytest.importorskip("faker")   # this module is entirely about the optional `faker` extra

from rlsautotest import checkwitness as cw
from rlsautotest.checkwitness import _gen_faker, _fmt_check_witness, FmtCtx


EMAIL          = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
EMAIL_LOOKAHEAD = r"^(?=.{6,254}$)[^@\s]+@[^@\s]+\.[a-z]{2,}$"   # the built-in constructor returns None here
URL            = r"^https?://[^\s/$.?#][^\s]*$"
IPV4_SPELLED   = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
IPV4_REPEAT    = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"             # one literal \. + a {3} quantifier
MAC            = r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"
UUID           = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
SLUG           = r"^[a-z0-9]+(?:-[a-z0-9]+)*$"


def _fx(col, pattern, lens=None):
    return FmtCtx(col=col, coltype="text", kind="regex", pattern=pattern, lens=lens or [])


# ---------------------------------------------------------------- named formats produce matching values
@pytest.mark.parametrize("col,pat", [
    ("email", EMAIL),
    ("contact_email", EMAIL_LOOKAHEAD),
    ("website", URL),
    ("client_ip", IPV4_SPELLED),
    ("mac_address", MAC),
    ("row_uuid", UUID),
    ("slug", SLUG),
])
def test_named_format_matches_pattern(col, pat):
    v = _gen_faker(_fx(col, pat))
    assert v is not None, (col, pat)
    assert re.search(pat, v), (col, pat, v)


def test_ipv4_detected_by_pattern_when_column_is_generic():
    # neither column name names an IP; the dotted-quad pattern alone drives detection, both spellings
    for pat in (IPV4_SPELLED, IPV4_REPEAT):
        v = _gen_faker(_fx("addr", pat))
        assert v is not None and re.search(pat, v), pat


def test_email_value_is_realistic_not_minimal():
    v = _gen_faker(_fx("email", EMAIL))
    assert v and v.count("@") == 1 and "." in v.split("@")[1]
    assert v not in ("a@a.aa", "aa@aa.aa", "0@0.aa")   # a real faker draw, not the minimal constructor


# ---------------------------------------------------------------- determinism
def test_deterministic_same_col_and_pattern():
    assert _gen_faker(_fx("email", EMAIL)) == _gen_faker(_fx("email", EMAIL))
    assert _gen_faker(_fx("client_ip", IPV4_SPELLED)) == _gen_faker(_fx("client_ip", IPV4_SPELLED))


# ---------------------------------------------------------------- DEFERS: built-ins keep ownership
def test_defers_on_generic_patterns_so_builtins_win():
    # exactly the checkfmt corpus shapes -> faker must not fire, so the deterministic constructor owns them
    assert _gen_faker(_fx("code", r"^[0-9]{10}$")) is None
    assert _gen_faker(_fx("sku", r"^[A-Z]{2}-[0-9]{4}$")) is None
    assert _gen_faker(_fx("serial4", r"^([0-9])\1{3}$")) is None


def test_defers_on_non_regex_kinds():
    assert _gen_faker(FmtCtx(col="email", kind="like", pattern="%@%")) is None
    assert _gen_faker(FmtCtx(col="email", kind=None, pattern=None, lens=[(">=", 5)])) is None
    assert _gen_faker(FmtCtx(col="email", kind="regex", pattern=None)) is None


def test_length_bound_respected():
    # no realistic email fits in <= 6 chars, so the generator defers rather than emit a non-conforming value
    v = _gen_faker(_fx("email", EMAIL, lens=[("<=", 6)]))
    assert v is None or len(v) <= 6


# ---------------------------------------------------------------- AST driver, with faker registered
def test_fmt_witness_rescues_lookaround_email():
    w = _fmt_check_witness("CHECK ((contact_email ~ '%s'::text))" % EMAIL_LOOKAHEAD)
    assert w is not None and w[0] == "contact_email" and re.search(EMAIL_LOOKAHEAD, w[1])


def test_fmt_witness_named_email_is_realistic():
    # front registration: a named format prefers the realistic faker value over the minimal construction
    w = _fmt_check_witness("CHECK ((email ~ '%s'::text))" % EMAIL)
    assert w is not None and w[0] == "email" and re.search(EMAIL, w[1])
    assert w[1] not in ("a@a.aa", "aa@aa.aa", "0@0.aa")


def test_generic_lookaround_still_returns_none():
    # a NON-named look-around (password-style) stays honestly UNRELIABLE: faker must not over-fire
    assert _fmt_check_witness(r"CHECK ((code ~ '^(?=.*[0-9]).{8,}$'::text))") is None


# ---------------------------------------------------------------- graceful no-op without the extra
def test_no_op_when_faker_missing(monkeypatch):
    monkeypatch.setattr(cw, "_FAKER_OK", False)
    assert _gen_faker(_fx("email", EMAIL)) is None
