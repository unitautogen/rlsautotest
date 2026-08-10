"""No-DB unit tests for MB-25: --allow-unreliable / .rlsautotestignore sanctioning of UNRELIABLE cells.

A sanctioned cell must (a) parse and resolve by [schema.]table[:CMD], (b) bake a pgTAP SKIP instead of a
fail() -- never a passing assertion, so an untrustworthy result is still not asserted -- and (c) let the
report exit gate go green while every UN-sanctioned UNRELIABLE cell still fails. All provable without a DB.
"""
import pytest

from rlsautotest.cli import _parse_allow_unreliable, _sanctioned_cmds_for
from rlsautotest.probe import ProbeBaker
from rlsautotest.structs import EmitContext


# ---------------------------------------------------------------- parser + resolver
def test_parse_bare_table_is_all_four_commands():
    s = _parse_allow_unreliable(["orders"])
    assert s[(None, "orders")] == {"SELECT", "INSERT", "UPDATE", "DELETE"}


def test_parse_table_command_and_schema_qualified_case_insensitive():
    s = _parse_allow_unreliable(["invoices:INSERT", "analytics.events:update"])
    assert s[(None, "invoices")] == {"INSERT"}
    assert s[("analytics", "events")] == {"UPDATE"}   # 'update' upper-cased


def test_parse_merges_flag_and_ignorefile_skipping_comments_and_blanks():
    s = _parse_allow_unreliable(["orders:SELECT"], ["# a comment", "", "  ", "orders:DELETE", "audit.logs"])
    assert s[(None, "orders")] == {"SELECT", "DELETE"}                      # two entries on one table union
    assert s[("audit", "logs")] == {"SELECT", "INSERT", "UPDATE", "DELETE"}  # bare -> all four


def test_parse_rejects_a_non_command():
    with pytest.raises(ValueError):
        _parse_allow_unreliable(["orders:TRUNCATE"])


def test_resolver_none_schema_matches_any_but_qualified_is_exact():
    s = _parse_allow_unreliable(["orders", "analytics.events:SELECT"])
    assert _sanctioned_cmds_for(s, "public", "orders") == {"SELECT", "INSERT", "UPDATE", "DELETE"}
    assert _sanctioned_cmds_for(s, "whatever", "orders") == {"SELECT", "INSERT", "UPDATE", "DELETE"}
    assert _sanctioned_cmds_for(s, "analytics", "events") == {"SELECT"}
    assert _sanctioned_cmds_for(s, "public", "events") is None    # right table, wrong schema
    assert _sanctioned_cmds_for(s, "public", "nope") is None
    assert _sanctioned_cmds_for(None, "public", "orders") is None  # nothing sanctioned -> None (byte-identical default)
    assert _sanctioned_cmds_for({}, "public", "orders") is None


# ---------------------------------------------------------------- emit: sanctioned -> SKIP, never fail()/pass
def _baker(sanctioned):
    ctx = EmitContext(q='"public"."t"', sanctioned_unreliable=sanctioned)
    return ProbeBaker(ctx), ctx


def test_sanctioned_select_bakes_skip_not_fail():
    baker, ctx = _baker({"SELECT"})
    sql = baker.read_assert(("count", 0, "seeded 0 rows in public.t. Fix: give a conforming row"),
                            "authenticated, authorized", ident="authorized")
    assert "SELECT skip(" in sql and "SELECT fail(" not in sql
    assert "UNRELIABLE (sanctioned)" in sql
    assert "seeded 0 rows" in sql                 # the cause is still carried (visible, explained)
    assert ctx.observations[-1].kind == "unreliable" and ctx.observations[-1].sanctioned is True


def test_unsanctioned_command_still_fails_when_a_different_command_is_sanctioned():
    baker, ctx = _baker({"SELECT"})               # only SELECT sanctioned
    sql = baker.write_assert(("rows", 0, "seeded 0 rows. Fix: x"), "INSERT",
                             'INSERT INTO "public"."t" DEFAULT VALUES', "authenticated, authorized", ident="authorized")
    assert "SELECT fail(" in sql and "SELECT skip(" not in sql
    assert ctx.observations[-1].sanctioned is False


def test_write_sanctioned_bakes_skip():
    baker, ctx = _baker({"DELETE"})
    sql = baker.write_assert(("rows", 0, "seeded 0 rows. Fix: x"), "DELETE",
                             'DELETE FROM "public"."t"', "authenticated, authorized", ident="authorized")
    assert "SELECT skip(" in sql and "SELECT fail(" not in sql
    assert ctx.observations[-1].sanctioned is True


def test_no_sanction_is_the_plain_fail_line():
    baker, ctx = _baker(None)
    sql = baker.read_assert(("count", 0, "seeded 0 rows. Fix: x"), "authenticated, authorized", ident="authorized")
    assert sql.startswith("SELECT fail( ") and "skip(" not in sql
    assert ctx.observations[-1].sanctioned is False


def test_sanction_never_turns_a_real_cell_green():
    # a sanctioned command must NOT affect a normal (trustworthy) observation -- it only ever downgrades a
    # would-be fail() UNRELIABLE line to a SKIP, never fabricates a passing assertion.
    baker, _ = _baker({"SELECT"})
    sql = baker.read_assert(("count", 3, None), "authenticated, authorized", ident="authorized")  # o[2] None = real cell
    assert "SELECT is(" in sql and "skip(" not in sql and "fail(" not in sql
