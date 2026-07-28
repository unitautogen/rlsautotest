"""No-DB unit tests for the column-security classifier. The SQL layer only gathers facts; the whole
decision -- scoped / leak / unscoped, and the leaked set -- is a pure function asserted here.

Principle under test (same as the row-level leak): we flag a column grant that a BROADER grant bypasses,
and NOTHING else. No column is treated as "sensitive"; a bare table-wide grant (no column grant) is silent.
"""
from rlsautotest.colsec import cell_facts, COL_CMDS


# ---------------------------------------------------------------- unscoped (no intent -> silent)
def test_unscoped_when_no_column_grant():
    # bare table-wide grant: effective = every column, but NO column grant -> no intent -> silent
    f = cell_facts([], ["id", "name", "role", "is_admin", "tenant_id"])
    assert f["kind"] == "unscoped" and f["granted"] == [] and f["leaked"] == []

def test_unscoped_ignores_privilege_looking_names():
    # is_admin/tenant_id are effective, but with no column grant we express no opinion (no name heuristic)
    f = cell_facts([], ["id", "is_admin", "tenant_id"])
    assert f["kind"] == "unscoped" and f["leaked"] == []

def test_unscoped_when_nothing_effective_either():
    f = cell_facts([], [])
    assert f["kind"] == "unscoped"


# ---------------------------------------------------------------- scoped (grant intact -> green)
def test_scoped_when_effective_equals_granted():
    f = cell_facts(["display_name", "bio"], ["display_name", "bio"])
    assert f["kind"] == "scoped" and f["granted"] == ["display_name", "bio"] and f["leaked"] == []

def test_scoped_is_order_insensitive_on_membership():
    f = cell_facts(["bio", "display_name"], ["display_name", "bio"])
    assert f["kind"] == "scoped" and f["leaked"] == []

def test_scoped_single_column_grant():
    f = cell_facts(["name"], ["name"])
    assert f["kind"] == "scoped" and f["granted"] == ["name"]


# ---------------------------------------------------------------- leak (broader grant bypasses -> red)
def test_leak_when_table_wide_grant_bypasses_column_grant():
    # column grant scopes to (name) but a table-wide grant makes every column effective -> the rest leak
    f = cell_facts(["name"], ["id", "name", "role", "is_admin", "tenant_id"])
    assert f["kind"] == "leak"
    assert f["granted"] == ["name"]
    assert f["leaked"] == ["id", "role", "is_admin", "tenant_id"]

def test_leak_preserves_effective_column_order():
    f = cell_facts(["b"], ["a", "b", "c"])
    assert f["kind"] == "leak" and f["leaked"] == ["a", "c"]

def test_leak_single_extra_column():
    f = cell_facts(["a", "b"], ["a", "b", "secret"])
    assert f["kind"] == "leak" and f["leaked"] == ["secret"]


# ---------------------------------------------------------------- shape / contract
def test_col_cmds_are_the_column_grantable_three():
    # DELETE is whole-row: Postgres has no column-level DELETE privilege, so it is never a CLS command.
    assert COL_CMDS == ("SELECT", "INSERT", "UPDATE")

def test_granted_echoed_verbatim_on_leak():
    # the report needs the intent (granted) as faded context beside the leak
    f = cell_facts(["x", "y"], ["x", "y", "z"])
    assert f["granted"] == ["x", "y"]


# ---------------------------------------------------------------- cls_assertions (pgTAP parity)
from rlsautotest.colsec import cls_assertions


def _cells(kind, granted=(), leaked=(), cmd="UPDATE"):
    return {"authenticated": {cmd: {"kind": kind, "granted": list(granted), "leaked": list(leaked)}}}

def test_cls_assertion_emitted_for_scoped_and_leak():
    for kind in ("scoped", "leak"):
        a = cls_assertions("colsec", "accounts", _cells(kind, ["name"], ["id", "role"]))
        assert len(a) == 1 and a[0]["kind"] == kind
        assert a[0]["sql"].startswith("SELECT is(") and "has_column_privilege" in a[0]["sql"]

def test_cls_assertion_skips_unscoped():
    assert cls_assertions("s", "t", _cells("unscoped")) == []

def test_cls_assertion_targets_right_role_cmd_table_and_asserts_zero():
    a = cls_assertions("colsec", "accounts", _cells("leak", ["name"], ["id"]))[0]["sql"]
    assert "'colsec'" in a and "'accounts'" in a and "'authenticated'" in a and "'UPDATE'" in a
    assert "aclexplode" in a and ", 0," in a   # scope holds == zero columns reachable beyond the grant

def test_cls_assertion_names_leak_columns_in_message():
    a = cls_assertions("colsec", "accounts", _cells("leak", ["name"], ["id", "role", "is_admin"]))[0]["sql"]
    assert "emit-time leak: id, role, is_admin" in a

def test_cls_assertions_cover_select_insert_update_never_delete():
    cells = {"authenticated": {c: {"kind": "leak", "granted": ["x"], "leaked": ["y"]}
                               for c in ("SELECT", "INSERT", "UPDATE", "DELETE")}}
    cmds = {x["cmd"] for x in cls_assertions("s", "t", cells)}
    assert cmds == {"SELECT", "INSERT", "UPDATE"}

def test_cls_assertion_escapes_single_quotes_in_message():
    # a table/role with an apostrophe must not break the SQL literal (defensive)
    a = cls_assertions("s", "o'brien", _cells("leak", ["x"], ["y"]))[0]["sql"]
    assert "o''brien" in a
