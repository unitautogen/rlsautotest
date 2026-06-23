"""No-DB unit tests for the pure helpers (CI 'unit' job)."""
from rlsautotest.cli import (_split_statements, _is_uuid, setup_hook_sql, render_report_text, _SHIM,
                             _mock_valid_row, classify_node, _where, _check_value_set)


def test_split_respects_dollar_quotes():
    sql = "create function f() returns void language plpgsql as $$ begin perform 1; end $$; select 1;"
    parts = _split_statements(sql)
    assert len(parts) == 2


def test_is_uuid():
    assert _is_uuid("11111111-1111-1111-1111-111111111111")
    assert not _is_uuid("not-a-uuid")


def test_setup_hook_offline_shim_vs_basejump():
    offline = setup_hook_sql(False)
    assert "tests.authenticate_as" in offline and "tests.create_supabase_user" in offline
    assert "tests.authenticate_as" in _SHIM
    present = setup_hook_sql(True)
    assert "basejump" in present.lower()
    assert "create or replace function tests.authenticate_as" not in present.lower()


def test_mock_valid_row_synthesizes_fk_parent_and_required_cols():
    # Regression for the opaque-RBAC-gated-writes gap (a table whose every command delegates to an
    # opaque fn -> no base seed). The write-mock path must still build a valid row: fill required
    # (NOT NULL, no-default, non-identity) columns and seed the FK parent so the row is insertable.
    fkmap = {"rbac.creditors": {"team_id": ("rbac.teams", "id")}}
    colsmap = {
        # (name, type, notnull, hasdefault)
        "rbac.creditors": [("id", "bigint", True, True), ("team_id", "uuid", True, False),
                           ("name", "text", True, False), ("amount", "numeric", False, False)],
        "rbac.teams": [("id", "uuid", True, True), ("name", "text", True, False)],
    }
    parents, row = _mock_valid_row("rbac", "creditors", fkmap, colsmap, {})
    # required non-identity cols are filled; identity PK and nullable col are not forced
    assert "team_id" in row and "name" in row
    assert "id" not in row and "amount" not in row
    # the FK parent is seeded (with its own required 'name'), so the creditors row is insertable
    assert any("rbac.teams" in s for s in parents)
    assert any("name" in s for s in parents)


def test_classify_value_set_and_scalar_lookup():
    # Generality regression (examples/transitions.sql): the recognizer must understand the shapes a
    # role-gated state machine uses, instead of dead-ending at NOT_TESTABLE.
    # `col = ANY(array[consts])` is value-set membership (distinct from the auth.uid()=ANY(col) shape).
    a = classify_node(_where("status = ANY (array['Queued','In Cutting'])"), None)
    assert a["kind"] == "col_in_set" and a["col"] == "status"
    assert set(a["values"]) == {"Queued", "In Cutting"}
    # `col <> ALL(array[consts])` -> the complement
    b = classify_node(_where("status <> ALL (array['In Cutting','Completed'])"), None)
    assert b["kind"] == "col_not_in_set" and set(b["values"]) == {"In Cutting", "Completed"}
    # the Supabase "read my role from a profile table" scalar subquery must classify as scalar_lookup,
    # NOT a phantom row_const on the base table (regression: _unwrap collapses the EXPR_SUBLINK to 'role').
    c = classify_node(_where("(select role from profile where id = (select auth.uid())) = 'cutter'"), None)
    assert c["kind"] == "scalar_lookup"
    assert c["lcol"] == "role" and c["lkey"] == "id" and c["value"] == "cutter"


def test_check_value_set_parses_the_with_check_value_space():
    # gap 2: the per-policy WITH CHECK value-set the transition audit compares against.
    assert _check_value_set("status = 'In Cutting'") == ("status", frozenset(["In Cutting"]))
    col, vals = _check_value_set("status = ANY (array['a','b'])")
    assert col == "status" and vals == frozenset(["a", "b"])
    assert _check_value_set("owner = (select auth.uid())") is None   # identity link, not a value constraint


def test_report_render():
    reps = [{
        "table": "t", "rls_enabled": True, "policied": ["SELECT"],
        "cells": {"SELECT": {"grant": True, "deny": True}},
        "footguns": [], "coverage": [2, 2],
    }]
    out = render_report_text(reps)
    assert "t" in out and "SELECT" in out and "legend" in out
