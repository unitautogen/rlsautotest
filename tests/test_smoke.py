"""No-DB unit tests for the pure helpers (CI 'unit' job)."""
from rlsautotest.cli import (_split_statements, _is_uuid, setup_hook_sql, render_report_text, _SHIM,
                             _mock_valid_row, classify_node, _where, _check_value_set, _solve_predicate,
                             _bump_lit)


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


def test_solver_derives_witness_for_an_unseen_predicate():
    # The general "solve, don't classify" core: derive true/false witnesses for a predicate the named-shape
    # catalog does NOT recognize (a numeric JWT-claim threshold), by reading operand roles only.
    ct = {"sensitivity": "integer", "owner": "uuid"}
    plan = _solve_predicate(_where("(auth.jwt() ->> 'clearance')::int >= sensitivity"), ct, {})
    assert plan is not None
    sat, fal = plan
    claims_of = lambda ctx: {tuple(k): v for k, v in ctx["claims"]}
    # satisfier: high clearance, low sensitivity; falsifier: the reverse
    assert int(claims_of(sat)[("clearance",)]) > int(claims_of(fal)[("clearance",)])
    assert sat["row"].get("sensitivity") is not None and fal["row"].get("sensitivity") is not None
    # an opaque function call yields no witness -> stays honest (NOT_TESTABLE), never guessed
    assert _solve_predicate(_where("my_opaque_check(id)"), ct, {}) is None


def test_bump_lit_varies_per_salt_and_is_type_aware():
    # The probe-and-repair synthesizer repairs a UNIQUE violation by varying a column with _bump_lit;
    # successive salts must produce DISTINCT, type-valid literals (else the repair loops forever).
    assert _bump_lit("uuid", 1) != _bump_lit("uuid", 2)
    assert _bump_lit("integer", 1) != _bump_lit("integer", 2)
    assert _bump_lit("text", 1) != _bump_lit("text", 2)
    assert _bump_lit("integer", 7).isdigit()                 # numeric stays unquoted
    assert _bump_lit("text", 7).startswith("'")              # text stays quoted


def test_action_table_parses_the_target_relation():
    # The post-arrange invariant needs the relation an action touches, to check it was actually seeded.
    from rlsautotest.cli import _action_table
    assert _action_table("SELECT count(*) FROM tenancy.orgs") == "tenancy.orgs"
    assert _action_table("UPDATE s.t SET a=1") == "s.t"
    assert _action_table("INSERT INTO s.t(a) VALUES (1)") == "s.t"
    assert _action_table("DELETE FROM s.t") == "s.t"


def test_rls_off_cell_uses_per_command_grants():
    # An RLS-off table is a hole ONLY for commands the role is actually granted; a missing grant blocks it.
    # Regression: the cell must not blanket-assume full access (which over-stated data_rooms as ✓! on writes).
    from rlsautotest.cli import _id_cell
    rep = {"rls_enabled": False, "exposed": True, "grants": {
        ("authenticated", "SELECT"): True, ("authenticated", "INSERT"): False,
        ("authenticated", "UPDATE"): False, ("authenticated", "DELETE"): False,
        ("anon", "SELECT"): False, ("anon", "INSERT"): False, ("anon", "UPDATE"): False, ("anon", "DELETE"): False}}
    assert _id_cell(rep, "authorized", "SELECT")[1] == "danger"   # RLS off + SELECT grant -> unfiltered read = hole
    assert _id_cell(rep, "authorized", "INSERT")[1] == "none"     # not granted -> blocked, NOT a hole
    assert _id_cell(rep, "authorized", "DELETE")[1] == "none"
    assert _id_cell(rep, "anon", "SELECT")[1] == "none"           # anon ungranted -> no false read hole


def test_service_role_cell_respects_grants():
    # service_role bypasses RLS, but BYPASSRLS does NOT grant table privileges — the cell must reflect the
    # real grant. Regression for the audit finding (service_role was shown ✓ unconditionally).
    from rlsautotest.cli import _id_cell
    rep = {"rls_enabled": True, "policied": ["SELECT", "INSERT", "UPDATE", "DELETE"], "idgrid": {}, "grants": {
        ("service_role", "SELECT"): True, ("service_role", "INSERT"): False,
        ("service_role", "UPDATE"): False, ("service_role", "DELETE"): False}}
    assert _id_cell(rep, "service_role", "SELECT")[1] == "svc"     # granted -> full bypass
    assert _id_cell(rep, "service_role", "INSERT")[1] == "none"    # not granted -> even the service key is blocked
    assert _id_cell(rep, "service_role", "DELETE")[1] == "none"
    assert _id_cell({"rls_enabled": True}, "service_role", "INSERT")[1] == "svc"   # no grant map -> safe ✓ fallback


def test_wv_value_typing_is_db_valid_for_time_types():
    # The general solver must emit DB-valid witness values for non-text columns (timestamp/date), not a text
    # placeholder. Regression for the per-min-term solver (BL-1) failing to verify on timestamptz columns.
    from rlsautotest.cli import _wv_some, _wv_other, _wv_lit
    assert "2020" in _wv_some("timestamp with time zone", {})
    assert _wv_some("timestamp with time zone", {}) != _wv_other("timestamp with time zone", {})   # distinct sat/fal
    lit = _wv_lit("timestamp with time zone", _wv_some("timestamp with time zone", {}))
    assert lit.startswith("'") and lit.endswith("::timestamp with time zone")   # cast to the column type
    assert _wv_lit("integer", "5") == "5" and _wv_lit("text", "x") == "'x'"      # numerics unquoted, text quoted


def test_report_render():
    reps = [{
        "table": "t", "rls_enabled": True, "policied": ["SELECT"],
        "cells": {"SELECT": {"grant": True, "deny": True}},
        "footguns": [], "coverage": [2, 2],
    }]
    out = render_report_text(reps)
    assert "t" in out and "SELECT" in out and "legend" in out
