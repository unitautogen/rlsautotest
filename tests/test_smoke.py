"""No-DB unit tests for the pure helpers (CI 'unit' job)."""
from rlsautotest.cli import (_split_statements, _is_uuid, setup_hook_sql, render_report_text, _SHIM,
                             _mock_valid_row, classify_node, _where, _check_value_set, _solve_predicate,
                             _bump_lit, _explain_dashes, _dnf_ast, _t, _v)


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


def test_solver_witnesses_array_overlap_and_containment():
    # WB-1: array overlap/containment witnesses. The solver must build an array-valued row that satisfies the
    # predicate and one that doesn't (DB-verified downstream); a non-array column yields no witness (stays NT).
    from rlsautotest.cli import _solve_predicate, _array_elem_type, _pg_array_literal
    assert _array_elem_type("text[]") == "text" and _array_elem_type("uuid[]") == "uuid"
    assert _array_elem_type("text") is None                     # not an array type
    assert _pg_array_literal(["vip", "beta"]) == "{vip,beta}" and _pg_array_literal([]) == "{}"
    ct = {"tags": "text[]", "roles": "text[]", "perms": "text[]"}
    sat, fal = _solve_predicate(_where("tags && array['vip','beta']"), ct, {})   # overlap
    assert "vip" in sat["row"]["tags"] and fal["row"]["tags"] == "{}"            # share an element vs empty (disjoint)
    sat, fal = _solve_predicate(_where("roles @> array['admin']"), ct, {})       # col contains all
    assert "admin" in sat["row"]["roles"] and fal["row"]["roles"] == "{}"
    sat, fal = _solve_predicate(_where("perms <@ array['read','write','admin']"), ct, {})   # col subset-of
    assert sat["row"]["perms"] == "{read}" and "rls_x" in fal["row"]["perms"]    # a subset vs a set with an outside element
    # column-on-the-right (`ARRAY @> col`) flips to <@ and still solves
    sat, fal = _solve_predicate(_where("array['admin','root'] @> roles"), ct, {})
    assert sat is not None and fal is not None
    # a non-array column under an array operator -> no witness (honest NT, not a guess)
    assert _solve_predicate(_where("name @> array['x']"), {"name": "text"}, {}) is None


def test_solver_witnesses_function_on_column_preimage():
    # WB-2: many-to-one fn(col)=const. The solver can't seed col:=target; it builds a column value whose IMAGE
    # equals the target (sat) and one whose image differs (fal). DB-verified downstream; non-invertible -> NT.
    from rlsautotest.cli import _solve_predicate
    sat, fal = _solve_predicate(_where("substring(code, 1, 3) = 'ABC'"), {"code": "text"}, {})
    assert sat["row"]["code"].startswith("ABC") and not fal["row"]["code"].startswith("ABC")
    sat, fal = _solve_predicate(_where("left(name, 1) = 'A'"), {"name": "text"}, {})
    assert sat["row"]["name"].startswith("A") and not fal["row"]["name"].startswith("A")
    # date_trunc: the column is the SECOND argument; sat = the aligned target itself
    sat, fal = _solve_predicate(_where("date_trunc('day', created_at) = timestamp '2026-06-15'"),
                                {"created_at": "timestamp without time zone"}, {})
    assert sat["row"]["created_at"].startswith("2026-06-15") and not fal["row"]["created_at"].startswith("2026-06-15")
    # to_char 'YYYY-MM' -> seed a date inside the target month
    sat, fal = _solve_predicate(_where("to_char(created_at, 'YYYY-MM') = '2026-06'"),
                                {"created_at": "timestamp without time zone"}, {})
    assert sat["row"]["created_at"].startswith("2026-06")
    # a non-invertible function -> no witness (honest NT, never a guess)
    assert _solve_predicate(_where("md5(token) = 'deadbeef'"), {"token": "text"}, {}) is None


def test_solver_witnesses_noncanonical_subquery():
    # WB-3: subqueries the canonical membership atom can't model. The solver must seed the extra condition /
    # both correlations into the aux row; a join (multi-table) in the subquery stays honest NT.
    from rlsautotest.cli import _solve_predicate
    ct = {"org_id": "uuid", "a": "uuid", "b": "uuid", "id": "uuid"}
    # extra condition role='admin' -> seeded into the aux membership row
    sat, fal = _solve_predicate(_where(
        "exists (select 1 from memberships m where m.org_id = t.org_id and m.user_id = (select auth.uid()) and m.role = 'admin')"), ct, {})
    aux = sat["aux"][0]["cols"]
    assert aux.get("role") == "admin" and "user_id" in aux and "org_id" in aux
    assert sat["row"]["org_id"] != fal["row"]["org_id"]            # fal points the correlation at a no-match value
    # two correlations -> both seeded (outer row + aux row)
    sat2, _ = _solve_predicate(_where("exists (select 1 from links l where l.a = t.a and l.b = t.b)"), ct, {})
    assert "a" in sat2["row"] and "b" in sat2["row"] and {"a", "b"} <= set(sat2["aux"][0]["cols"])
    # a multi-table (join) subquery -> not modeled -> None (honest NT, never a guess)
    assert _solve_predicate(_where(
        "exists (select 1 from links l join other o on o.id = l.a where l.b = t.b)"), ct, {}) is None


def test_solver_witnesses_is_distinct_from():
    # BL-8: null-safe operators. IS DISTINCT FROM = null-safe <> (negation of equality); IS NOT DISTINCT FROM
    # = null-safe = (equality). Currently NT in the classifier; the solver routes them through _solve_eq.
    from rlsautotest.cli import _solve_predicate, _WV_UID
    ct = {"owner_id": "uuid"}
    sat, fal = _solve_predicate(_where("owner_id is distinct from (select auth.uid())"), ct, {})
    assert sat["row"]["owner_id"] != _WV_UID and fal["row"]["owner_id"] == _WV_UID   # distinct: sat NOT mine, fal mine
    sat2, fal2 = _solve_predicate(_where("owner_id is not distinct from (select auth.uid())"), ct, {})
    assert sat2["row"]["owner_id"] == _WV_UID and fal2["row"]["owner_id"] != _WV_UID  # not-distinct: sat mine, fal not


def test_input_signature_collectors_for_construct_first_floor():
    # BL-5/BL-6: the construct-first floor collects the free row column(s) and the literal operands of a
    # predicate, so it can vary the column over candidates (including the predicate's own constants) and let
    # the DB judge true/false for an operator it has no specific code for.
    from rlsautotest.cli import _expr_cols, _expr_consts, _candidate_values
    ct = {"name": "text", "n": "integer"}
    assert _expr_cols(_where("starts_with(name, 'Admin')"), ct) == ["name"]
    assert "Admin" in _expr_consts(_where("starts_with(name, 'Admin')"))
    assert _expr_cols(_where("(n % 2) = 0"), ct) == ["n"]
    assert "Admin" in _candidate_values("text", {}) and None in _candidate_values("text", {})
    assert "2" in _candidate_values("integer", {})


def test_dnf_pushes_not_inward_de_morgan():
    # BL-3: NOT is pushed inward so NOT-of-compound becomes separate min-terms the per-branch solver can witness.
    nots = lambda m: _t(m[0]) == "BoolExpr" and _v(m[0]).get("boolop") == "NOT_EXPR"
    mts = _dnf_ast(_where("NOT (a = 1 AND b = 2)"))            # -> (NOT a=1) OR (NOT b=2): two 1-leaf min-terms
    assert len(mts) == 2 and all(len(m) == 1 and nots(m) for m in mts)
    mts2 = _dnf_ast(_where("NOT (a = 1 OR b = 2)"))            # -> (NOT a=1) AND (NOT b=2): one 2-leaf min-term
    assert len(mts2) == 1 and len(mts2[0]) == 2
    mts3 = _dnf_ast(_where("NOT (NOT (a = 1))"))               # -> a = 1 (double negation cancels, no NOT wrapper)
    assert len(mts3) == 1 and len(mts3[0]) == 1 and _t(mts3[0][0]) == "A_Expr"


def test_claim_paths_collects_jwt_keys_for_joint_search():
    # BL-11: the joint search collects every JWT claim path the predicate reads so it can vary the SESSION,
    # not just the row. (A claim ref is a leaf — not recursed into.)
    from rlsautotest.cli import _claim_paths
    assert _claim_paths(_where("(auth.jwt()->>'dept') = name")) == [["dept"]]
    assert _claim_paths(_where("(auth.jwt()->'app_metadata'->>'org')::uuid = org_id")) == [["app_metadata", "org"]]
    assert _claim_paths(_where("a = b")) == []   # no claim referenced


def test_subquery_tables_extracts_seed_plan_for_relational_state_floor():
    # BL-12: the relational-state floor finds each single-table subquery a policy reads and how to seed a row it
    # would count (identity col `= auth.uid()`, extra equalities, the aggregated column for sum/avg), so it can
    # vary the CARDINALITY and let Postgres evaluate the real aggregate. Bails (-> NT) on multi-table joins.
    from rlsautotest.cli import _subquery_tables
    s = _subquery_tables(_where("(select count(*) from events e where e.owner = (select auth.uid())) >= 3"))
    assert len(s) == 1 and s[0]["mtable"] == "events" and s[0]["uid"] == "owner"
    s2 = _subquery_tables(_where("(select sum(amount) from orders o where o.owner = (select auth.uid())) >= 100"))
    assert s2 and s2[0]["uid"] == "owner" and s2[0]["num"] == ["amount"]    # aggregated col noted -> seeded large
    s3 = _subquery_tables(_where("(select count(*) from m where m.uid = (select auth.uid()) and m.role = 'admin') > 0"))
    assert s3 and s3[0]["extras"].get("role") == "admin"                    # extra equality carried into the seed
    assert _subquery_tables(_where("(select count(*) from a join b on a.id = b.aid) >= 1")) == []  # join -> not seedable


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


def test_explain_dashes_catches_unexplained_dash():
    # The 'NT can never go silent' guarantee: a policied command with a '–' (no idgrid entry) and NO
    # unhandled-class reason — i.e. a row the engine couldn't synthesize / a fallback coverage gap — must
    # still get a loud footgun, not a silent dash.
    rep = {"rls_enabled": True, "policied": ["SELECT"], "idgrid": {}, "unreliable_cells": set()}
    per = {"SELECT": {"classes": [{"handled": True}]}}                 # predicate handled, so no reason
    out = _explain_dashes(rep, per, [])
    assert any("no established cause" in n for n in out)               # catch-all fired
    assert not any("NOT TESTABLE" in n for n in out)                  # not the reason-based note


def test_explain_dashes_uses_reason_when_present():
    # A '–' whose command carries an unhandled-atom reason (e.g. an exotic operator) is explained by the
    # NOT TESTABLE note naming the reason — NOT the generic catch-all.
    rep = {"rls_enabled": True, "policied": ["SELECT"], "idgrid": {}, "unreliable_cells": set()}
    per = {"SELECT": {"classes": [{"handled": False, "reason": "unhandled atom: ~ pattern on email"}]}}
    out = _explain_dashes(rep, per, [])
    assert any("NOT TESTABLE" in n and "~ pattern on email" in n for n in out)
    assert not any("no established cause" in n for n in out)           # reason present -> not the catch-all


def test_explain_dashes_excludes_update_no_neutral_and_covered_cells():
    # (a) UPDATE-'–' when there's no policy-neutral column already prints its own note -> the catch-all must
    #     NOT double-report it.
    rep_u = {"rls_enabled": True, "policied": ["UPDATE"], "idgrid": {}, "unreliable_cells": set()}
    notes = ["UPDATE not fully tested - no policy-neutral column to modify (every column is PK / FK ...)"]
    assert _explain_dashes(rep_u, {"UPDATE": {"classes": [{"handled": True}]}}, notes) == []
    # (b) a fully-covered table (every cell has an idgrid verdict) yields NO dash footgun at all.
    rep_ok = {"rls_enabled": True, "policied": ["SELECT"], "unreliable_cells": set(),
              "idgrid": {"SELECT": {"authorized": {"exp": True, "pass": True},
                                    "other": {"exp": True, "pass": True},
                                    "anon": {"exp": False, "pass": True}}}}
    assert _explain_dashes(rep_ok, {"SELECT": {"classes": [{"handled": True}]}}, []) == []


def test_report_render():
    reps = [{
        "table": "t", "rls_enabled": True, "policied": ["SELECT"],
        "cells": {"SELECT": {"grant": True, "deny": True}},
        "footguns": [], "coverage": [2, 2],
    }]
    out = render_report_text(reps)
    assert "t" in out and "SELECT" in out and "legend" in out
