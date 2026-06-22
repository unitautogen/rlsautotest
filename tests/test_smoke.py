"""No-DB unit tests for the pure helpers (CI 'unit' job)."""
from rlsautotest.cli import _split_statements, _is_uuid, setup_hook_sql, render_report_text, _SHIM


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


def test_report_render():
    reps = [{
        "table": "t", "rls_enabled": True, "policied": ["SELECT"],
        "cells": {"SELECT": {"grant": True, "deny": True}},
        "footguns": [], "coverage": [2, 2],
    }]
    out = render_report_text(reps)
    assert "t" in out and "SELECT" in out and "legend" in out
