"""No-DB unit tests for the bypass-surface classifiers (lint codes L011-L015).

Each classifier is the pure decision for ONE object given its catalog facts; the SQL layer in bypass.py only
gathers those facts. So every outcome (and every SAFE non-outcome) is asserted here without a database.
"""
from rlsautotest.bypass import (classify_view, classify_function, classify_role, classify_force,
                                 _SANCTIONED_BYPASS)

ALLOW = set(_SANCTIONED_BYPASS)


def _code(f):  return None if f is None else f[0]
def _sev(f):   return None if f is None else f[1]
def _codes(fs): return sorted(x[0] for x in fs)


# ---------------------------------------------------------------- L011 / L011b (views)
def test_view_definer_anon_over_rls_is_L011_critical():
    f = classify_view("v", "v", True, ["anon"], ["public.secrets"], False)
    assert _code(f) == "L011" and _sev(f) == "CRITICAL" and "secrets" in f[4]

def test_view_definer_authenticated_only_over_rls_is_L011_high():
    f = classify_view("v", "v", True, ["authenticated"], ["public.secrets"], False)
    assert _code(f) == "L011" and _sev(f) == "HIGH"

def test_matview_over_rls_is_L011_labeled_materialized():
    f = classify_view("mv", "m", True, ["anon"], ["public.secrets"], False)
    assert _code(f) == "L011" and "materialized view" in f[4]

def test_view_definer_reads_another_view_unresolved_is_L011b():
    f = classify_view("v", "v", True, ["anon"], [], True)
    assert _code(f) == "L011b" and _sev(f) == "MEDIUM"

def test_view_definer_over_nonrls_only_is_not_flagged():
    # FP fix: a definer view over only non-RLS base tables bypasses nothing.
    assert classify_view("v", "v", True, ["anon"], [], False) is None

def test_view_security_invoker_is_not_flagged():
    assert classify_view("v", "v", False, ["anon"], ["public.secrets"], False) is None

def test_view_definer_unreachable_is_not_flagged():
    assert classify_view("v", "v", True, [], ["public.secrets"], False) is None


# ---------------------------------------------------------------- L012 / L013 (SECURITY DEFINER functions)
def test_fn_anon_reads_rls_pinned_sp_is_L012_critical_only():
    fs = classify_function("f()", ["anon"], False, ["secrets"], False)
    assert _codes(fs) == ["L012"] and fs[0][1] == "CRITICAL"

def test_fn_anon_reads_rls_mutable_sp_is_L012_and_L013():
    fs = classify_function("f()", ["anon"], False, ["secrets"], True)
    d = {x[0]: x[1] for x in fs}
    assert _codes(fs) == ["L012", "L013"] and d["L012"] == "CRITICAL" and d["L013"] == "HIGH"

def test_fn_authenticated_only_reads_rls_is_L012_high():
    fs = classify_function("f()", ["authenticated"], False, ["secrets"], False)
    assert _codes(fs) == ["L012"] and fs[0][1] == "HIGH"

def test_fn_anon_opaque_body_is_L012_high_unresolved():
    fs = classify_function("f()", ["anon"], True, [], False)
    assert _codes(fs) == ["L012"] and fs[0][1] == "HIGH" and "opaque" in fs[0][4]

def test_fn_transparent_no_rls_table_is_not_flagged():
    # FP fix: a readable SQL function that provably touches no RLS table bypasses nothing.
    assert classify_function("f()", ["anon"], False, [], False) == []

def test_fn_unreachable_mutable_sp_is_L013_medium_only():
    fs = classify_function("f()", [], False, ["secrets"], True)
    assert _codes(fs) == ["L013"] and fs[0][1] == "MEDIUM"

def test_fn_reachable_transparent_but_mutable_is_L013_high_only():
    fs = classify_function("f()", ["anon"], False, [], True)
    assert _codes(fs) == ["L013"] and fs[0][1] == "HIGH"


# ---------------------------------------------------------------- L014 (roles)
def test_role_bypassrls_reachable_is_L014_critical():
    f = classify_role("badrole", False, True, True, ALLOW)
    assert _code(f) == "L014" and _sev(f) == "CRITICAL" and "BYPASSRLS" in f[4]

def test_role_bypassrls_unreachable_is_L014_high():
    f = classify_role("badrole", False, True, False, ALLOW)
    assert _code(f) == "L014" and _sev(f) == "HIGH"

def test_role_superuser_message_says_superuser():
    f = classify_role("badsuper", True, False, True, ALLOW)
    assert _code(f) == "L014" and "a superuser" in f[4]

def test_role_service_role_is_sanctioned():
    assert classify_role("service_role", False, True, False, ALLOW) is None

def test_role_user_allowlist_is_respected():
    assert classify_role("worker", False, True, True, ALLOW | {"worker"}) is None


# ---------------------------------------------------------------- L015 (RLS on, FORCE off)
def test_force_nonsuper_owner_is_L015_medium():
    f = classify_force("t", "app_owner", False, False)
    assert _code(f) == "L015" and _sev(f) == "MEDIUM"

def test_force_login_owner_is_L015_high():
    f = classify_force("t", "app_owner", False, True)
    assert _code(f) == "L015" and _sev(f) == "HIGH"

def test_force_client_owner_is_L015_high():
    f = classify_force("t", "authenticated", False, False)
    assert _code(f) == "L015" and _sev(f) == "HIGH"

def test_force_superuser_owner_is_not_flagged():
    assert classify_force("t", "postgres", True, True) is None
