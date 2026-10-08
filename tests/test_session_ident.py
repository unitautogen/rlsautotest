"""No-DB unit tests for session-identity owner checks: `col = current_setting('x')` and `col = SESSION_USER`.

The live behaviour (both shapes 8/8, emitted suites green, and red once the policy is loosened to
USING (true)) is proven by the CI step on examples/sessionident.sql. These tests pin the pieces that need no
database: the classifier recognises both identity sources, the identity helpers emit the right session
statements in the right order, the emitted cleanup undoes them, and a JWT-only identity is byte-identical.
"""
import json

from rlsautotest.atoms import _cmd_dnf, build_class, classify_node
from rlsautotest.astutil import _where
from rlsautotest.structs import EmitContext


def _atom(expr, cur=None):
    return classify_node(_where(expr), cur)


def test_guc_owner_recognised_both_operand_orders_and_casts():
    for expr in ("tenant = current_setting('app.tenant', true)",
                 "current_setting('app.tenant'::text, true) = tenant",
                 "tenant_id = (current_setting('app.tenant', true))::uuid"):
        a = _atom(expr)
        assert a["kind"] == "guc_owner", expr
        assert a["keys"] == ["app.tenant"]


def test_guc_owner_class_is_rowlinked_and_carries_the_setting():
    c = build_class([_atom("tenant = current_setting('app.tenant', true)")], 0)
    assert c["handled"] and c["rowlinked"]
    assert c["guc_keys"] == ["app.tenant"]
    gv = c["claims"]["__rlsa_guc"]["app.tenant"]
    assert c["rowseed"]["tenant"] == f"'{gv}'"
    assert gv != c["claims"]["sub"]   # never mistaken for a JWT uid by the unique-owner INSERT path


def test_session_user_without_a_database_is_honestly_not_testable():
    a = _atom("ownr = SESSION_USER")
    assert a["kind"] == "unknown" and "connection" in a["text"]
    c = build_class([a], 0)
    assert not c["handled"]


def test_session_owner_class_acts_as_first_role_with_second_as_rival():
    from rlsautotest.structs import Atom
    c = build_class([Atom(kind="session_owner", col="ownr", values=["sid_alice", "sid_bob"])], 0)
    assert c["handled"] and c["rowlinked"]
    assert c["claims"]["__rlsa_session"] == "sid_alice"
    assert c["session_rival"] == "sid_bob"
    assert c["rowseed"]["ownr"] == "'sid_alice'"


def test_ident_orders_session_statements_and_strips_reserved_keys():
    ctx = EmitContext(helpers=False)
    cj = json.dumps({"sub": "x", "role": "authenticated", "exp": 1,
                     "__rlsa_guc": {"app.tenant": "T"}, "__rlsa_session": "sid_alice"})
    out = ctx.ident(cj, "authenticated")
    assert out[0] == 'SET LOCAL SESSION AUTHORIZATION sid_alice;'     # first: it resets the current role
    assert out[-1] == "SELECT set_config('app.tenant', 'T', true);"      # last: wins over any flat-claim GUC
    assert any(s.startswith("SET LOCAL ROLE authenticated") for s in out)
    assert not any("__rlsa_" in s for s in out)                          # never leaks into request.jwt.claims
    assert ctx.session_cleanup(cj) == ["RESET SESSION AUTHORIZATION;",
                                       "SELECT set_config('app.tenant', '', true);"]


def test_jwt_only_identity_is_byte_identical():
    ctx = EmitContext(helpers=False)
    cj = json.dumps({"sub": "11111111-1111-1111-1111-111111111111", "role": "authenticated"})
    assert ctx.ident(cj, "authenticated") == ctx._ident_jwt(cj, "authenticated")
    assert ctx.pident(cj, "authenticated") == ctx._pident_jwt(cj, "authenticated")
    assert ctx.session_cleanup(cj) == [] and ctx.session_cleanup("") == []


def test_policy_dnf_classifies_guc_policy_for_every_command():
    pols = [("tenant_iso", "PERMISSIVE", "ALL", ["public"], "(tenant = current_setting('app.tenant'::text, true))", None)]
    for cmd, clause in (("SELECT", 4), ("INSERT", 5), ("UPDATE", 4), ("DELETE", 4)):
        dnf, has_pol, _open, _srcs = _cmd_dnf(pols, cmd, clause, None)
        assert has_pol and [a["kind"] for a in dnf[0]] == ["guc_owner"], cmd
