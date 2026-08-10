"""No-DB unit tests for MB-9b: a PROBED client role that itself carries BYPASSRLS.

Probing the row-level matrix AS a role that bypasses RLS sees every row regardless of policy, so its
observations are meaningless -- the baker MUST degrade those cells to a loud UNRELIABLE (never a green
pass), while the sanctioned service_role bypass row stays a normal observed cell. There is no corpus
fixture for this (no client role in the example schemas carries BYPASSRLS, and a cluster-level BYPASSRLS
role cannot be added to the shared regression database safely), so the behaviour is proven here without a
database: a real EmitContext + ProbeBaker with bypass_probed set, plus the pure probed_bypassrls helper.
"""
from rlsautotest.structs import EmitContext
from rlsautotest.probe import ProbeBaker
from rlsautotest.catalog import probed_bypassrls


def _baker(bypass_probed, unauth_role="anon"):
    ctx = EmitContext(q='"public"."t"', bypass_probed=bypass_probed, unauth_role=unauth_role)
    return ProbeBaker(ctx), ctx


# ---------------------------------------------------------------- read_assert (SELECT)
def test_read_authorized_bypassrls_role_is_unreliable_not_green():
    baker, ctx = _baker({"authenticated"})
    sql = baker.read_assert(("count", 1, None), "authenticated, authorized", ident="authorized")
    assert "fail(" in sql and "BYPASSRLS" in sql and "UNRELIABLE" in sql
    assert ctx.observations[-1].kind == "unreliable"
    # the message must carry a specific, actionable Fix for THIS cause -- not the old blanket seeding advice
    assert "Fix:" in sql and "NOBYPASSRLS" in sql
    assert "investigate seeding" not in sql


def test_read_service_role_bypass_is_exempt_and_green():
    # the sanctioned bypass row must stay a normal observed cell (showing it bypasses IS the point)
    baker, ctx = _baker({"authenticated", "service_role"})
    sql = baker.read_assert(("count", 3, None), "service_role", ident="service_role")
    assert "fail(" not in sql and "is(" in sql
    assert ctx.observations[-1].kind == "cell"


def test_read_no_bypass_is_green_byte_identical_path():
    baker, ctx = _baker(set())
    sql = baker.read_assert(("count", 1, None), "authenticated, authorized", ident="authorized")
    assert "fail(" not in sql and "is(" in sql
    assert ctx.observations[-1].kind == "cell"


def test_read_anon_maps_to_custom_unauth_role():
    # a custom unauth role name that bypasses -> the anon-identity cell is UNRELIABLE
    baker, _ = _baker({"visitor"}, unauth_role="visitor")
    sql = baker.read_assert(("count", 5, None), "visitor", ident="anon")
    assert "fail(" in sql and "BYPASSRLS" in sql


def test_read_anon_not_flagged_when_only_authenticated_bypasses():
    baker, _ = _baker({"authenticated"}, unauth_role="anon")
    sql = baker.read_assert(("count", 0, None), "anon", ident="anon")
    assert "fail(" not in sql   # the unauth role ('anon') is not in the bypass set


# ---------------------------------------------------------------- write_assert (INSERT/UPDATE/DELETE)
def test_write_authorized_bypassrls_role_is_unreliable():
    baker, ctx = _baker({"authenticated"})
    sql = baker.write_assert(("rows", 1, None), "INSERT", 'INSERT INTO "public"."t" DEFAULT VALUES',
                             "authenticated, authorized", ident="authorized")
    assert "fail(" in sql and "BYPASSRLS" in sql and "Fix:" in sql and "NOBYPASSRLS" in sql
    assert ctx.observations[-1].kind == "unreliable"


def test_write_service_role_is_exempt_green():
    baker, _ = _baker({"authenticated", "service_role"})
    sql = baker.write_assert(("rows", 1, None), "INSERT", 'INSERT INTO "public"."t" DEFAULT VALUES',
                             "service_role", ident="service_role")
    assert "fail(" not in sql and "isnt_empty(" in sql


def test_write_none_ident_defaults_to_authenticated_and_is_guarded():
    # specialized branches probe as the literal 'authenticated' role with ident=None -> still guarded
    baker, _ = _baker({"authenticated"})
    sql = baker.write_assert(("rows", 1, None), "INSERT", 'INSERT INTO "public"."t" DEFAULT VALUES',
                             "authenticated, no policy", ident=None)
    assert "fail(" in sql and "BYPASSRLS" in sql


def test_write_pre_existing_unreliable_is_left_untouched():
    # a genuine seed/precondition failure must not be masked or re-labelled by the bypass guard
    baker, _ = _baker({"authenticated"})
    sql = baker.write_assert(("err", "23505", "seed collided"), "INSERT", "INSERT ...",
                             "authenticated, authorized", ident="authorized")
    assert "fail(" in sql and "seed collided" in sql and "BYPASSRLS" not in sql


def test_write_non_42501_constraint_synthesizes_unreliable_with_fix():
    # a non-42501 error with NO prior reason = the probe's own synthesized value tripped a table
    # CHECK/constraint (not a policy denial). write_assert synthesizes an UNRELIABLE carrying a specific
    # Fix (give the column a CHECK-satisfying value), not the old blanket 'investigate seeding'.
    baker, ctx = _baker(set())
    sql = baker.write_assert(("err", "23514", None), "INSERT", 'INSERT INTO "public"."t" DEFAULT VALUES',
                             "authenticated, authorized", ident="authorized")
    assert "fail(" in sql and "23514" in sql and "Fix:" in sql
    assert "CHECK" in sql and "constraint" in sql          # the cause is named, not mislabelled as a denial
    assert "investigate seeding" not in sql
    assert ctx.observations[-1].kind == "unreliable"


# ---------------------------------------------------------------- probed_bypassrls helper (fake cursor, no DB)
class _FakeCur:
    def __init__(self, rows):
        self._rows = rows
        self.q = None
        self.args = None

    def execute(self, q, args=None):
        self.q = q
        self.args = args

    def fetchall(self):
        return self._rows


def test_probed_bypassrls_empty_or_falsy_roles_makes_no_query():
    cur = _FakeCur([])
    assert probed_bypassrls(cur, [None, "", None]) == set()
    assert cur.q is None   # short-circuits without touching the database


def test_probed_bypassrls_dedups_and_returns_bypassing_subset():
    cur = _FakeCur([("authenticated",)])
    out = probed_bypassrls(cur, ["authenticated", "anon", "authenticated"])
    assert out == {"authenticated"}
    assert cur.args == (["authenticated", "anon"],)   # de-duped, order preserved


# ---------------------------------------------------------------- UNRELIABLE message format (per-cause Fix, no blanket tail)
def test_unrel_fail_carries_cause_fix_and_drops_blanket_seeding_tail():
    from rlsautotest.probe import _unrel_fail
    q = lambda s: "'" + s.replace("'", "''") + "'"   # minimal SQL-literal quoter, like ctx.desc
    reason = "seeded 0 rows in public.docs. Fix: check the seed for public.docs and the identity binding"
    msg = _unrel_fail(q, "SELECT: authenticated, authorized", ("count", 0, reason))
    assert msg.startswith("SELECT fail(") and "UNRELIABLE - " in msg
    assert "Fix: check the seed" in msg                 # the cause's own remedy is carried through
    assert "[probe observed count=0]" in msg            # observation shown for diagnostics
    assert "investigate seeding" not in msg             # the old misleading blanket tail is gone


def test_unrel_fail_shows_error_observation():
    from rlsautotest.probe import _unrel_fail
    q = lambda s: "'" + s.replace("'", "''") + "'"
    msg = _unrel_fail(q, "INSERT: authenticated, authorized", ("err", "23514", "the write value tripped a CHECK. Fix: give it a CHECK-satisfying value"))
    assert "[probe observed error 23514]" in msg and "Fix: give it a CHECK-satisfying value" in msg


# ---------------------------------------------------------------- seeded-0 remediation splits on the observed cause
def test_seeded_zero_reason_constraint_on_seed_gives_not_auto_probable_advice():
    # the seed INSERT itself failed (e.g. 23514 CHECK) -> the row was never planted, so identity binding
    # is NOT the remedy; the honest fix names the constraint / not-auto-probable, never 'claim style'.
    from rlsautotest.probe import _seeded_zero_reason
    msg = _seeded_zero_reason("public.docs", "23514")
    assert "23514" in msg and "Fix:" in msg
    assert "not auto-probable" in msg or "satisfies the table's constraints" in msg
    assert "CHECK/constraint" in msg
    assert "identity binding" not in msg      # the wrong remedy is withheld when the seed never inserted
    assert "claim style" not in msg


def test_seeded_zero_reason_clean_empty_keeps_identity_binding_advice():
    # the seed INSERT succeeded but the row is invisible (seed_err None) -> owner-claim / RLS mismatch;
    # the identity-binding + claim-style advice is exactly right here and must be retained.
    from rlsautotest.probe import _seeded_zero_reason
    msg = _seeded_zero_reason("public.docs", None)
    assert "identity binding" in msg and "claim style" in msg
    assert "seed error" not in msg            # no phantom seed error when the insert succeeded
    assert "Fix:" in msg
