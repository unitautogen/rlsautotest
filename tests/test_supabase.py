"""No-DB unit tests for the --supabase helpers (issue #3). Every function under test is pure: no database
and no supabase CLI. Covers the DB-URL pick from `supabase status` text, the keep-set a run owns, and which
files reconcile prunes (and, crucially, which it never touches)."""
from rlsautotest.cli import pick_local_db_url, supabase_keep_set, orphans_to_prune


# -------------------------------------------------- pick_local_db_url
STATUS_ENV = '''ANON_KEY="ey.aaa.bbb"
API_URL="http://127.0.0.1:54321"
DB_URL="postgresql://postgres:postgres@127.0.0.1:54322/postgres"
STUDIO_URL="http://127.0.0.1:54323"
'''


def test_pick_reads_the_host_db_url():
    assert pick_local_db_url(STATUS_ENV) == "postgresql://postgres:postgres@127.0.0.1:54322/postgres"


def test_pick_prefers_host_url_over_docker_internal():
    # the container-internal @db:5432 url must NOT win over the host 127.0.0.1 one, even listed first
    txt = ('INTERNAL="postgresql://postgres:postgres@db:5432/postgres"\n'
           'DB_URL="postgresql://postgres:postgres@127.0.0.1:54322/postgres"\n')
    assert pick_local_db_url(txt) == "postgresql://postgres:postgres@127.0.0.1:54322/postgres"


def test_pick_accepts_localhost_too():
    txt = 'DB_URL="postgres://postgres:postgres@localhost:54322/postgres"\n'
    assert pick_local_db_url(txt).endswith("@localhost:54322/postgres")


def test_pick_falls_back_to_only_url_when_none_is_host_local():
    txt = 'X="postgresql://postgres:postgres@db:5432/postgres"\n'
    assert pick_local_db_url(txt) == "postgresql://postgres:postgres@db:5432/postgres"


def test_pick_returns_none_when_no_url_present():
    assert pick_local_db_url("no urls here") is None
    assert pick_local_db_url("") is None
    assert pick_local_db_url(None) is None


def test_pick_strips_the_wrapping_quote():
    # -o env wraps the value in double quotes; the captured token must not keep the trailing quote
    txt = 'DB_URL="postgresql://postgres:postgres@127.0.0.1:54322/postgres"'
    assert '"' not in pick_local_db_url(txt)


# -------------------------------------------------- supabase_keep_set
def test_keep_set_has_hook_guard_and_numbered_tables():
    keep = supabase_keep_set("000-setup-tests-hooks_rlsautotest.sql", "_rlsautotest.sql", True,
                             ["notes", "accounts"])
    assert "000-setup-tests-hooks_rlsautotest.sql" in keep
    assert "010-rls-enabled_rlsautotest.sql" in keep
    # numbered by SORTED table order: accounts -> 101, notes -> 102
    assert "101-rls-accounts_rlsautotest.sql" in keep
    assert "102-rls-notes_rlsautotest.sql" in keep


def test_keep_set_omits_guard_when_not_emitted():
    keep = supabase_keep_set("000-h_rlsautotest.sql", "_rlsautotest.sql", False, ["notes"])
    assert not any("010-rls-enabled" in k for k in keep)
    assert "101-rls-notes_rlsautotest.sql" in keep


def test_keep_set_always_has_the_hook_even_with_no_tables():
    assert supabase_keep_set("000-h_rlsautotest.sql", "_rlsautotest.sql", False, []) == {"000-h_rlsautotest.sql"}


# -------------------------------------------------- orphans_to_prune
def test_prune_targets_only_stale_generated_files():
    keep = {"000-h_rlsautotest.sql", "101-rls-notes_rlsautotest.sql"}
    listing = ["000-h_rlsautotest.sql", "101-rls-notes_rlsautotest.sql",
               "999-rls-ghost_rlsautotest.sql", "keepme.test.sql"]
    assert orphans_to_prune(listing, keep) == ["999-rls-ghost_rlsautotest.sql"]


def test_prune_never_touches_hand_written_tests():
    # hand-written files lack the _rlsautotest.sql suffix, so they are NEVER orphans, even if unknown
    listing = ["my_own.test.sql", "notes_test.sql", "readme.md"]
    assert orphans_to_prune(listing, set()) == []


def test_prune_keeps_the_current_set_and_removes_the_rest():
    keep = supabase_keep_set("000-h_rlsautotest.sql", "_rlsautotest.sql", True, ["notes"])
    listing = list(keep) + ["777-rls-old_rlsautotest.sql"]
    assert orphans_to_prune(listing, keep) == ["777-rls-old_rlsautotest.sql"]


def test_prune_of_empty_listing_is_empty():
    assert orphans_to_prune([], {"000-h_rlsautotest.sql"}) == []