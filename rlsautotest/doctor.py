# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""rlsautotest doctor — probe-environment diagnostics + support bundle.

Answers ONE question before anyone trusts a matrix or a suite: can this connection role
actually establish every precondition the probe needs? (Issue #2: a role that couldn't
CREATE OR REPLACE a policy function produced a silently degenerate, false-passing suite.)

Every check is read-only or savepoint-wrapped and rolled back; nothing persists.
The optional --json bundle is REDACTED BY DESIGN: catalog facts, role names, function
names/owners, sqlstates and per-table classification summaries — never row data, never
credentials, never policy expressions beyond what pg_policies exposes to the same role.
"""
from __future__ import annotations
import argparse, json, platform, sys
import psycopg


_CLIENT_ROLES = ("anon", "authenticated", "service_role")


def _sp(cur, name, fn):
    """Run fn() inside SAVEPOINT `name`, always rolled back. Returns (ok, sqlstate_or_None)."""
    cur.execute(f"SAVEPOINT {name}")
    try:
        fn()
        return True, None
    except Exception as e:
        return False, (getattr(e, "sqlstate", None) or "XX000")
    finally:
        try:
            cur.execute(f"ROLLBACK TO SAVEPOINT {name}")
            cur.execute(f"RELEASE SAVEPOINT {name}")
        except Exception:
            pass


def _policy_functions(cur, schema):
    """Every resolvable non-builtin function called from any policy in `schema`:
    [{schema, name, args, owner, definition}] — the mock candidates the probe may need to replace."""
    from .strategies.mock import _policy_fn_names
    cur.execute("SELECT DISTINCT tablename FROM pg_policies WHERE schemaname=%s", (schema,))
    called = set()
    for (t,) in cur.fetchall():
        called |= _policy_fn_names(cur.connection, schema, t)
    if not called:
        return []
    out, seen = [], set()
    for (nsp, name) in sorted(called, key=lambda x: (x[0] or "", x[1])):
        if nsp in ("pg_catalog", "auth"):
            continue
        if nsp:
            cur.execute("""SELECT n.nspname, p.proname, pg_get_function_identity_arguments(p.oid),
                                  pg_get_userbyid(p.proowner), pg_get_functiondef(p.oid)
                           FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                           WHERE n.nspname=%s AND p.proname=%s""", (nsp, name))
        else:
            cur.execute("""SELECT n.nspname, p.proname, pg_get_function_identity_arguments(p.oid),
                                  pg_get_userbyid(p.proowner), pg_get_functiondef(p.oid)
                           FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                           WHERE p.proname=%s AND n.nspname NOT IN ('pg_catalog','information_schema','auth')""",
                        (name,))
        for (fnsp, fnm, fargs, fowner, fdef) in cur.fetchall():
            key = (fnsp, fnm, fargs)
            if key in seen:
                continue
            seen.add(key)
            out.append({"schema": fnsp, "name": fnm, "args": fargs, "owner": fowner, "definition": fdef})
    return out


def cmd_doctor():
    """rlsautotest doctor — verify the probe environment; optionally write a support bundle."""
    ap = argparse.ArgumentParser(prog="rlsautotest doctor",
                                 description="Diagnose the probe environment: role privileges, mock/helper "
                                             "creatability, pgTAP availability. Read-only (all writes are "
                                             "savepoint-wrapped and rolled back).")
    ap.add_argument("--schema", default="public", help="target schema (default: public)")
    ap.add_argument("--db-url", help="Postgres connection string (else PG* env)")
    ap.add_argument("--json", metavar="FILE", default="doctor.json",
                    help="path for the diagnostic bundle (always written; default: doctor.json)")
    a = ap.parse_args(sys.argv[2:])
    try: sys.stdout.reconfigure(encoding="utf-8")
    except Exception: pass

    from . import __version__
    _lines = []     # everything shown on screen, mirrored into the bundle -> ONE file serves human + machine
    def say(s=""):
        print(s); _lines.append(s)
    checks = []     # (ok, label, remedy_or_None)
    def check(ok, label, remedy=None):
        checks.append({"ok": bool(ok), "label": label, "remedy": (None if ok else remedy)})
        say(("  ok    - " if ok else "  FAIL  - ") + label + ("" if ok or not remedy else f"\n            -> {remedy}"))

    bundle = {"tool": {"name": "rlsautotest", "version": __version__,
                       "python": platform.python_version(), "platform": platform.platform()},
              "schema": a.schema}
    with psycopg.connect(a.db_url or "") as conn, conn.cursor() as cur:
        say(f"\nrlsautotest doctor — schema '{a.schema}'\n")
        # ── server / connection ────────────────────────────────────────────────
        cur.execute("SELECT version(), current_user, session_user, current_setting('is_superuser')")
        ver, cu, su, is_super = cur.fetchone()
        bundle["server"] = {"version": ver, "current_user": cu, "session_user": su, "superuser": is_super == "on"}
        say(f"  server: {ver.split(',')[0]}")
        say(f"  connection role: {cu}" + (" (superuser)" if is_super == "on" else ""))
        say()

        # ── client roles + SET ROLE ────────────────────────────────────────────
        cur.execute("SELECT rolname FROM pg_roles WHERE rolname = ANY(%s)", (list(_CLIENT_ROLES),))
        have = {r for (r,) in cur.fetchall()}
        for r in _CLIENT_ROLES:
            if r not in have:
                check(False, f"role '{r}' exists", f"create it (CREATE ROLE {r} NOLOGIN) or this identity row is untestable")
                continue
            ok, ss = _sp(cur, "_rlsa_doc_role", lambda r=r: (cur.execute(f"SET LOCAL ROLE {r}"), cur.execute("RESET ROLE")))
            check(ok, f"can SET ROLE {r}", None if ok else f"GRANT {r} TO {cu} (sqlstate {ss}) — the probe acts as each client role")
        bundle["client_roles"] = {r: (r in have) for r in _CLIENT_ROLES}

        # ── schema CREATE (mock/helper installation site) ─────────────────────
        for sch in dict.fromkeys([a.schema, "public"]):
            cur.execute("SELECT has_schema_privilege(current_user, %s, 'CREATE')", (sch,))
            ok = bool(cur.fetchone()[0])
            check(ok, f"CREATE privilege on schema '{sch}'",
                  f"GRANT CREATE ON SCHEMA {sch} TO {cu}, or connect as the schema owner — required for the "
                  f"pgTAP shim and seed helpers (Supabase local: connect as supabase_admin)")

        # ── pgTAP ──────────────────────────────────────────────────────────────
        cur.execute("SELECT to_regprocedure('plan(integer)') IS NOT NULL, "
                    "EXISTS(SELECT 1 FROM pg_available_extensions WHERE name='pgtap')")
        tap_here, tap_avail = cur.fetchone()
        check(tap_here or tap_avail, "pgTAP installed or available",
              "install pgTAP (CREATE EXTENSION pgtap) or ensure the connection role can create the fallback shim")
        bundle["pgtap"] = {"installed": bool(tap_here), "available": bool(tap_avail)}

        # ── auth.users (Supabase) ─────────────────────────────────────────────
        cur.execute("SELECT to_regclass('auth.users') IS NOT NULL")
        bundle["auth_users"] = bool(cur.fetchone()[0])
        say(f"  info  - auth.users {'present' if bundle['auth_users'] else 'absent (non-Supabase or no auth schema)'}")

        # ── policy functions: ownership + replaceability (the issue #2 check) ──
        fns = _policy_functions(cur, a.schema)
        bundle["policy_functions"] = []
        for f in fns:
            qn = f'"{f["schema"]}"."{f["name"]}"'
            ok, ss = _sp(cur, "_rlsa_doc_fn", lambda f=f: cur.execute(f["definition"]))   # self-replace with its OWN definition: a no-op if permitted
            check(ok, f"can CREATE OR REPLACE {qn}({f['args']}) [owner: {f['owner']}]",
                  f"sqlstate {ss}: mock wiring for policies delegating to this function is impossible as '{cu}' — "
                  f"connect as '{f['owner']}' (or a role that owns it); on Supabase local: supabase_admin")
            bundle["policy_functions"].append({**{k: f[k] for k in ("schema", "name", "args", "owner")},
                                               "replaceable": ok, "sqlstate": ss})
        if not fns:
            say(f"  info  - no user functions referenced by policies in '{a.schema}' (no mock wiring needed)")

        # ── per-table classification summary (debug half of the bundle) ───────
        try:
            from .atoms import analyze
            from .catalog import rls_tables
            tabs = rls_tables(cur, a.schema)
            summary = []
            for t in sorted(tabs):
                try:
                    _pols, per, cmds, notes = analyze(cur, a.schema, t)
                    summary.append({"table": t, "commands": cmds,
                                    "classes": {cmd: [{"kinds": c.get("kinds"), "handled": bool(c.get("handled")),
                                                       "reason": c.get("reason")} for c in per[cmd]["classes"]]
                                                for cmd in cmds},
                                    "notes": notes})
                except Exception as e:
                    summary.append({"table": t, "error": f"{type(e).__name__}: {getattr(e, 'sqlstate', '') or str(e)[:200]}"})
            bundle["tables"] = summary
            say(f"  info  - classified {len(summary)} RLS table(s) for the bundle")
        except Exception as e:
            bundle["tables_error"] = str(e)[:200]

    bundle["checks"] = checks
    failed = [c for c in checks if not c["ok"]]
    say()
    if failed:
        say(f"RESULT: {len(failed)} check(s) FAILED — reports/suites generated in this environment would be "
              f"degraded; affected cells are marked ‼ UNRELIABLE, never silently baked.")
    else:
        say("RESULT: environment OK — the probe can establish every precondition it needs.")
    if a.json:
        bundle["report_text"] = "\n".join(_lines)   # the human-readable doctor report, embedded: ONE file to attach
        open(a.json, "w", encoding="utf-8").write(json.dumps(bundle, indent=2, default=str))
        say(f"bundle written to {a.json} — attach it to a GitHub issue (it contains catalog metadata only: "
              f"role/function/table names and sqlstates; NO row data, NO credentials)")
    sys.exit(1 if failed else 0)
