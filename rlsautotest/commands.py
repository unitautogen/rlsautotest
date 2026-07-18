# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""Misc subcommands: users, coverage, init.

Split out of the original single-module cli.py; behavior-preserving.
"""
from __future__ import annotations
import argparse
import json
import sys
import psycopg



# ── users ─────────────────────────────────────────────────────────────────────
def cmd_users():
    """rlsautotest users — list users from auth.users for testing context."""
    ap = argparse.ArgumentParser(prog="rlsautotest users",
                                 description="List users from auth.users for --as-user testing.")
    ap.add_argument("--db-url", help="Postgres connection string (else PG* env)")
    ap.add_argument("--limit", type=int, default=25, help="max rows (default: 25)")
    ap.add_argument("--json", metavar="FILE", help="write as JSON")
    a = ap.parse_args(sys.argv[2:])
    try: sys.stdout.reconfigure(encoding="utf-8")
    except Exception: pass

    with psycopg.connect(a.db_url or "") as conn, conn.cursor() as cur:
        try:
            cur.execute("""SELECT id, email, phone, role, created_at,
                                  raw_app_meta_data::text, raw_user_meta_data::text
                           FROM auth.users ORDER BY created_at DESC LIMIT %s""", (a.limit,))
            rows = cur.fetchall()
        except Exception as e:
            if "auth" in str(e).lower() or "does not exist" in str(e).lower():
                print("auth.users not found. Is this a Supabase database? (auth schema required)", file=sys.stderr)
                sys.exit(2)
            raise

    if not rows:
        print("No users in auth.users. Add users via Supabase Dashboard → Authentication.")
        return
    if a.json:
        data = [{"id": str(r[0]), "email": r[1], "phone": r[2], "role": r[3],
                 "created_at": str(r[4]), "app_metadata": r[5], "user_metadata": r[6]}
                for r in rows]
        open(a.json, "w", encoding="utf-8").write(json.dumps(data, indent=2))

    print(f"\nrlsautotest users — {len(rows)} user(s)\n")
    print(f"  {'ID':<38}  {'EMAIL / PHONE':<30}  {'ROLE':<15}  CREATED")
    print("  " + "─" * 95)
    for (uid, email, phone, role, created, _app, _meta) in rows:
        ident = email or phone or "—"
        print(f"  {str(uid):<38}  {ident:<30}  {(role or '—'):<15}  {str(created)[:19]}")
    print(f"\nTest from a real user's perspective:\n"
          f"  rlsautotest --schema <s> --report --as-user <email>\n")



# ── coverage ─────────────────────────────────────────────────────────────────
def cmd_coverage():
    """rlsautotest coverage — RLS policy obligation-surface coverage report."""
    ap = argparse.ArgumentParser(prog="rlsautotest coverage",
                                 description="Report what fraction of RLS obligations are covered by the generated battery.")
    ap.add_argument("--schema", required=True)
    ap.add_argument("--table", help="one table only")
    ap.add_argument("--db-url", help="Postgres connection string (else PG* env)")
    ap.add_argument("--json", metavar="FILE", help="write as JSON")
    a = ap.parse_args(sys.argv[2:])
    try: sys.stdout.reconfigure(encoding="utf-8")
    except Exception: pass

    CMDS = ("SELECT", "INSERT", "UPDATE", "DELETE")
    def _expand(c):
        return set(CMDS) if (c or "ALL").upper() == "ALL" else {(c or "").upper()}
    # The obligations our battery asserts (authorized + unauthorized per policied command)
    BATTERY_OBL = {(c, p)
                   for c in CMDS
                   for p in ("authorized", "unauthorized")}

    with psycopg.connect(a.db_url or "") as conn, conn.cursor() as cur:
        cur.execute("""SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                       WHERE n.nspname=%s AND c.relkind='r' AND c.relrowsecurity ORDER BY c.relname""",
                    (a.schema,))
        rls_tables_all = [r[0] for r in cur.fetchall()]
        if a.table:
            rls_tables_all = [t for t in rls_tables_all if t == a.table]
        rows_out = []
        for t in rls_tables_all:
            cur.execute("SELECT cmd FROM pg_policies WHERE schemaname=%s AND tablename=%s", (a.schema, t))
            cmds = set()
            for (c,) in cur.fetchall():
                cmds |= _expand(c)
            cmds &= set(CMDS)
            obligations = {(c, p) for c in cmds for p in ("authorized", "unauthorized")}
            covered = obligations & BATTERY_OBL
            uncovered = sorted(obligations - covered)
            pct = round(len(covered) / len(obligations) * 100, 1) if obligations else 0.0
            rows_out.append({"table": t, "policy_commands": sorted(cmds),
                              "obligations": len(obligations), "covered": len(covered),
                              "coverage": pct,
                              "uncovered": [f"{c}/{p}" for (c, p) in uncovered]})

    if a.json:
        open(a.json, "w", encoding="utf-8").write(json.dumps(rows_out, indent=2))
    if not rows_out:
        print(f"No RLS-enabled tables in schema {a.schema}.", file=sys.stderr); sys.exit(2)

    tot_o = sum(r["obligations"] for r in rows_out)
    tot_c = sum(r["covered"] for r in rows_out)
    overall = round(tot_c / tot_o * 100, 1) if tot_o else 0.0
    print(f"\nrlsautotest coverage — {a.schema}  [{overall:.1f}% overall]\n")
    print(f"  {'TABLE':<30}  {'COV%':>6}  {'COVERED':>8}  UNCOVERED")
    print("  " + "─" * 75)
    for r in rows_out:
        filled = int(r["coverage"] // 10)
        bar = "█" * filled + "░" * (10 - filled)
        unc = ", ".join(r["uncovered"]) or "—"
        print(f"  {r['table']:<30}  {r['coverage']:>5.1f}%  {r['covered']:>2}/{r['obligations']:<2}  {bar}  {unc}")
    print(f"\n  Overall: {tot_c}/{tot_o} obligations covered ({overall:.1f}%)")
    print(f"\n  Tip: 'rlsautotest --schema {a.schema} --report' executes the battery and shows the identity matrix.\n")



# ── init ─────────────────────────────────────────────────────────────────────
def cmd_init():
    """rlsautotest init — discover tables and RLS/policy status in a schema."""
    ap = argparse.ArgumentParser(prog="rlsautotest init",
                                 description="Discover tables, RLS status, and grants in a schema.")
    ap.add_argument("--schema", required=True)
    ap.add_argument("--db-url", help="Postgres connection string (else PG* env)")
    ap.add_argument("--json", metavar="FILE", help="write as JSON")
    a = ap.parse_args(sys.argv[2:])
    try: sys.stdout.reconfigure(encoding="utf-8")
    except Exception: pass

    with psycopg.connect(a.db_url or "") as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT c.relname,
                   c.relrowsecurity,
                   COUNT(DISTINCT p.policyname)                                                AS policy_count,
                   COUNT(DISTINCT CASE WHEN a.grantee='authenticated' THEN a.privilege_type END) AS auth_grants,
                   COUNT(DISTINCT CASE WHEN a.grantee='anon'          THEN a.privilege_type END) AS anon_grants
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            LEFT JOIN pg_policies p
                   ON p.schemaname = n.nspname AND p.tablename = c.relname
            LEFT JOIN information_schema.role_table_grants a
                   ON a.table_schema = n.nspname AND a.table_name = c.relname
                  AND a.grantee IN ('authenticated','anon')
            WHERE n.nspname=%s AND c.relkind='r'
            GROUP BY c.relname, c.relrowsecurity
            ORDER BY c.relname""", (a.schema,))
        rows = cur.fetchall()

    if not rows:
        print(f"No tables found in schema {a.schema}.", file=sys.stderr); sys.exit(2)
    if a.json:
        data = [{"table": r[0], "rls_enabled": bool(r[1]), "policy_count": int(r[2]),
                 "auth_grants": int(r[3]), "anon_grants": int(r[4])} for r in rows]
        open(a.json, "w", encoding="utf-8").write(json.dumps(data, indent=2))

    print(f"\nrlsautotest init — {a.schema}  [{len(rows)} table(s)]\n")
    print(f"  {'TABLE':<32}  {'RLS':<5}  {'POLICIES':>9}  {'AUTH':>5}  {'ANON':>5}  STATUS")
    print("  " + "─" * 72)
    n_exposed = 0
    for (name, rls_on, pol_cnt, auth_g, anon_g) in rows:
        icon = "🔒" if rls_on else "🔓"
        status_parts = []
        if not rls_on and (auth_g or anon_g):
            status_parts.append("⚠ EXPOSED")
            n_exposed += 1
        elif rls_on and pol_cnt == 0:
            status_parts.append("no policies (implicit deny)")
        elif rls_on:
            status_parts.append("protected")
        else:
            status_parts.append("RLS off (internal?)")
        print(f"  {name:<32}  {icon} {'ON' if rls_on else 'OFF':<3}  {int(pol_cnt):>5} pol  "
              f"{int(auth_g):>5}g  {int(anon_g):>5}g  {', '.join(status_parts)}")
    n_rls = sum(1 for r in rows if r[1])
    print(f"\n  Summary: {n_rls}/{len(rows)} tables RLS-enabled"
          + (f"  ⚠ {n_exposed} exposed (RLS off + client grant)" if n_exposed else " ✅"))
    print(f"\n  Next steps:")
    print(f"    rlsautotest lint     --schema {a.schema}              # static analysis")
    print(f"    rlsautotest snapshot --schema {a.schema}              # save policy baseline")
    print(f"    rlsautotest --schema {a.schema} --html rls-report.html  # full probe report")
    print()

