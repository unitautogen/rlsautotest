# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""Policy snapshot / drift diff subcommands.

Split out of the original single-module cli.py; behavior-preserving.
"""
from __future__ import annotations
import argparse, json, re, sys
import psycopg
from pglast.parser import parse_sql_json



# ── snapshot ─────────────────────────────────────────────────────────────────
def cmd_snapshot():
    """rlsautotest snapshot — save current RLS policy state to a JSON file."""
    import datetime, os
    ap = argparse.ArgumentParser(prog="rlsautotest snapshot",
                                 description="Save current RLS policy state for later diff.")
    ap.add_argument("--schema", required=True)
    ap.add_argument("--db-url", help="Postgres connection string (else PG* env)")
    ap.add_argument("--out", default=".rlsautotest/snapshot.json",
                    help="output path (default: .rlsautotest/snapshot.json)")
    a = ap.parse_args(sys.argv[2:])

    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with psycopg.connect(a.db_url or "") as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT schemaname, tablename, policyname, permissive, roles::text, cmd, qual, with_check
            FROM pg_policies WHERE schemaname=%s ORDER BY tablename, policyname""", (a.schema,))
        pol_rows = cur.fetchall()
        cur.execute("""SELECT c.relname, c.relrowsecurity
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname=%s AND c.relkind='r' ORDER BY c.relname""", (a.schema,))
        table_rows = cur.fetchall()

    snapshot = {
        "schema": a.schema,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "tables": {r[0]: {"rls_enabled": bool(r[1])} for r in table_rows},
        "policies": [{"schema": r[0], "table": r[1], "name": r[2], "permissive": r[3],
                       "roles": r[4], "cmd": r[5], "qual": r[6], "with_check": r[7]}
                      for r in pol_rows],
    }
    open(a.out, "w", encoding="utf-8").write(json.dumps(snapshot, indent=2))
    print(f"Snapshot saved: {os.path.abspath(a.out)}")
    print(f"  {len(snapshot['policies'])} policies across {len(table_rows)} tables  "
          f"(timestamp: {snapshot['timestamp']})")



# ── diff ─────────────────────────────────────────────────────────────────────
def cmd_diff():
    """rlsautotest diff — compare current RLS policies vs a saved snapshot."""
    ap = argparse.ArgumentParser(prog="rlsautotest diff",
                                 description="Compare current RLS policies vs saved snapshot.")
    ap.add_argument("--schema", required=True)
    ap.add_argument("--db-url", help="Postgres connection string (else PG* env)")
    ap.add_argument("--snapshot", default=".rlsautotest/snapshot.json",
                    help="snapshot file (default: .rlsautotest/snapshot.json)")
    ap.add_argument("--json", metavar="FILE", help="write diff output as JSON")
    a = ap.parse_args(sys.argv[2:])
    try: sys.stdout.reconfigure(encoding="utf-8")
    except Exception: pass

    try:
        saved = json.loads(open(a.snapshot, encoding="utf-8").read())
    except FileNotFoundError:
        print(f"No snapshot at {a.snapshot}. Run first:\n"
              f"  rlsautotest snapshot --schema {a.schema}", file=sys.stderr)
        sys.exit(2)

    with psycopg.connect(a.db_url or "") as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT tablename, policyname, permissive, roles::text, cmd, qual, with_check
            FROM pg_policies WHERE schemaname=%s ORDER BY tablename, policyname""", (a.schema,))
        curr_pols = {(r[0], r[1]): {"table": r[0], "name": r[1], "permissive": r[2],
                                      "roles": r[3], "cmd": r[4], "qual": r[5], "with_check": r[6]}
                     for r in cur.fetchall()}
        cur.execute("""SELECT c.relname, c.relrowsecurity
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname=%s AND c.relkind='r' ORDER BY c.relname""", (a.schema,))
        curr_tables = {r[0]: bool(r[1]) for r in cur.fetchall()}

    def _sig(p): return (p.get("permissive"), p.get("roles"), p.get("cmd"),
                          p.get("qual"), p.get("with_check"))

    saved_pols = {(p["table"], p["name"]): p for p in saved.get("policies", [])}
    added   = [curr_pols[k] for k in curr_pols if k not in saved_pols]
    removed = [saved_pols[k] for k in saved_pols if k not in curr_pols]
    changed = []
    for k in curr_pols:
        if k in saved_pols and _sig(curr_pols[k]) != _sig(saved_pols[k]):
            changed.append({"table": k[0], "name": k[1],
                             "before": saved_pols[k], "after": curr_pols[k]})

    saved_tables = {t: v.get("rls_enabled") for t, v in saved.get("tables", {}).items()}
    rls_changes = [{"table": t, "before": saved_tables[t], "after": cur_rls}
                   for t, cur_rls in curr_tables.items()
                   if t in saved_tables and bool(saved_tables[t]) != bool(cur_rls)]

    result = {"added": added, "removed": removed, "changed": changed, "rls_changes": rls_changes,
              "snapshot_timestamp": saved.get("timestamp", "?")}
    if a.json:
        open(a.json, "w", encoding="utf-8").write(json.dumps(result, indent=2))

    total = len(added) + len(removed) + len(changed) + len(rls_changes)
    if total == 0:
        print(f"✅  No policy changes since snapshot ({saved.get('timestamp','?')})")
        return

    print(f"\nrlsautotest diff — {a.schema}  vs  {a.snapshot}  ({saved.get('timestamp','?')})\n")
    for p in added:
        print(f"  ✅ ADDED    {p['table']}.{p['name']}  cmd={p['cmd']}  permissive={p['permissive']}")
    for p in removed:
        print(f"  🗑  REMOVED  {p['table']}.{p['name']}  cmd={p['cmd']}")
    for c in changed:
        print(f"  ✏  CHANGED  {c['table']}.{c['name']}")
        b, af = c["before"], c["after"]
        for field in ("permissive", "roles", "cmd", "qual", "with_check"):
            bv, av = b.get(field), af.get(field)
            if bv != av:
                print(f"       {field}: {bv!r}  →  {av!r}")
    for r in rls_changes:
        icon = "🔒" if r["after"] else "🔓"
        state = "ENABLED" if r["after"] else "DISABLED"
        print(f"  {icon} RLS {state}  {r['table']}")
    print()
    # Exit 1 if any security-reducing change (policy removed, RLS disabled, or USING/WITH CHECK widened)
    security_reduced = bool(removed or [r for r in rls_changes if not r["after"]])
    if security_reduced:
        print("⚠  Security-reducing changes detected (exit 1 — CI gate; pass --no-fail to suppress)")
        sys.exit(1)

