# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""Policy lint (L001-L010).

Split out of the original single-module cli.py; behavior-preserving.
"""
from __future__ import annotations
import argparse, json, re, sys
import psycopg
from pglast.parser import parse_sql_json



# ══════════════════════════════════════════════════════════════════════════════
# SUBCOMMAND HANDLERS  (lint · snapshot · diff · users · coverage · init)
# ══════════════════════════════════════════════════════════════════════════════

_SEV_ORDER = {"INFO": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

_SEV_ICON  = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "INFO": "🔵"}



# ── lint ─────────────────────────────────────────────────────────────────────
def _lint_table(cur, schema, table):
    """Static analysis of one table's RLS policies — no test execution."""
    cur.execute("""SELECT c.relrowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                   WHERE n.nspname=%s AND c.relname=%s""", (schema, table))
    row = cur.fetchone()
    if not row:
        return []
    rls_on = bool(row[0])
    cur.execute("""SELECT policyname, permissive, roles, cmd, qual, with_check
                   FROM pg_policies WHERE schemaname=%s AND tablename=%s ORDER BY policyname""",
                (schema, table))
    policies = cur.fetchall()
    findings = []

    if not rls_on and policies:
        findings.append(("L008", "MEDIUM", table, None, "RLS disabled but policies exist — policies are dead (never evaluated)"))
        return findings

    if not policies:
        if rls_on:
            findings.append(("L004", "HIGH", table, None,
                              "RLS enabled but no policies — all access implicitly denied for every role"))
        return findings

    # derive which commands have at least one policy
    expanded = set()
    for (_, _, _, cmd, _, _) in policies:
        c = (cmd or "ALL").upper()
        expanded |= ({"SELECT","INSERT","UPDATE","DELETE"} if c == "ALL" else {c})
    if "DELETE" not in expanded:
        findings.append(("L010", "INFO", table, None,
                          "No DELETE policy — implicit deny for DELETE (add one or document intent)"))

    for (pname, permissive, roles, cmd, qual, with_check) in policies:
        cmd_eff = (cmd or "ALL").upper()
        q = (qual or "").strip()
        wc = (with_check or "").strip()
        role_list = list(roles or [])

        # L001: USING(true) on a permissive policy
        if q.lower() in ("true", "(true)") and permissive == "PERMISSIVE":
            anon_in = not role_list or "anon" in role_list
            findings.append(("L001", "CRITICAL" if anon_in else "HIGH", table, pname,
                              "USING(true) — permissive open read; " +
                              ("anon + authenticated" if anon_in else "authenticated") +
                              " users can read ALL rows"))

        # L002: WITH CHECK(true) on a permissive policy
        if wc.lower() in ("true", "(true)") and permissive == "PERMISSIVE":
            findings.append(("L002", "CRITICAL", table, pname,
                              "WITH CHECK(true) — permissive open write; authorized users can write any row"))

        # L003: UPDATE/ALL with USING but no WITH CHECK
        if cmd_eff in ("UPDATE", "ALL") and q and not wc:
            findings.append(("L003", "HIGH", table, pname,
                              "UPDATE policy has USING but no WITH CHECK — rows can be moved out of authorized scope"))

        # L009: USING ≠ WITH CHECK on UPDATE (asymmetric scope)
        if cmd_eff in ("UPDATE", "ALL") and q and wc and q.lower() != wc.lower():
            findings.append(("L009", "INFO", table, pname,
                              f"USING ≠ WITH CHECK: read scope ({q[:60]!r}) differs from write scope ({wc[:60]!r})"))

        # L005: opaque user-defined function in policy (not auth.* / pg_catalog)
        both = f"{q} {wc}"
        udfs = re.findall(r'\b(?!auth\.|pgsodium\.|extensions\.|pg_catalog\.)([a-z_]\w*\.[a-z_]\w*)\s*\(', both, re.I)
        udfs = [u for u in udfs if not u.startswith(("storage.", "public."))]
        if udfs:
            findings.append(("L005", "HIGH", table, pname,
                              f"Policy calls user-defined function(s): {udfs} — logic is opaque and won't be auto-tested by rlsautotest"))

        # L007: permissive policy grants anon full SELECT with no real restriction
        if permissive == "PERMISSIVE" and "anon" in role_list and cmd_eff in ("SELECT","ALL"):
            if q.lower() in ("true", "(true)"):
                findings.append(("L007", "MEDIUM", table, pname,
                                  "Permissive policy grants anon full SELECT — verify public read is intentional"))

        # L006: self-referential policy → infinite recursion risk
        full_table = f"{schema}.{table}"
        if re.search(rf'\b{re.escape(table)}\b', both, re.I) or full_table.lower() in both.lower():
            findings.append(("L006", "HIGH", table, pname,
                              f"Policy references its own table ({table}) in the predicate — "
                              f"risk of infinite recursion; use a SECURITY DEFINER helper fn instead"))

    return findings



def cmd_lint():
    """rlsautotest lint — static analysis of RLS policy expressions (no test execution)."""
    ap = argparse.ArgumentParser(prog="rlsautotest lint",
                                 description="Static analysis of RLS policy expressions.")
    ap.add_argument("--schema", required=True)
    ap.add_argument("--table", help="analyze one table; omit for all tables in the schema")
    ap.add_argument("--db-url", help="Postgres connection string (else PG* env)")
    ap.add_argument("--json", metavar="FILE", help="write findings as JSON")
    ap.add_argument("--min-severity", choices=["INFO","MEDIUM","HIGH","CRITICAL"], default="INFO",
                    help="minimum severity to report (default: INFO)")
    a = ap.parse_args(sys.argv[2:])
    try: sys.stdout.reconfigure(encoding="utf-8")
    except Exception: pass

    with psycopg.connect(a.db_url or "") as conn, conn.cursor() as cur:
        if a.table:
            tables = [a.table]
        else:
            cur.execute("""SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                           WHERE n.nspname=%s AND c.relkind='r' ORDER BY c.relname""", (a.schema,))
            tables = [r[0] for r in cur.fetchall()]
        all_findings = []
        for t in tables:
            all_findings.extend(_lint_table(cur, a.schema, t))

    min_sev = _SEV_ORDER[a.min_severity]
    filtered = [(rid, sev, tbl, pol, msg) for (rid, sev, tbl, pol, msg) in all_findings
                if _SEV_ORDER.get(sev, 0) >= min_sev]
    filtered.sort(key=lambda x: (-_SEV_ORDER.get(x[1], 0), x[2], x[3] or ""))

    if a.json:
        data = [{"rule": r, "severity": s, "table": t, "policy": p, "message": m}
                for (r, s, t, p, m) in filtered]
        open(a.json, "w", encoding="utf-8").write(json.dumps(data, indent=2))

    if not filtered:
        print(f"✅  No issues found in {a.schema} schema (min-severity={a.min_severity})")
        return
    print(f"\nrlsautotest lint — {a.schema}  [{len(filtered)} finding(s)]\n")
    cur_table = None
    for (rid, sev, tbl, pol, msg) in filtered:
        if tbl != cur_table:
            print(f"  {a.schema}.{tbl}")
            cur_table = tbl
        pol_tag = f"  [{pol}]" if pol else ""
        print(f"    {_SEV_ICON.get(sev,'·')} {rid} {sev}{pol_tag}: {msg}")
    print()
    n_crit = sum(1 for (_, s, *_) in filtered if s == "CRITICAL")
    n_high = sum(1 for (_, s, *_) in filtered if s == "HIGH")
    if n_crit or n_high:
        sys.exit(1)

