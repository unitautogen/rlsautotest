# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""Policy lint (L001-L010).

Split out of the original single-module cli.py; behavior-preserving.
"""
from __future__ import annotations
import argparse, json, re, sys
import psycopg

from .astutil import _colname, _expr_cols, _names, _node_fn_names, _qt, _subquery_sig, _t, _v, _where
from .bypass import find_bypass
from .catalog import _single_unique_col


def _scalar_subquery_lookups(expr_text):
    """Issue #4 shape detector: every `col = (SELECT ... FROM t WHERE <caller correlation>)` comparison
    in a policy expression -> [(lookup_table, key_col, has_limit)]. AST-based (pglast), NOT a regex:
    the initplan idiom `(SELECT auth.uid()) = col` has no FROM and is never matched, and EXISTS / IN /
    ANY forms are multi-row-safe so only the scalar `=` comparison is reported. The caller decides
    whether the shape is actually hazardous (a lookup keyed on a UNIQUE column returns at most one
    row -- the classic profile lookup -- and is fine)."""
    out = []
    try:
        node = _where(expr_text)
    except Exception:
        return out
    if node is None:
        return out
    def walk(n):
        if isinstance(n, dict):
            if _t(n) == "A_Expr":
                v = _v(n)
                if _names(v.get("name")) == "=":
                    for side in (v.get("lexpr"), v.get("rexpr")):
                        if isinstance(side, dict) and _t(side) == "SubLink":
                            sv = _v(side)
                            if sv.get("subLinkType") == "EXPR_SUBLINK":
                                try:
                                    sig = _subquery_sig(sv.get("subselect"))
                                except Exception:
                                    sig = None
                                if sig and (sig.get("uid") or sig.get("fns")):
                                    key = sig.get("uid") or (sig["fns"][0].get("mcol") if sig.get("fns") else None)
                                    ss = (sv.get("subselect") or {}).get("SelectStmt", {})
                                    out.append((sig["mtable"], key, ss.get("limitCount") is not None))
            for vv in n.values():
                walk(vv)
        elif isinstance(n, list):
            for x in n:
                walk(x)
    walk(node)
    return out




# ══════════════════════════════════════════════════════════════════════════════
# SUBCOMMAND HANDLERS  (lint · snapshot · diff · users · coverage · init)
# ══════════════════════════════════════════════════════════════════════════════

_SEV_ORDER = {"INFO": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

_SEV_ICON  = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "INFO": "🔵"}



# ── lint ─────────────────────────────────────────────────────────────────────
def _cols_referenced(expr_text, colset):
    """Table columns (from colset) named anywhere in a policy predicate. AST, not text."""
    try:
        node = _where(expr_text)
    except Exception:
        return set()
    return set(_expr_cols(node, {c: 1 for c in colset})) if node is not None else set()


def _identity_scoped_cols(expr_text, colset):
    """Columns of the table compared against a caller-identity source (auth.*/current_setting/a
    correlated subquery) in this predicate -- the columns the policy uses to DEFINE access scope.
    No name heuristics: scope-ness comes from the predicate STRUCTURE (a column on one side of a
    comparison whose other side reads the caller's identity), so `is_admin`/`body` are never mistaken
    for scope keys and `tenant_id = auth.jwt()->>'t'` is always caught."""
    try:
        node = _where(expr_text)
    except Exception:
        return set()
    if node is None:
        return set()
    out = set()
    def _has_identity(n):
        for f in _node_fn_names(n):
            if f == "current_setting" or f.startswith("auth.") or f.split(".")[-1] in ("uid", "jwt", "role"):
                return True
        seen = [False]
        def w(x):
            if isinstance(x, dict):
                if _t(x) == "SubLink":
                    seen[0] = True
                for v in x.values():
                    w(v)
            elif isinstance(x, list):
                for y in x:
                    w(y)
        w(n)
        return seen[0]
    def walk(n):
        if isinstance(n, dict):
            tt = _t(n)
            if tt == "A_Expr":
                v = _v(n); l = v.get("lexpr"); r = v.get("rexpr")
                lc = _colname(l) if l else None
                rc = _colname(r) if r else None
                if lc in colset and r is not None and _has_identity(r):
                    out.add(lc)
                if rc in colset and l is not None and _has_identity(l):
                    out.add(rc)
            elif tt == "SubLink":
                te = _v(n).get("testexpr")
                tc = _colname(te) if te else None
                if tc in colset:
                    out.add(tc)   # `col IN (SELECT ...)` / `col = ANY (SELECT ...)`
            for v in n.values():
                walk(v)
        elif isinstance(n, list):
            for x in n:
                walk(x)
    walk(node)
    return out


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
    # RA-4 context: does ANY policy in this SCHEMA carry an explicit role list (polroles != {0})?
    # Schema-wide on purpose -- the divergence footgun is a no-TO policy in a schema whose author
    # otherwise scopes policies to roles.
    cur.execute("""SELECT EXISTS (SELECT 1 FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid
                   JOIN pg_namespace n ON n.oid = c.relnamespace
                   WHERE n.nspname = %s AND NOT (p.polroles @> ARRAY[0]::oid[]))""", (schema,))
    _schema_has_scoped = bool(cur.fetchone()[0])
    # L018 (MB-20) context: table columns (writable vs not) + the identity-SCOPE columns used by
    # ANY policy on the table (structure-derived, no name heuristics).
    cur.execute("""SELECT a.attname, (a.attgenerated <> '' OR a.attidentity = 'a') AS nonwritable
        FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = %s AND c.relname = %s AND a.attnum > 0 AND NOT a.attisdropped
        ORDER BY a.attnum""", (schema, table))
    _allset, _writable = set(), set()
    for _an, _nw in cur.fetchall():
        _allset.add(_an)
        if not _nw:
            _writable.add(_an)
    _scope_cols = set()
    for (_pn0, _pm0, _rl0, _cmd0, _qu0, _wc0) in policies:
        for _e0 in (_qu0, _wc0):
            if _e0:
                _scope_cols |= _identity_scoped_cols(_e0, _allset)
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
        # RA-2: a policy with no TO clause is stored as polroles={0} (the PUBLIC pseudo-role) and
        # pg_policies renders it as roles=['public'] -- NEVER as an empty list, so the `not role_list`
        # branch alone could not fire for the most common shape in the wild. PUBLIC includes anon.
        if q.lower() in ("true", "(true)") and permissive == "PERMISSIVE":
            anon_in = not role_list or "anon" in role_list or "public" in role_list
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

        # L018 (MB-20 / cekuu35 audit q#3): a write policy that constrains SOME columns but leaves an
        # identity-SCOPE column of the table unconstrained on the write side -- a caller may set/change
        # that column on INSERT/UPDATE (reassign ownership, move the row to another tenant), because
        # Postgres only re-checks the columns the write predicate NAMES. Column-precise; complements
        # L003 (UPDATE USING with no WITH CHECK) and L009 (asymmetric USING vs WITH CHECK).
        if permissive == "PERMISSIVE" and cmd_eff in ("INSERT", "UPDATE", "ALL"):
            _effw = wc if wc else q          # effective write check: WITH CHECK, else USING (PG applies USING)
            if _effw and _effw.lower() not in ("true", "(true)"):
                _named = _cols_referenced(_effw, _allset)
                # Fire ONLY when the write check pins the row to the CALLER'S OWN identity (a self-row
                # edit) yet leaves another access-scope column open -- that is the escalation ("edit my
                # own row and change the column that defines its scope"). A write check that is a
                # ROLE/permission gate instead (has_role(...), an admin function) is NOT flagged: an
                # admin setting other columns (e.g. granting membership to any user_id) is intended,
                # not a hole. Distinguishes wsc.docs (owner_id = auth.uid(), tenant_id open) from
                # rbt.mships (has_role(org_id,'owner') INSERT -- owner adds members by design).
                _self = _identity_scoped_cols(_effw, _allset)
                _uncon = sorted((_scope_cols & _writable) - _named)
                if _self and _uncon:
                    findings.append(("L018", "MEDIUM", table, pname,
                        "Write policy constrains " + (", ".join(sorted(_named)) or "no columns") +
                        " but NOT access-scope column(s) " + ", ".join(_uncon) + " — a caller may set or "
                        "change them on write (e.g. reassign ownership or move the row to another tenant), "
                        "since the write side only re-checks columns its predicate names. Add them to "
                        "WITH CHECK so every column the policies use to define scope is re-checked on write."))

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
        # RA-3: a no-TO policy (roles=['public']) reaches anon too -- the most public shape there is.
        if permissive == "PERMISSIVE" and ("anon" in role_list or "public" in role_list) and cmd_eff in ("SELECT","ALL"):
            if q.lower() in ("true", "(true)"):
                findings.append(("L007", "MEDIUM", table, pname,
                                  "Permissive policy grants anon full SELECT — verify public read is intentional"))

        # L017 (RA-4): a PERMISSIVE policy with no TO clause (roles=['public'] = EVERYONE) sitting
        # beside role-scoped policies in the same schema. The classic shape is a policy NAMED
        # "Service role full access" whose audience is actually every role: the name promises a role,
        # PUBLIC delivers everyone, and permissiveness ORs away every scoped policy beside it.
        # Deliberately quiet when the WHOLE schema omits TO (the Supabase tutorial norm): with no
        # role-scoped siblings there is no divergence to flag.
        if permissive == "PERMISSIVE" and role_list == ["public"] and _schema_has_scoped:
            findings.append(("L017", "HIGH", table, pname,
                              "Policy has no TO clause, so it applies to EVERY role (PUBLIC) -- while other "
                              "policies in this schema are role-scoped. If the name/intent targets one role "
                              "(e.g. service_role), the audience diverges from it, and because permissive "
                              "policies OR together it also widens every scoped policy beside it. "
                              "Fix: add `TO <role>` to scope the policy to its intended audience"))

        # L016 (issue #4): scalar-subquery membership lookup -- `col = (SELECT ... FROM t WHERE ... = auth.uid())`.
        # Works only while every user has AT MOST ONE row in t: a second membership makes the subquery
        # return 2 rows -> 21000 error on every query (or, with LIMIT, an arbitrary pick -> the user
        # randomly sees one membership's data). A lookup keyed on a UNIQUE column (the profile shape)
        # returns at most one row by schema and is NOT flagged.
        _sq_seen = set()
        for _expr in (q, wc):
            if not _expr:
                continue
            for (_mtab, _mkey, _mlim) in _scalar_subquery_lookups(_expr):
                _mt = _mtab if "." in _mtab else f"{schema}.{_mtab}"
                if _mkey and _single_unique_col(cur, _qt(_mt), _mkey):
                    continue
                _k = (pname, _mt)
                if _k in _sq_seen:
                    continue
                _sq_seen.add(_k)
                if _mlim:
                    _sqmsg = (f"Scalar-subquery membership lookup with LIMIT: the policy compares a column to "
                              f"`(SELECT ... FROM {_mt} ... LIMIT ...)` keyed on the caller. When a user has TWO rows in "
                              f"{_mt} (e.g. belongs to two teams), Postgres silently picks ONE arbitrarily -- the user "
                              f"randomly sees one membership's data and the other is hidden. Use EXISTS/IN over the "
                              f"membership table, or resolve the value into a JWT claim at auth time.")
                else:
                    _sqmsg = (f"Scalar-subquery membership lookup: the policy compares a column to "
                              f"`(SELECT ... FROM {_mt} ...)` keyed on the caller. It works only while every user has at "
                              f"most ONE row in {_mt}: the moment someone belongs to two (e.g. joins a second team), the "
                              f"subquery returns 2 rows and EVERY query on this table errors for them (21000). Use "
                              f"EXISTS/IN over the membership table, or resolve the value into a JWT claim at auth time.")
                findings.append(("L016", "HIGH", table, pname, _sqmsg))

        # L019 (MB-21 / cekuu35 audit q#8): an unwrapped auth.uid()/auth.jwt()/auth.role() in the
        # predicate is re-evaluated PER ROW; `(select auth.uid())` is hoisted to a one-time InitPlan.
        # On a large table that is a real scan-cost difference (Supabase's 0003_auth_rls_initplan).
        # INFO -- a performance note, not a correctness hole.
        if re.search(r'auth\.(uid|jwt|role)\s*\(', both, re.I) and not re.search(r'\(\s*select\s+auth\.', both, re.I):
            findings.append(("L019", "INFO", table, pname,
                "Policy calls auth.uid()/auth.jwt()/auth.role() unwrapped, so it re-evaluates once PER ROW. "
                "Wrap it as `(select auth.uid())` to hoist it into a single InitPlan (Supabase lint "
                "0003_auth_rls_initplan) — a scan-cost win on large tables; behavior is unchanged."))

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
    ap.add_argument("--allow-bypass-role", action="append", default=[], metavar="ROLE",
                    help="a role allowed to bypass RLS (repeatable); adds to the L014 sanctioned allowlist")
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
        if not a.table:   # bypass surfaces (views / SECURITY DEFINER fns / roles) are schema-level, only on a full scan
            all_findings.extend(find_bypass(cur, a.schema, a.allow_bypass_role))

    min_sev = _SEV_ORDER[a.min_severity]
    filtered = [(rid, sev, tbl, pol, msg) for (rid, sev, tbl, pol, msg) in all_findings
                if _SEV_ORDER.get(sev, 0) >= min_sev]
    filtered.sort(key=lambda x: (-_SEV_ORDER.get(x[1], 0), x[2], x[3] or ""))

    if a.json:
        data = [{"severity": s, "table": t, "policy": p, "message": m}
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
        print(f"    {_SEV_ICON.get(sev,'·')} {sev}{pol_tag}: {msg}")
    print()
    n_crit = sum(1 for (_, s, *_) in filtered if s == "CRITICAL")
    n_high = sum(1 for (_, s, *_) in filtered if s == "HIGH")
    if n_crit or n_high:
        sys.exit(1)

