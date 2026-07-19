#!/usr/bin/env python3
# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""testgen.rls - predicate-tree, command-aware RLS test generator.

Per RLS_ARCHITECTURE.md. For EACH command we take the applicable policies, parse
the right clause (USING for reads, WITH CHECK for INSERT) to DNF min-terms, and
derive one identity class per min-term. Emits the role-switch AAA battery with:
 - recursive ancestors-first FK seeding (multi-table / transitive chains),
 - enum-aware fills + enum-typed RBAC labels,
 - fresh-identity insert when the link column is unique/PK,
 - (SELECT auth.uid()) wrapper unwrap, auth.role()='authenticated' open gate.
Unhandled atoms -> reason-coded NOT_TESTABLE.

  python -m testgen.rls --schema <s> --table <t> [--describe] [--out f.sql]
"""
from __future__ import annotations
import argparse
import json
import sys
import psycopg

# The engine was split into focused modules; cli re-exports every symbol so that
# `from rlsautotest.cli import X` keeps working for tests and downstream users.
from .astutil import ORDER, _CMDS4, _HOME, _TAGLINE, _TAGLINE2, _and_conjuncts, _array_consts, _bool_extra, _claim_paths, _colname, _colqual, _const, _eq_pairs, _expr_cols, _expr_consts, _find_queries, _is_func, _is_true_clause, _is_uuid, _jwt_anywhere, _jwt_keys, _list_consts, _names, _not, _qlit, _split_statements, _sq, _t, _unwrap, _v, _where  # noqa: F401
from .values import CV, FOREIGN, FUTURE_EXP, INS, MV, NOBODY, RIVAL_ORG, RIVAL_SUB, _CASTABLE_CACHE, _bump_lit, _castable_lit, _lit, _nonempty_array_lit  # noqa: F401
from .catalog import _FK_SQL, _action_table, _basejump_present, _check_bool_udfs, _columns, _constraint_meta, _effective_grants, _exposed, _fk_by_name, _fk_of, all_tables, rls_tables  # noqa: F401
from .bypass import find_bypass, finding_type  # noqa: F401
from .atoms import _DNF_BUDGET, _check_value_set, _classify_aexpr, _cmd_dnf, _dnf_ast, _folder_owner, _func_selects, _introspect_claim_fn, _introspect_rbac, _membership, _scalar_lookup, _set_claim, analyze, build_class, classify_node  # noqa: F401
from .witness import _WV_UID, _array_elem_type, _candidate_sessions, _candidate_values, _class_pick, _col_textfn, _flip_first, _flip_last, _fn_preimage, _like_match, _pg_array_literal, _range_witness, _regex_match, _side_role, _solve_array, _solve_between, _solve_eq, _solve_fncol_eq, _solve_fncol_preimage, _solve_ineq, _solve_jsonb, _solve_leaf, _solve_node, _solve_pattern, _solve_predicate, _solve_subquery, _subquery_tables, _wv_ctx, _wv_lit, _wv_merge, _wv_other, _wv_some  # noqa: F401
from .probe import _probe, _unrel_fail  # noqa: F401
from .seeding import _mock_valid_row, _seed_one, _seed_plan, _synth_required_cols, _synthesize_row, _unq, _wrap_seed  # noqa: F401
from .structs import EmitContext  # noqa: F401
from .emit import _HOOK_SELFTEST, _PGTAP_ENSURE, _SHIM, _emit_both, _load_ctx, coverage, emit, emit_flat, emit_rls_guard, setup_hook_sql  # noqa: F401
from .strategies.mock import _mocklit, _opaque_fn_sig, _policy_bool_udfs, mock_emit  # noqa: F401
from .strategies.synth import _synth_gate, synth_emit  # noqa: F401
from .strategies.recursion import _synth_recursion_gate, synth_recursion_emit  # noqa: F401
from .strategies.mockforce import _force_atom_plan, _force_sentinels, mock_force_emit  # noqa: F401
from .strategies.solver import solve_emit  # noqa: F401
from .strategies.relstate import relstate_emit  # noqa: F401
from .report import _DENY_WORDS, _ID_ROWS, _REPORT_SKIP, _as_user_report, _explain_dashes, _id_cell, _table_report, _table_status, render_report_html, render_report_text  # noqa: F401
from .lint import _SEV_ICON, _SEV_ORDER, _lint_table, cmd_lint  # noqa: F401
from .snapshot import cmd_diff, cmd_snapshot  # noqa: F401
from .commands import cmd_coverage, cmd_init, cmd_users  # noqa: F401
from .doctor import cmd_doctor  # noqa: F401



# ══════════════════════════════════════════════════════════════════════════════
# DISPATCH TABLE for subcommands
# ══════════════════════════════════════════════════════════════════════════════
_SUBCMDS = {
    "lint": cmd_lint,
    "snapshot": cmd_snapshot,
    "diff": cmd_diff,
    "users": cmd_users,
    "coverage": cmd_coverage,
    "init": cmd_init,
    "doctor": cmd_doctor,
}



def main():
    import os, pathlib
    # ── subcommand dispatch (lint / snapshot / diff / users / coverage / init) ──
    if len(sys.argv) > 1 and sys.argv[1] in _SUBCMDS:
        return _SUBCMDS[sys.argv[1]]()

    ap = argparse.ArgumentParser(prog="rlsautotest", description="Generate native pgTAP RLS tests for Supabase/Postgres.")
    ap.add_argument("--schema", required=True)
    ap.add_argument("--table", help="single table; omit (with --emit) to do every RLS table in the schema")
    ap.add_argument("--emit", metavar="DIR", help="write the Supabase suite layout under DIR: native pgTAP into DIR/tests/database/rls/")
    ap.add_argument("--label", help="emit into a named subfolder rls/<label>/ — give each database its own label when generating for several")
    ap.add_argument("--out", help="single-table: write nested (debug) pgTAP here")
    ap.add_argument("--flat", help="single-table: write native flat pgTAP here")
    ap.add_argument("--setup", help="single-table: write 000-setup-tests-hooks.sql here")
    ap.add_argument("--describe", action="store_true")
    ap.add_argument("--debug-emitter", action="store_true", help="with --emit: ALSO write the legacy nested runtests() form into DIR/.rlsautotest/debug/ (demoted: it predates the probe engine and exists for debugging only)")
    ap.add_argument("--debug-unhandled", action="store_true", help="read-only: list every policy branch the CLASSIFIER couldn't recognize (table, command, policy, shape) across the schema — to triage parsing gaps")
    ap.add_argument("--no-helpers", action="store_true", help="emit fully self-contained tests (no tests.* helpers / no 000-hook)")
    ap.add_argument("--implicit-deny", action="store_true", help="DEFAULT (kept for compatibility): emit deny tests for commands a table has NO policy for (RLS-on deny-by-default), so CI governs the FULL command matrix and a future too-broad grant/policy fails the suite")
    ap.add_argument("--no-implicit-deny", action="store_true", help="do NOT emit the deny-by-default tests for no-policy commands")
    ap.add_argument("--db-url", help="Postgres connection string (else uses PG* env)")
    ap.add_argument("--report", action="store_true", help="run the suite and print the grant/deny coverage matrix")
    ap.add_argument("--report-json", help="write the matrix as JSON to this path")
    ap.add_argument("--html", help="run the suite and write an HTML report to this path (the single-command routine)")
    ap.add_argument("--no-fail", action="store_true", help="with --report/--html: do NOT exit non-zero on problems (default: exit 1 if any table is exposed or any check fails — for CI gating)")
    ap.add_argument("--quiet", action="store_true", help="with --report/--html: only show tables with issues (suppress clean tables)")
    ap.add_argument("--parallel", type=int, default=1, metavar="N",
                    help="run N tables in parallel for --report/--html (default: 1 = sequential)")
    ap.add_argument("--as-user", metavar="EMAIL",
                    help="after --report: show what a specific auth.users identity can/cannot do")
    a = ap.parse_args()
    if a.label and not all(ch.isalnum() or ch in "-_" for ch in a.label):
        ap.error("--label may contain only letters, digits, '-' and '_' (it names an emit subfolder; this blocks path traversal)")
    try: sys.stdout.reconfigure(encoding="utf-8")   # render matrix glyphs on Windows too
    except Exception: pass
    helpers = not a.no_helpers
    if a.report or a.html or a.emit:
        sys.stderr.write(
            "\nWARNING: rlsautotest runs statements against the database in --db-url to probe\n"
            "each policy -- it seeds rows and executes SELECT/INSERT/UPDATE/DELETE. Each probe is\n"
            "wrapped in a transaction and rolled back (nothing is committed), but the statements DO\n"
            "run (table locks, triggers, sequences fire). Point --db-url at a DISPOSABLE COPY of\n"
            "your database, NEVER production.\n\n"
        )
    report_gate = 0   # exit code for the report/emit paths (1 if CI-gating problems found)
    with psycopg.connect(a.db_url or "") as conn, conn.cursor() as cur:
        if a.debug_unhandled:   # read-only triage: which policy branches does the classifier drop to NOT_TESTABLE?
            tabs2 = [a.table] if a.table else rls_tables(cur, a.schema)
            rows_out = []
            for t in sorted(tabs2):
                try:
                    _pols, _per, _cmds2, _notes = analyze(cur, a.schema, t)
                except Exception as e:
                    print(f"  {a.schema}.{t}: analyze error: {e}"); continue
                for cmd in _cmds2:
                    for c in _per[cmd]["classes"]:
                        if not c.get("handled"):
                            rows_out.append((t, cmd, c.get("src_policy") or "?", c.get("reason") or "?"))
            if not rows_out:
                print(f"No unclassified policy branches in schema {a.schema} — every branch is handled by the classifier.")
            else:
                print(f"Unclassified policy branches in schema {a.schema} ({len(rows_out)}):\n")
                for (t, cmd, pol, reason) in rows_out:
                    print(f"  {a.schema}.{t}  {cmd:<6}  policy [{pol}]  ->  {reason}")
                print("\nNote: these are the CLASSIFIER's gaps. The per-min-term solver (BL-1) may still emit a")
                print("DB-verified grant/deny for them at --report/--emit time; run --report to see which stay '-'.")
            return
        if a.report or a.html:
            if a.table:
                cur.execute("""SELECT c.relrowsecurity, EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid)
                    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s AND c.relname=%s""",
                            (a.schema, a.table))
                row = cur.fetchone()
                tabs = [(a.table, bool(row[0]), bool(row[1]))] if row else []
            else:
                tabs = all_tables(cur, a.schema)
            # ── parallel or sequential table probing ──────────────────────────
            def _probe_one(t_tuple, conn_=None, cur_=None):
                cn, cr = (conn_ or conn), (cur_ or cur)
                t, rls_on, has_pol = t_tuple
                if rls_on and has_pol:
                    rep = _table_report(cr, cn, a.schema, t, helpers)
                else:
                    fg = []
                    if rls_on and not has_pol:   # RLS on, zero policies = deny-all to client roles (safe if intentional, else unintentionally inaccessible)
                        fg.append("RLS is ENABLED but NO POLICY is defined -> every client role (anon/authenticated) is denied ALL access. Safe if intentional (deny-all); otherwise the table is unintentionally inaccessible -> add a policy.")
                    rep = {"table": t, "rls_enabled": rls_on, "policied": [], "cells": {}, "footguns": fg, "coverage": [0, 0]}
                rep["has_policy"] = has_pol
                rep["exposed"] = (not rls_on) and _exposed(cr, a.schema, t)
                rep["grants"] = _effective_grants(cr, a.schema, t)   # per-command grants for ALL roles (incl service_role) — every cell is grant-gated
                return rep

            n_parallel = max(1, getattr(a, "parallel", 1))
            if n_parallel > 1:
                # One PRIVATE connection per worker thread. Probes mutate per-SESSION state (SET ROLE,
                # request.jwt.claims, savepoints) and one aborted transaction poisons every statement
                # sharing it (25P02) — so N tables through the single outer connection was both
                # crash-prone and unsound (identity bleed between interleaved probes). Thread-local
                # connections keep each table's probe sequential and isolated in its own session;
                # _ex.map preserves table order.
                from concurrent.futures import ThreadPoolExecutor
                import threading
                _tls, _pconns, _plock = threading.local(), [], threading.Lock()
                def _probe_par(t_tuple):
                    c = getattr(_tls, "conn", None)
                    if c is None:
                        c = psycopg.connect(a.db_url or "")
                        _tls.conn = c
                        with _plock:
                            _pconns.append(c)
                    with c.cursor() as cr:
                        return _probe_one(t_tuple, conn_=c, cur_=cr)
                try:
                    with ThreadPoolExecutor(max_workers=n_parallel) as _ex:
                        reps = list(_ex.map(_probe_par, tabs))
                finally:
                    for c in _pconns:
                        try: c.close()
                        except Exception: pass
            else:
                reps = [_probe_one(t) for t in tabs]

            # ── --quiet: suppress tables with no issues ───────────────────────
            if getattr(a, "quiet", False):
                def _has_issues(r):
                    if r.get("exposed"): return True
                    if r.get("footguns"): return True
                    if any(_id_cell(r, k, c)[1] in ("danger", "fail") for k, _ in _ID_ROWS for c in _CMDS4):
                        return True
                    return False
                reps_display = [r for r in reps if _has_issues(r)]
                if not reps_display:
                    print(f"✅  All {len(reps)} table(s) clean — no issues found.")
                    if not a.no_fail:
                        sys.exit(0)
            else:
                reps_display = reps

            # bypass surfaces (views / SECURITY DEFINER fns / roles that sidestep RLS) — shown in HTML + JSON.
            with conn.cursor() as _bcur:
                bypass_findings = find_bypass(_bcur, a.schema)
            if a.report_json:
                # the in-memory report holds sets (unreliable_cells) and tuple-keyed dicts (grants),
                # neither JSON-serializable: render sets as sorted lists and tuple keys as "a:b".
                def _jsonable(o):
                    if isinstance(o, dict):
                        return {(k if isinstance(k, str) else ":".join(map(str, k)) if isinstance(k, tuple) else str(k)): _jsonable(v)
                                for k, v in o.items()}
                    if isinstance(o, (set, frozenset)):
                        return sorted(_jsonable(x) for x in o)
                    if isinstance(o, (list, tuple)):
                        return [_jsonable(x) for x in o]
                    return o
                _payload = {"tables": reps, "bypass_surfaces": [
                    {"object": o, "type": finding_type(c, m), "severity": s, "why": m}
                    for (c, s, o, _d, m) in bypass_findings]}
                open(a.report_json, "w", encoding="utf-8").write(json.dumps(_jsonable(_payload), indent=2))
            if a.html:
                open(a.html, "w", encoding="utf-8").write(render_report_html(reps_display, a.schema, bypass_findings))
                _abs = os.path.abspath(a.html)
                print(f"HTML report for {len(reps_display)} table(s) written to:\n  {_abs}")
                try:    # clickable file:// URL in most terminals
                    print(f"  {pathlib.Path(_abs).as_uri()}")
                except Exception: pass
                print(f"\n{_TAGLINE} {_TAGLINE2}")
            if a.report or not a.html:
                print(render_report_text(reps_display))
            # CI gate: fail on any exposed table (RLS off + reachable), any failing/leaking check, or a broken policy
            exposed_any = [r["table"] for r in reps if r.get("exposed")]
            holes_any = [r["table"] for r in reps
                         if any(_id_cell(r, k, c)[1] in ("danger", "fail") for k, _ in _ID_ROWS for c in _CMDS4)]
            broken_any = [r["table"] for r in reps if any("BROKEN POLICY" in f for f in r.get("footguns", []))]
            leak_any = [r["table"] for r in reps if r.get("transition_leaks")]
            unreliable_any = [r["table"] for r in reps if r.get("unreliable")]
            if exposed_any or holes_any or broken_any or leak_any or unreliable_any:
                bits = []
                if exposed_any: bits.append(f"{len(exposed_any)} exposed table(s): {', '.join(exposed_any)}")
                if holes_any:   bits.append(f"{len(holes_any)} table(s) with policy holes/failures: {', '.join(holes_any)}")
                if broken_any:  bits.append(f"{len(broken_any)} broken/unreadable table(s): {', '.join(broken_any)}")
                if leak_any:    bits.append(f"{len(leak_any)} table(s) with cross-policy WITH CHECK leaks: {', '.join(leak_any)}")
                if unreliable_any: bits.append(f"{len(unreliable_any)} table(s) with UNRELIABLE tests (seed/precondition failed): {', '.join(unreliable_any)}")
                print("\nFAIL: " + "; ".join(bits) + ("" if a.no_fail else "  (exit 1 — CI gate; pass --no-fail to suppress)"))
                report_gate = 0 if a.no_fail else 1
            # ── --as-user: probe from a real auth.users identity ──────────────
            if getattr(a, "as_user", None):
                try:
                    cur.execute("SELECT id, raw_app_meta_data, raw_user_meta_data FROM auth.users WHERE email=%s",
                                (a.as_user,))
                    u_row = cur.fetchone()
                    if not u_row:
                        print(f"\n⚠  --as-user: no auth.users row with email={a.as_user!r}. "
                              f"Run 'rlsautotest users' to see available identities.")
                    else:
                        u_id, app_meta_raw, user_meta_raw = u_row
                        app_meta = json.loads(app_meta_raw) if app_meta_raw else {}
                        user_meta = json.loads(user_meta_raw) if user_meta_raw else {}
                        print(f"\n── as-user: {a.as_user} ({u_id}) ─────────────────────────────")
                        print(f"  {'TABLE':<32}  {'SELECT':>12}  {'INSERT':>12}  {'UPDATE':>12}  {'DELETE':>12}")
                        print("  " + "─" * 74)
                        probe_tabs = [a.table] if a.table else [r["table"] for r in reps if r.get("rls_enabled")]
                        for t in probe_tabs:
                            res = _as_user_report(conn, cur, a.schema, t, u_id, app_meta, user_meta)
                            row_cells = [res.get(c, "–") for c in ["SELECT", "INSERT", "UPDATE", "DELETE"]]
                            print(f"  {t:<32}  {row_cells[0]:>12}  {row_cells[1]:>12}  {row_cells[2]:>12}  {row_cells[3]:>12}")
                        print()
                except Exception as e:
                    if "auth" in str(e).lower() or "does not exist" in str(e).lower():
                        print(f"\n⚠  --as-user requires auth.users (Supabase): {e}")
                    else:
                        raise

            if not (a.emit or (a.table and (a.flat or a.out or a.setup))):
                # fall through when test files were ALSO requested (--emit, or single-table --flat/--out/--setup
                # combined with --report/--html: one command produces both, and the gate still exits at the end)
                sys.exit(report_gate)
        if a.emit:
            tdir = os.path.join(a.emit, "tests", "database", "rls", *( [a.label] if a.label else [] ))
            ddir = os.path.join(a.emit, ".rlsautotest", "debug", *( [a.label] if a.label else [] ))
            os.makedirs(tdir, exist_ok=True)
            if a.debug_emitter: os.makedirs(ddir, exist_ok=True)
            if helpers:
                hookpath = os.path.join(tdir, "000-setup-tests-hooks.sql")
                if not os.path.exists(hookpath):   # non-destructive: never clobber an existing hook
                    open(hookpath, "w", encoding="utf-8").write(setup_hook_sql(_basejump_present(cur)))
            guard = emit_rls_guard(cur, a.schema)   # schema-wide "RLS must be enabled" guard
            if guard:
                open(os.path.join(tdir, "010-rls-enabled.test.sql"), "w", encoding="utf-8").write(guard)
            tables = [a.table] if a.table else rls_tables(cur, a.schema)
            for i, t in enumerate(sorted(tables), start=1):
                ctx = _load_ctx(cur, a.schema, t)
                flat, nested = _emit_both(a.schema, t, ctx, helpers, conn=conn, implicit_deny=not a.no_implicit_deny, debug=a.debug_emitter)
                num = f"{100 + i:03d}"
                open(os.path.join(tdir, f"{num}-rls-{t}.test.sql"), "w", encoding="utf-8").write(flat)
                if nested is not None:
                    open(os.path.join(ddir, f"{t}.debug.sql"), "w", encoding="utf-8").write(nested)
                print(f"  {a.schema}.{t}: coverage={ctx['cov']}/{ctx['tot']} -> {num}-rls-{t}.test.sql")
            print(f"emitted {len(tables)} test file(s) into:\n  {os.path.abspath(tdir)}")
            if guard:
                print("  + 010-rls-enabled.test.sql (guard: fails if a reachable table has RLS off)")
            print(f"run them with:\n  pg_prove -d \"<your copy>\" {os.path.join(tdir, '*.sql')}")
            print(f"\n{_TAGLINE} {_TAGLINE2}")
            sys.exit(report_gate)
        if not a.table:
            ap.error("--table is required unless --emit is used")
        ctx = _load_ctx(cur, a.schema, a.table)
        if a.describe:
            print(f"\n{a.schema}.{a.table}  commands={ctx['cmds']}  unique={sorted(ctx['unique_cols'])}")
            for cmd in ctx["cmds"]:
                pc = ctx["per"][cmd]
                d = [("GRANT" if not c["rowlinked"] else "+".join(c["kinds"])) + ("" if c["handled"] else f"(NT:{c['reason']})") for c in pc["classes"]]
                print(f"  {cmd}: open={pc['open']} classes=[{', '.join(d) or 'none'}]")
            for x in ctx["notes"]: print(f"  NOTE: {x}")
            print(f"  coverage: {ctx['cov']}/{ctx['tot']}")
            return
        flat, nested = _emit_both(a.schema, a.table, ctx, helpers, conn=conn, implicit_deny=not a.no_implicit_deny, debug=bool(a.out) or a.debug_emitter)
        hook = setup_hook_sql(_basejump_present(cur)) if (a.setup and helpers) else None
    if a.out: open(a.out, "w", encoding="utf-8").write(nested)
    if a.flat: open(a.flat, "w", encoding="utf-8").write(flat)
    if a.setup and hook: open(a.setup, "w", encoding="utf-8").write(hook)
    print(f"cmds={ctx['cmds']} coverage={ctx['cov']}/{ctx['tot']} helpers={helpers} -> out={a.out} flat={a.flat} setup={a.setup if (a.setup and hook) else None}")
    if a.report or a.html:
        sys.exit(report_gate)   # --report/--html combined with --flat/--out: the CI gate still applies



if __name__ == "__main__":
    main()
