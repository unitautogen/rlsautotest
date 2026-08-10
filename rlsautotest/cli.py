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
from .catalog import _FK_SQL, _action_table, _basejump_present, _check_bool_udfs, _columns, _constraint_meta, _effective_grants, _exposed, _fk_by_name, _fk_of, all_tables, auth_profile, rls_tables  # noqa: F401
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
from .report import _DENY_WORDS, _ID_ROWS, _REPORT_SKIP, _as_user_report, _explain_dashes, _id_cell, _id_rows, _table_report, _table_status, render_report_html, render_report_text  # noqa: F401
from .lint import _SEV_ICON, _SEV_ORDER, _lint_table, cmd_lint  # noqa: F401
from .snapshot import cmd_diff, cmd_snapshot  # noqa: F401
from .commands import cmd_coverage, cmd_init, cmd_users  # noqa: F401
from .doctor import cmd_doctor  # noqa: F401


# ── MB-25: --allow-unreliable / .rlsautotestignore -- sanction a reviewed, genuinely-unprobeable UNRELIABLE
# cell so CI passes while the cell stays visible (emitted as a pgTAP SKIP, exempt from the gate, never a
# green pass). Mirrors the --allow-bypass sanctioning pattern. All pure + no-DB (unit-tested).
_CMDS_ALL_MB25 = ("SELECT", "INSERT", "UPDATE", "DELETE")


def _parse_allow_unreliable(entries, ignore_lines=()):
    """Parse --allow-unreliable entries + .rlsautotestignore lines into {(schema_or_None, table): {UPPERCASE cmds}}.
    Grammar: [schema.]table[:CMD]; a bare table -> all four commands. `#` comments and blanks are ignored.
    Raises ValueError naming a bad command (so main() can turn it into an argparse error)."""
    out = {}
    for raw in list(entries or ()) + list(ignore_lines or ()):
        s = (raw or "").strip()
        if not s or s.startswith("#"):
            continue
        tbl, sep, cmd = s.partition(":")
        tbl = tbl.strip()
        if not tbl:
            continue
        head, dot, tail = tbl.rpartition(".")
        key = (head or None, tail) if dot else (None, tbl)
        if sep and cmd.strip():
            c = cmd.strip().upper()
            if c not in _CMDS_ALL_MB25:
                raise ValueError("--allow-unreliable / .rlsautotestignore: '%s' is not a command (use SELECT/INSERT/UPDATE/DELETE, or a bare table for all four)" % cmd.strip())
            cmds = {c}
        else:
            cmds = set(_CMDS_ALL_MB25)
        out.setdefault(key, set()).update(cmds)
    return out


def _sanctioned_cmds_for(sanctions, schema, table):
    """The set of UPPERCASE commands sanctioned for (schema, table); a None-schema entry matches any schema.
    Returns None when nothing matches (the byte-identical default -> emit/report unchanged)."""
    if not sanctions:
        return None
    out = set()
    for (s, t), cmds in sanctions.items():
        if t == table and (s is None or s == schema):
            out |= cmds
    return out or None


def _load_rlsautotestignore(a):
    """Read entry lines from the first existing .rlsautotestignore (cwd, then the Supabase project root)."""
    import os   # module-local: cli.py imports os only inside main(), so keep this helper self-contained
    paths = [os.path.join(os.getcwd(), ".rlsautotestignore")]
    _root = getattr(a, "_sb_root", None)
    if _root:
        paths.append(os.path.join(_root, ".rlsautotestignore"))
    for p in paths:
        try:
            if os.path.isfile(p):
                with open(p, encoding="utf-8") as _fh:
                    return _fh.read().splitlines()
        except Exception:
            pass
    return []



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




def pick_local_db_url(status_output):
    """From `supabase status -o env` text, pick the LOCAL host Postgres URL. Prefer a 127.0.0.1/localhost
    URL over the docker-internal @db:5432 one (only reachable inside the container network); fall back to
    the first postgres URL if none is host-local. Returns None when the text has no postgres URL. Pure, so
    it is unit-tested without a database or the supabase CLI."""
    import re
    urls = [u.strip('"') for u in re.findall(r"postgres(?:ql)?://\S+", status_output or "")]
    return next((u for u in urls if "127.0.0.1" in u or "localhost" in u), (urls[0] if urls else None))


def supabase_keep_set(hook, ext, has_guard, tables):
    """Filenames THIS --supabase run owns: the hook (always), the RLS-enabled guard (when emitted), and one
    file per table (NNN-rls-<t><ext>, NNN = 100 + sorted index). Reconcile uses it to tell current from
    orphaned. Pure."""
    keep = {hook}
    if has_guard:
        keep.add("010-rls-enabled" + ext)
    for i, t in enumerate(sorted(tables), start=1):
        keep.add(f"{100 + i:03d}-rls-{t}" + ext)
    return keep


def orphans_to_prune(dir_listing, keep):
    """Generated files to prune on reconcile: ONLY names ending in _rlsautotest.sql that are not in keep.
    A hand-written test never carries that suffix, so it is never returned here -- the safety property,
    made unit-testable. Pure."""
    keep = set(keep)
    return [f for f in dir_listing if f.endswith("_rlsautotest.sql") and f not in keep]

def main():
    import os, pathlib
    # ── subcommand dispatch (lint / snapshot / diff / users / coverage / init) ──
    if len(sys.argv) > 1 and sys.argv[1] in _SUBCMDS:
        return _SUBCMDS[sys.argv[1]]()

    ap = argparse.ArgumentParser(prog="rlsautotest", description="Generate native pgTAP RLS tests for Supabase/Postgres.")
    ap.add_argument("--schema", help="target schema (required unless --supabase, which defaults it to public)")
    ap.add_argument("--all-schemas", action="store_true", help="scan EVERY RLS-bearing schema and (with --html) write ONE combined dashboard: pick a schema on the left, its full report shows on the right. Use with --report and/or --html (optionally with --supabase to bind to the local Supabase database); not combined with --table/--emit/--as-user/--report-json.")
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
    ap.add_argument("--no-probe", "--structural-only", action="store_true", dest="no_probe", help="STRUCTURAL-ONLY: run ZERO live probes (no INSERT/UPDATE/DELETE, no row synthesis) against the target, so it is safe to point at a production replica. Emits only the tests that need no probing -- the RLS-enabled guard and the column-level-security assertions -- and leaves the row-level matrix NOT tested (partial coverage, honest). Row-level coverage needs a disposable copy without this flag.")
    ap.add_argument("--supabase", action="store_true", help="Supabase project mode: detect the project via supabase/config.toml, default --schema to public, use the LOCAL supabase DB, and write tests straight into supabase/tests/rls/ with a _rlsautotest.sql suffix (runs under supabase test db; never collides with hand-written tests; re-running prunes its own stale generated output and leaves your hand-written tests untouched)")
    ap.add_argument("--db-url", help="Postgres connection string (else uses PG* env)")
    ap.add_argument("--report", action="store_true", help="run the suite and print the grant/deny coverage matrix")
    ap.add_argument("--report-json", help="write the matrix as JSON to this path")
    ap.add_argument("--html", help="run the suite and write an HTML report to this path (the single-command routine)")
    ap.add_argument("--no-fail", action="store_true", help="with --report/--html: do NOT exit non-zero on problems (default: exit 1 if any table is exposed or any check fails — for CI gating)")
    ap.add_argument("--fail-on-bypass", nargs="?", const="CRITICAL", default=None, metavar="SEVERITY",
                    help="OPT-IN (with --report/--html): also fail the CI gate on bypass surfaces (views / SECURITY DEFINER fns / RLS-bypassing roles) at or above SEVERITY (bare flag = CRITICAL). Off by default -- a bypass surface is a review flag unless you opt in; sanction reviewed ones with --allow-bypass so only NEW surfaces fail.")
    ap.add_argument("--allow-bypass", action="append", default=None, metavar="CODE:OBJECT",
                    help="sanction a bypass surface so --fail-on-bypass ignores it: CODE:OBJECT (e.g. L012:recursion.descendants_of(uuid)) or a bare CODE to allow every finding of that code. Repeatable.")
    ap.add_argument("--allow-unreliable", action="append", default=None, metavar="TABLE[:CMD]",
                    help="MB-25: sanction a reviewed, genuinely-unprobeable UNRELIABLE cell so CI passes: [schema.]table[:CMD] (CMD = SELECT/INSERT/UPDATE/DELETE; a bare table sanctions all four). Repeatable. The cell stays visible as UNRELIABLE in the report but is EXEMPT from the exit gate and emitted as a pgTAP SKIP (never a green pass); any UNRELIABLE cell you did not list still fails. The same entries can live in a checked-in .rlsautotestignore at the repo root.")
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
    # -- Supabase project mode (issue #3): zero-config emit into supabase/tests/rls/ --
    a._sb_root = None
    if a.supabase:
        for _p in [pathlib.Path.cwd(), *pathlib.Path.cwd().parents]:
            if (_p / "supabase" / "config.toml").is_file():
                a._sb_root = str(_p); break
        if a._sb_root is None:
            ap.error("--supabase: no supabase/config.toml found from the current directory upward; run this from inside your Supabase project")
        if not a.schema:
            a.schema = "public"
        if not a.db_url:
            # Ask the Supabase CLI for the real local connection string; never hand-build one.
            # `supabase status -o env` reports the host URL (127.0.0.1:<port>); we skip the
            # docker-internal db:5432 URL that only resolves inside the container network.
            import subprocess as _sp, shutil as _sh
            if not _sh.which("supabase"):
                ap.error("--supabase: the `supabase` CLI is not on PATH. Install it and run `supabase start`, or pass --db-url with a disposable database copy.")
            try:
                _st = _sp.run("supabase status -o env", shell=True, cwd=a._sb_root, capture_output=True, text=True, timeout=60)
            except Exception as _e:
                ap.error("--supabase: could not run `supabase status` (%s). Start the local stack with `supabase start`, or pass --db-url." % _e)
            if _st.returncode != 0:
                _tail = ((_st.stderr or _st.stdout or "").strip().splitlines() or ["non-zero exit"])[-1]
                ap.error("--supabase: `supabase status` failed (%s). Start `supabase start`, or pass --db-url with a disposable copy." % _tail)
            _pick = pick_local_db_url(_st.stdout)
            if not _pick:
                ap.error("--supabase: `supabase status` did not report a local database URL. Pass --db-url with a disposable database copy.")
            a.db_url = _pick   # the LOCAL host URL supabase itself reports; never a linked/remote project
    if not a.schema and not a.all_schemas:
        ap.error("--schema is required (use --supabase to default it to public, or --all-schemas to scan every RLS-bearing schema)")
    if a.all_schemas:
        _bad = [nm for nm, on in (("--table", a.table), ("--emit", a.emit), ("--as-user", a.as_user), ("--report-json", a.report_json)) if on]
        if _bad:
            ap.error("--all-schemas cannot be combined with " + ", ".join(_bad) + " (it scans the whole database and writes one combined report)")
        if not (a.report or a.html):
            ap.error("--all-schemas needs --html PATH (combined dashboard) and/or --report (per-schema text)")
    if (a.report or a.html or a.emit) and not a.supabase:
        sys.stderr.write(
            "\nWARNING: rlsautotest runs statements against the database in --db-url to probe\n"
            "each policy -- it seeds rows and executes SELECT/INSERT/UPDATE/DELETE. Each probe is\n"
            "wrapped in a transaction and rolled back (nothing is committed), but the statements DO\n"
            "run (table locks, triggers, sequences fire). Point --db-url at a DISPOSABLE COPY of\n"
            "your database, NEVER production.\n\n"
        )
    # MB-25: resolve the sanctioned-UNRELIABLE set once (--allow-unreliable entries + .rlsautotestignore),
    # validated here so a bad command is an argparse error. Empty by default -> emit/report byte-identical.
    try:
        a._sanctions = _parse_allow_unreliable(getattr(a, "allow_unreliable", None), _load_rlsautotestignore(a))
    except ValueError as _e:
        ap.error(str(_e))
    report_gate = 0   # exit code for the report/emit paths (1 if CI-gating problems found)
    with psycopg.connect(a.db_url or "") as conn, conn.cursor() as cur:
        conn._rlsa_no_probe = bool(getattr(a, "no_probe", False))   # MB-10: structural-only -> the probe + row-synth paths short-circuit
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
            if a.all_schemas:
                from .multi import run_all_schemas
                run_all_schemas(conn, cur, a, helpers)   # discovers every RLS schema, renders, sys.exit()s
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
                prof = auth_profile(cr, a.schema)
                if rls_on and has_pol:
                    rep = _table_report(cr, cn, a.schema, t, helpers, sanctioned=_sanctioned_cmds_for(a._sanctions, a.schema, t))
                else:
                    fg = []
                    if rls_on and not has_pol:   # RLS on, zero policies = deny-all to client roles (safe if intentional, else unintentionally inaccessible)
                        fg.append("RLS is ENABLED but NO POLICY is defined -> every client role (anon/authenticated) is denied ALL access. Safe if intentional (deny-all); otherwise the table is unintentionally inaccessible -> add a policy.")
                    rep = {"table": t, "rls_enabled": rls_on, "policied": [], "cells": {}, "footguns": fg, "coverage": [0, 0]}
                rep["auth"] = prof
                rep["has_policy"] = has_pol
                rep["exposed"] = (not rls_on) and _exposed(cr, a.schema, t)
                rep["grants"] = _effective_grants(cr, a.schema, t)   # per-command grants for ALL roles (incl service_role) — every cell is grant-gated
                from .colsec import column_security
                _cust = sorted({i[5:] for cm in rep.get("idgrid", {}).values() for i in cm if isinstance(i, str) and i.startswith("role:")})
                _cls_roles = ([prof["service_role"]] if prof["service_role"] else []) + ["authenticated", prof["unauth"]]
                rep["column_security"] = column_security(cr, a.schema, t, _cls_roles + _cust)
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
                        c._rlsa_no_probe = bool(getattr(a, "no_probe", False))   # MB-10: propagate to worker connections
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
                    if any(_id_cell(r, k, c)[1] in ("danger", "fail") for k, _ in _id_rows(r) for c in _CMDS4):
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
            # MB-9: OPT-IN CRITICAL-bypass gate. Default OFF -> the bypass surface stays a review flag and every
            # existing suite + gate is byte-identical. With --fail-on-bypass, a finding at or above the chosen
            # severity fails the gate UNLESS its CODE:OBJECT (or a bare CODE) is sanctioned via --allow-bypass --
            # so a reviewed, intentional definer helper is not a false-fail, but a NEW unsanctioned CRITICAL
            # surface is caught in CI. (The 4 corpus definer schemas rbt/recursion/dw/rcw gate only when opted in.)
            bypass_gate = []
            if getattr(a, "fail_on_bypass", None):
                _sevrank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
                _minsev = _sevrank.get(str(a.fail_on_bypass).upper(), 4)
                _allowb = set(getattr(a, "allow_bypass", None) or [])
                for (_bc, _bs, _bo, _bd, _bm) in bypass_findings:
                    if _sevrank.get(_bs, 0) >= _minsev and f"{_bc}:{_bo}" not in _allowb and _bc not in _allowb:
                        bypass_gate.append(f"{_bc} {_bo}")
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
                try:
                    cur.execute("SELECT current_database()"); _dbname = cur.fetchone()[0]
                except Exception:
                    _dbname = None
                open(a.html, "w", encoding="utf-8").write(render_report_html(reps_display, a.schema, bypass_findings, db=_dbname))
                _abs = os.path.abspath(a.html)
                print(f"HTML report for {len(reps_display)} table(s) written to:\n  {_abs}")
                try:    # clickable file:// URL in most terminals
                    print(f"  {pathlib.Path(_abs).as_uri()}")
                except Exception: pass
                print(f"\n{_TAGLINE} {_TAGLINE2}")
            if a.report or not a.html:
                print(render_report_text(reps_display, bypass_findings))   # MB-9: text report shows the bypass surfaces too (HTML/JSON already did)
            # CI gate: fail on any exposed table (RLS off + reachable), any failing/leaking check, or a broken policy
            exposed_any = [r["table"] for r in reps if r.get("exposed")]
            holes_any = [r["table"] for r in reps
                         if any(_id_cell(r, k, c)[1] in ("danger", "fail") for k, _ in _id_rows(r) for c in _CMDS4)]
            broken_any = [r["table"] for r in reps if any("BROKEN POLICY" in f for f in r.get("footguns", []))]
            leak_any = [r["table"] for r in reps if r.get("transition_leaks")]
            multi_any = [r["table"] for r in reps if r.get("multi_findings")]
            # MB-25: an UNRELIABLE table still gates UNLESS every UNRELIABLE cell is sanctioned
            # (--allow-unreliable / .rlsautotestignore). This reduces EXACTLY to the old `r["unreliable"]`
            # test when nothing is sanctioned; a non-cell unreliable condition (e.g. no pgTAP output) always gates.
            unreliable_any = [r["table"] for r in reps
                              if r.get("unreliable")
                              and ((set(r.get("unreliable_cells") or ()) - set(r.get("sanctioned_cells") or ()))
                                   or not r.get("unreliable_cells"))]
            if exposed_any or holes_any or broken_any or leak_any or multi_any or unreliable_any or bypass_gate:
                bits = []
                if exposed_any: bits.append(f"{len(exposed_any)} exposed table(s): {', '.join(exposed_any)}")
                if holes_any:   bits.append(f"{len(holes_any)} table(s) with policy holes/failures: {', '.join(holes_any)}")
                if broken_any:  bits.append(f"{len(broken_any)} broken/unreadable table(s): {', '.join(broken_any)}")
                if leak_any:    bits.append(f"{len(leak_any)} table(s) with cross-policy RLS leaks (read and/or WITH CHECK write): {', '.join(leak_any)}")
                if multi_any:   bits.append(f"{len(multi_any)} table(s) mis-serving users who belong to 2 tenants: {', '.join(multi_any)}")
                if unreliable_any: bits.append(f"{len(unreliable_any)} table(s) with UNRELIABLE tests (result not trustworthy): {', '.join(unreliable_any)}")
                if bypass_gate: bits.append(f"{len(bypass_gate)} unsanctioned bypass surface(s) [--fail-on-bypass]: {', '.join(bypass_gate)}")
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

            if not (a.emit or a.supabase or (a.table and (a.flat or a.out or a.setup))):
                # fall through when test files were ALSO requested (--emit, or single-table --flat/--out/--setup
                # combined with --report/--html: one command produces both, and the gate still exits at the end)
                sys.exit(report_gate)
        if a.emit or a.supabase:
            if a.supabase:
                tdir = os.path.join(a._sb_root, "supabase", "tests", "rls", *( [a.label] if a.label else [] ))
                ddir = os.path.join(a._sb_root, "supabase", ".rlsautotest", "debug", *( [a.label] if a.label else [] ))
                _ext = "_rlsautotest.sql"
                _hook = "000-setup-tests-hooks_rlsautotest.sql"
            else:
                tdir = os.path.join(a.emit, "tests", "database", "rls", *( [a.label] if a.label else [] ))
                ddir = os.path.join(a.emit, ".rlsautotest", "debug", *( [a.label] if a.label else [] ))
                _ext = ".test.sql"
                _hook = "000-setup-tests-hooks.sql"
            os.makedirs(tdir, exist_ok=True)
            if a.debug_emitter: os.makedirs(ddir, exist_ok=True)
            if helpers:
                hookpath = os.path.join(tdir, _hook)
                if not os.path.exists(hookpath):   # non-destructive: never clobber an existing hook
                    open(hookpath, "w", encoding="utf-8").write(setup_hook_sql(_basejump_present(cur), auth_profile(cur, a.schema)))   # MB-11: shim role vocabulary matches the schema's discovered model
            guard = emit_rls_guard(cur, a.schema)   # schema-wide "RLS must be enabled" guard
            if guard:
                open(os.path.join(tdir, "010-rls-enabled" + _ext), "w", encoding="utf-8").write(guard)
            tables = [a.table] if a.table else rls_tables(cur, a.schema)
            for i, t in enumerate(sorted(tables), start=1):
                ctx = _load_ctx(cur, a.schema, t)
                flat, nested = _emit_both(a.schema, t, ctx, helpers, conn=conn, implicit_deny=not a.no_implicit_deny, debug=a.debug_emitter, sanctioned=_sanctioned_cmds_for(a._sanctions, a.schema, t))
                num = f"{100 + i:03d}"
                open(os.path.join(tdir, f"{num}-rls-{t}" + _ext), "w", encoding="utf-8").write(flat)
                if nested is not None:
                    open(os.path.join(ddir, f"{t}.debug.sql"), "w", encoding="utf-8").write(nested)
                print(f"  {a.schema}.{t}: coverage={ctx['cov']}/{ctx['tot']} -> {num}-rls-{t}{_ext}")
            if a.supabase:
                # Reconcile: this folder holds exactly THIS run's generated files, plus your
                # hand-written tests (which never carry the suffix). Prune any orphaned
                # *_rlsautotest.sql a previous run left -- a dropped table, a renumber, an old
                # schema. Runs AFTER a successful write, so a failed probe never deletes your
                # suite. The hook is infrastructure the tests depend on, so it is always kept.
                _keep = supabase_keep_set(_hook, _ext, bool(guard), tables)
                _pruned = 0
                for _name in orphans_to_prune(os.listdir(tdir), _keep):
                    try:
                        os.remove(os.path.join(tdir, _name)); _pruned += 1
                    except OSError:
                        pass
                if _pruned:
                    print(f"  reconciled: removed {_pruned} stale generated file(s) no longer part of this run")
            print(f"emitted {len(tables)} test file(s) into:\n  {os.path.abspath(tdir)}")
            if guard:
                print(f"  + 010-rls-enabled{_ext} (guard: fails if a reachable table has RLS off)")
            print("run them with:\n  supabase test db") if a.supabase else print(f"run them with:\n  pg_prove -d \"<your copy>\" {os.path.join(tdir, '*.sql')}")
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
        flat, nested = _emit_both(a.schema, a.table, ctx, helpers, conn=conn, implicit_deny=not a.no_implicit_deny, debug=bool(a.out) or a.debug_emitter, sanctioned=_sanctioned_cmds_for(a._sanctions, a.schema, a.table))
        hook = setup_hook_sql(_basejump_present(cur), auth_profile(cur, a.schema)) if (a.setup and helpers) else None   # MB-11: flavor-aware shim roles
    if a.out: open(a.out, "w", encoding="utf-8").write(nested)
    if a.flat: open(a.flat, "w", encoding="utf-8").write(flat)
    if a.setup and hook: open(a.setup, "w", encoding="utf-8").write(hook)
    print(f"cmds={ctx['cmds']} coverage={ctx['cov']}/{ctx['tot']} helpers={helpers} -> out={a.out} flat={a.flat} setup={a.setup if (a.setup and hook) else None}")
    if a.report or a.html:
        sys.exit(report_gate)   # --report/--html combined with --flat/--out: the CI gate still applies



if __name__ == "__main__":
    main()
