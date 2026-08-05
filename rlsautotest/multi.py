#!/usr/bin/env python3
# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""--all-schemas orchestration.

rlsautotest normally targets ONE schema per run (--schema). --all-schemas scans
every RLS-bearing schema in the connected database, runs the exact same per-table
probe a single-schema run does, and (with --html) stitches the per-schema reports
into ONE interactive dashboard: a schema picker on the left, that schema's full
report on the right. Each embedded report is byte-identical to that schema's own
`rlsautotest --schema <s> --html` output -- this module only discovers the schema
set and lays the reports out; it never re-implements the report itself.
"""
from __future__ import annotations
import base64
import json
import os
import pathlib
import sys
import html as _html

import psycopg

from .astutil import _CMDS4, _TAGLINE, _TAGLINE2
from .catalog import all_tables, auth_profile, _exposed, _effective_grants
from .bypass import find_bypass
from .report import _ID_ROWS, _id_cell, _table_report, render_report_html, render_report_text
from .colsec import column_security


def discover_rls_schemas(cur):
    """Every user schema that owns at least one RLS-enabled table
    (pg_class.relrowsecurity), sorted alphabetically for a deterministic dashboard.

    Scope: an RLS *tester* has nothing to assert about a schema that uses no
    row-level security, so those are skipped. Within each returned schema EVERY
    table is still probed (RLS-off / exposed tables included) exactly as a
    single-schema run does, so an exposed table inside an RLS-bearing schema is
    still caught. Only a schema where no table has RLS at all is left out.
    """
    cur.execute(
        """
        SELECT DISTINCT n.nspname
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE c.relkind IN ('r', 'p')
           AND c.relrowsecurity
           AND n.nspname !~ '^pg_'
           AND n.nspname <> 'information_schema'
         ORDER BY 1
        """
    )
    return [r[0] for r in cur.fetchall()]


def _probe_schema(conn, cur, a, schema, helpers):
    """Probe every table in `schema`; return (reps, reps_display, bypass_findings).

    Mirrors the single-schema report path in cli.main() one-for-one (same _probe_one
    body, same parallel/sequential switch, same --quiet filter) so that
    render_report_html(reps_display, schema, ...) emits the identical bytes a
    single-schema run would produce for this schema.
    """
    tabs = all_tables(cur, schema)

    def _probe_one(t_tuple, conn_=None, cur_=None):
        cn, cr = (conn_ or conn), (cur_ or cur)
        t, rls_on, has_pol = t_tuple
        prof = auth_profile(cr, schema)
        if rls_on and has_pol:
            rep = _table_report(cr, cn, schema, t, helpers)
        else:
            fg = []
            if rls_on and not has_pol:
                fg.append("RLS is ENABLED but NO POLICY is defined -> every client role (anon/authenticated) is denied ALL access. Safe if intentional (deny-all); otherwise the table is unintentionally inaccessible -> add a policy.")
            rep = {"table": t, "rls_enabled": rls_on, "policied": [], "cells": {}, "footguns": fg, "coverage": [0, 0]}
        rep["auth"] = prof
        rep["has_policy"] = has_pol
        rep["exposed"] = (not rls_on) and _exposed(cr, schema, t)
        rep["grants"] = _effective_grants(cr, schema, t)
        _cust = sorted({i[5:] for cm in rep.get("idgrid", {}).values() for i in cm if isinstance(i, str) and i.startswith("role:")})
        _cls_roles = ([prof["service_role"]] if prof["service_role"] else []) + ["authenticated", prof["unauth"]]
        rep["column_security"] = column_security(cr, schema, t, _cls_roles + _cust)
        return rep

    n_parallel = max(1, getattr(a, "parallel", 1))
    if n_parallel > 1:
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
                try:
                    c.close()
                except Exception:
                    pass
    else:
        reps = [_probe_one(t) for t in tabs]

    if getattr(a, "quiet", False):
        def _has_issues(r):
            if r.get("exposed"):
                return True
            if r.get("footguns"):
                return True
            if any(_id_cell(r, k, c)[1] in ("danger", "fail") for k, _ in _ID_ROWS for c in _CMDS4):
                return True
            return False
        reps_display = [r for r in reps if _has_issues(r)]
    else:
        reps_display = reps

    with conn.cursor() as _bcur:
        bypass_findings = find_bypass(_bcur, schema)
    return reps, reps_display, bypass_findings


def _summary(reps, bypass_findings):
    """Left-list summary for one schema: table count, review flags, and a status
    kind (ok / note / warn) driving the status dot and the header roll-up."""
    tables = len(reps)
    exposed = any(r.get("exposed") for r in reps)
    danger = sum(1 for r in reps for k, _ in _ID_ROWS for c in _CMDS4 if _id_cell(r, k, c)[1] in ("danger", "fail"))
    foot = any(r.get("footguns") for r in reps)
    byp = bool(bypass_findings)
    flags = []
    if exposed:
        flags.append("exposed")
    if byp:
        flags.append("bypass")
    if danger:
        flags.append("%d review cell(s)" % danger)
    if foot and not (danger or byp or exposed):
        flags.append("footgun")
    kind = "warn" if (exposed or byp) else ("note" if (danger or foot) else "ok")
    return {"tables": tables, "flags": flags, "kind": kind}


_DASH_TEMPLATE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RLS Report - all schemas</title>
<style>
 :root{--bg:#f7f8fa;--panel:#fff;--ink:#1c2230;--muted:#5b6472;--line:#e4e7ec;--ok:#1a7f5a;--note:#2f5bd6;--warn:#9a6a00;--sel:#eaf1ff;--selbd:#9db8ff}
 @media (prefers-color-scheme:dark){:root{--bg:#0e1116;--panel:#161b22;--ink:#e7ebf0;--muted:#9aa4b2;--line:#262d38;--ok:#4cc38a;--note:#6b8afd;--warn:#e3b341;--sel:#18233c;--selbd:#31507f}}
 *{box-sizing:border-box} html,body{margin:0} body{background:var(--bg);color:var(--ink);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
 .wrap{max-width:1280px;margin:0 auto;padding:26px 20px 60px}
 h1{margin:0 0 3px;font-size:24px;letter-spacing:-.01em} .sub{margin:0;color:var(--muted);font-size:14px}
 .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
 .chip{display:inline-block;margin:13px 0 2px;padding:6px 12px;border-radius:8px;font-weight:700;font-size:14px}
 .chip.ok{background:rgba(26,127,90,.12);color:var(--ok)} .chip.note{background:rgba(47,91,214,.12);color:var(--note)} .chip.warn{background:rgba(154,106,0,.16);color:var(--warn)}
 .layout{display:flex;gap:18px;margin-top:16px;align-items:flex-start}
 .list{flex:0 0 300px;display:flex;flex-direction:column;gap:5px;max-height:calc(100vh - 40px);overflow:auto;position:sticky;top:14px}
 .item{display:flex;align-items:center;gap:9px;width:100%;text-align:left;cursor:pointer;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:9px 11px;color:inherit;font:inherit}
 .item:hover{border-color:var(--selbd)} .item.sel{background:var(--sel);border-color:var(--selbd)}
 .dot{flex:0 0 auto;width:8px;height:8px;border-radius:50%}
 .dot.ok{background:var(--ok)} .dot.note{background:var(--note)} .dot.warn{background:var(--warn)}
 .itxt{flex:1;min-width:0;display:flex;flex-direction:column;gap:1px}
 .iname{font-size:13.5px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
 .itab{flex:0 0 auto;font-size:11px;color:var(--muted)}
 .detail{flex:1;min-width:0;position:sticky;top:14px}
 .dbar{display:flex;align-items:baseline;gap:10px;padding:0 2px 8px} .dbar b{font-size:16px}
 #detail{width:100%;border:1px solid var(--line);border-radius:12px;background:#fff;min-height:440px;display:block}
 .note{color:var(--muted);font-size:12.5px;margin:8px 2px 0}
 @media (max-width:860px){ .layout{flex-direction:column} .list{flex:none;width:100%;max-height:320px;position:static} .detail{position:static;width:100%} }
</style></head><body><div class="wrap">
 <h1>RLS Report</h1>
 <p class="sub">@@SUB@@</p>
 <div class="chip @@CHIPKIND@@">@@COUNT@@ schema(s) &middot; @@CHIP@@</div>
 <div class="note">Click a schema on the left to load its full report on the right. The tag after each name is its table count and any review flags (exposed table / bypass surface / cells to review / footgun) -- findings to read, not necessarily test failures.</div>
 <div class="layout">
   <div class="list" role="tablist">@@ITEMS@@</div>
   <div class="detail">
     <div class="dbar"><b id="dtitle" class="mono">&nbsp;</b><span id="ddesc" class="sub"></span></div>
     <iframe id="detail" title="schema report"></iframe>
   </div>
 </div>
 <p class="note" style="margin-top:22px">Each report is the exact per-schema rlsautotest HTML output, embedded. Generated by rlsautotest - part of UnitAutogen.</p>
</div>
<script>
const REPORTS = @@REPORTS@@;
function b64utf8(b){ return new TextDecoder().decode(Uint8Array.from(atob(b), function(c){ return c.charCodeAt(0); })); }
const frame = document.getElementById('detail');
function fit(){ try{ frame.style.height = (frame.contentWindow.document.body.scrollHeight + 40) + 'px'; }catch(e){} }
frame.addEventListener('load', fit);
function show(s){
  document.querySelectorAll('.item').forEach(function(b){ b.classList.toggle('sel', b.dataset.s === s); });
  document.getElementById('dtitle').textContent = s;
  frame.srcdoc = b64utf8(REPORTS[s]);
  if (window.matchMedia('(max-width:860px)').matches) frame.scrollIntoView({behavior:'smooth', block:'start'});
}
document.querySelectorAll('.item').forEach(function(b){ b.addEventListener('click', function(){ show(b.dataset.s); }); });
var first = document.querySelector('.item'); if (first) show(first.dataset.s);
</script>
</body></html>"""


def render_all_schemas_html(schemas, db=None):
    """Build the combined dashboard from an ordered list of per-schema dicts
    {schema, html, tables, flags, kind}. Pure function of its inputs (each report is
    base64-embedded and swapped into the iframe on click) so it is unit-testable."""
    reports = {}
    items = []
    n_warn = n_note = 0
    for s in schemas:
        name = s["schema"]
        reports[name] = base64.b64encode(s["html"].encode("utf-8")).decode("ascii")
        kind = s.get("kind", "ok")
        if kind == "warn":
            n_warn += 1
        elif kind == "note":
            n_note += 1
        tabs = s.get("tables", 0)
        flags = s.get("flags") or []
        fl = ", ".join(flags) if flags else "clean"
        tail = "" if fl == "clean" else " &middot; " + _html.escape(fl)
        items.append(
            '<button class="item" data-s="%s" role="tab">'
            '<span class="dot %s"></span>'
            '<span class="itxt"><span class="iname mono">%s</span></span>'
            '<span class="itab">%dt%s</span></button>'
            % (_html.escape(name), kind, _html.escape(name), tabs, tail))
    if n_warn:
        chip_kind, chip_txt = "warn", "%d schema(s) need review" % n_warn
    elif n_note:
        chip_kind, chip_txt = "note", "%d schema(s) with notes" % n_note
    else:
        chip_kind, chip_txt = "ok", "no issues found"
    sub = "rlsautotest across every RLS-bearing schema"
    if db:
        sub += ' &middot; database <span class="mono">%s</span>' % _html.escape(db)
    page = (_DASH_TEMPLATE
            .replace("@@ITEMS@@", "".join(items))
            .replace("@@SUB@@", sub)
            .replace("@@CHIPKIND@@", chip_kind)
            .replace("@@CHIP@@", _html.escape(chip_txt))
            .replace("@@COUNT@@", str(len(schemas)))
            .replace("@@REPORTS@@", json.dumps(reports)))
    return page


def run_all_schemas(conn, cur, a, helpers):
    """Entry point for --all-schemas: discover the RLS-bearing schemas, probe each,
    write the combined dashboard (--html) and/or per-schema text (--report), apply the
    aggregate CI gate, and exit the process (never returns)."""
    schemas = discover_rls_schemas(cur)
    if not schemas:
        print("No RLS-bearing schemas found (no table has RLS enabled in any user schema).")
        sys.exit(0)

    try:
        cur.execute("SELECT current_database()")
        dbname = cur.fetchone()[0]
    except Exception:
        dbname = None

    combined = []
    all_reps = []
    quiet_all_clean = True

    print("scanning %d RLS-bearing schema(s): %s" % (len(schemas), ", ".join(schemas)))
    for s in schemas:
        try:
            conn.rollback()   # clean slate between schemas (probes roll themselves back; belt and braces)
        except Exception:
            pass
        reps, reps_display, bypass_findings = _probe_schema(conn, cur, a, s, helpers)
        all_reps.append((s, reps))
        if reps_display:
            quiet_all_clean = False

        if a.html:
            hs = render_report_html(reps_display, s, bypass_findings, db=dbname)
            meta = _summary(reps, bypass_findings)
            meta.update({"schema": s, "html": hs})
            combined.append(meta)

        if a.report or not a.html:
            print("\n===== schema: %s =====" % s)
            print(render_report_text(reps_display))

    if a.html:
        with open(a.html, "w", encoding="utf-8") as fh:
            fh.write(render_all_schemas_html(combined, db=dbname))
        abs_ = os.path.abspath(a.html)
        print("\nCombined HTML report for %d schema(s) written to:\n  %s" % (len(combined), abs_))
        try:
            print("  %s" % pathlib.Path(abs_).as_uri())
        except Exception:
            pass
        print("\n%s %s" % (_TAGLINE, _TAGLINE2))

    if getattr(a, "quiet", False) and quiet_all_clean:
        print("\nAll %d table(s) across %d schema(s) clean -- no issues found." % (
            sum(len(r) for _s, r in all_reps), len(all_reps)))

    def q(s, t):
        return "%s.%s" % (s, t)
    exposed_any, holes_any, broken_any, leak_any, unreliable_any = [], [], [], [], []
    for s, reps in all_reps:
        exposed_any += [q(s, r["table"]) for r in reps if r.get("exposed")]
        holes_any += [q(s, r["table"]) for r in reps
                      if any(_id_cell(r, k, c)[1] in ("danger", "fail") for k, _ in _ID_ROWS for c in _CMDS4)]
        broken_any += [q(s, r["table"]) for r in reps if any("BROKEN POLICY" in f for f in r.get("footguns", []))]
        leak_any += [q(s, r["table"]) for r in reps if r.get("transition_leaks")]
        unreliable_any += [q(s, r["table"]) for r in reps if r.get("unreliable")]

    gate = 0
    if exposed_any or holes_any or broken_any or leak_any or unreliable_any:
        bits = []
        if exposed_any:
            bits.append("%d exposed table(s): %s" % (len(exposed_any), ", ".join(exposed_any)))
        if holes_any:
            bits.append("%d table(s) with policy holes/failures: %s" % (len(holes_any), ", ".join(holes_any)))
        if broken_any:
            bits.append("%d broken/unreadable table(s): %s" % (len(broken_any), ", ".join(broken_any)))
        if leak_any:
            bits.append("%d table(s) with cross-policy RLS leaks (read and/or WITH CHECK write): %s" % (len(leak_any), ", ".join(leak_any)))
        if unreliable_any:
            bits.append("%d table(s) with UNRELIABLE tests (seed/precondition failed): %s" % (len(unreliable_any), ", ".join(unreliable_any)))
        print("\nFAIL: " + "; ".join(bits) + ("" if a.no_fail else "  (exit 1 -- CI gate; pass --no-fail to suppress)"))
        gate = 0 if a.no_fail else 1

    sys.exit(gate)