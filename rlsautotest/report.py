# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""Per-identity x command access-matrix report (text + HTML renderers).

Split out of the original single-module cli.py; behavior-preserving.
"""
from __future__ import annotations
import json
import re
from .astutil import _CMDS4, _HOME, _TAGLINE, _TAGLINE2, _split_statements
from .emit import _emit_both, _load_ctx



_REPORT_SKIP = re.compile(r"^\s*(BEGIN|COMMIT|ROLLBACK)\s*;?\s*$|FROM\s+finish\s*\(", re.I)

_DENY_WORDS = ("unauthorized", "anon", "nothing", "cannot", "affects 0", "out of scope")



def _file_tap_lines(taplines, obs, cells, idgrid, leak_msgs, unreliable_msgs, unreliable_cells):
    """F4 structural filing: match each numbered TAP line to the emitter's own Observation (by the
    pgTAP test number == plan-order index) and file the matrix cell from the Observation — the
    English label is display-only, so a strategy's wording can no longer misfile a cell. Returns
    the lines that had NO usable Observation, for the legacy label-keyword fallback (e.g. a file
    emitted by an older version, or an index misalignment — safety net, never a crash)."""
    leftovers = []
    for ln in taplines:
        first = ln.strip().split("\n", 1)[0]   # a FAILING pgTAP test returns 'not ok' + '#'-diagnostic lines; parse the 'not ok' line only
        m = re.match(r"(ok|not ok)\s+(\d+)\s*-\s*(.*)$", first)
        if m:
            passed, num, label = m.group(1) == "ok", int(m.group(2)), m.group(3)
        else:
            m = re.match(r"(ok|not ok)\b.*?-\s*(.*)$", first)
            if not m:
                continue
            passed, num, label = m.group(1) == "ok", None, m.group(2)
        ob = obs[num - 1] if (num is not None and 1 <= num <= len(obs)) else None
        if ob is None or getattr(ob, "kind", None) in (None, "unknown"):
            leftovers.append((ln, label, passed))
            continue
        if ob.kind == "unreliable":
            unreliable_msgs.append(label)
            unreliable_cells.add((ob.cmd, ob.ident or "authorized"))
            continue
        if ob.kind == "leak":
            if not passed: leak_msgs.append(label.replace(" [transition-leak]", ""))
            continue
        d = cells.setdefault(ob.cmd, {})
        side = "grant" if ob.exp else "deny"
        d[side] = d.get(side, True) and passed
        ident = ob.ident or "authorized"
        g = idgrid.setdefault(ob.cmd, {}).setdefault(ident, {"exp": ob.exp, "pass": True})
        g["exp"] = ob.exp; g["pass"] = g["pass"] and passed
    return leftovers



def _table_report(cur, conn, schema, table, helpers):
    """Run the SELF-CONTAINED flat battery (robust: seeds as the connection role, no service_role /
    shim dependency) statement-by-statement, collect each pgTAP assertion's returned line, and parse
    its descriptive label into a grant/deny matrix. Rolled back so nothing persists."""
    ctx = _load_ctx(cur, schema, table)
    obs = []   # F4: one Observation per emitted test, in plan order — the structural report contract
    flat = _emit_both(schema, table, ctx, helpers=False, conn=conn, obs_out=obs)[0]
    taplines = []
    try:
        for st in _split_statements(flat):
            if not st.strip() or _REPORT_SKIP.match(st):
                continue
            cur.execute("SAVEPOINT _rlsa_rep")   # per-statement isolation: a failing SEED must not abort the
            try:                                  # whole battery -> the UNRELIABLE fail() assertions still run
                cur.execute(st)
                if cur.description:
                    for r in cur.fetchall():
                        v = r[0]
                        if isinstance(v, str) and (v.startswith("ok") or v.startswith("not ok")):
                            taplines.append(v)
                cur.execute("RELEASE SAVEPOINT _rlsa_rep")
            except Exception:
                try: cur.execute("ROLLBACK TO SAVEPOINT _rlsa_rep")
                except Exception: pass
    except Exception:
        pass
    finally:
        conn.rollback()
    cells = {}
    idgrid = {}   # cmd -> { identity -> {"exp": <should-be-able>, "pass": <test passed>} }
    leak_msgs = []   # cross-policy WITH CHECK transition leaks (baked as failing throws_ok lines)
    unreliable_msgs = []   # tests whose precondition (seed) could not be established -> not trustworthy
    unreliable_cells = set()
    # UNRELIABLE is a GENERATION-TIME fact (the probe's precondition failed), not a replay outcome:
    # file those cells straight from the Observations so they show ‼ even when the replay itself could
    # not produce TAP output (e.g. the connection role cannot create the pgTAP shim -- issue #2).
    for ob in obs:
        if getattr(ob, "kind", None) == "unreliable":
            unreliable_cells.add((ob.cmd, ob.ident or "authorized"))
    _filed = _file_tap_lines(taplines, obs, cells, idgrid, leak_msgs, unreliable_msgs, unreliable_cells)
    if obs and not taplines:
        unreliable_msgs.append("the report battery produced NO pgTAP output when replayed (pgTAP is not "
                               "installed and the fallback shim could not be created by this connection role); "
                               "run `rlsautotest doctor` to diagnose the probe environment")
    for ln, label, passed in _filed:   # lines with NO matching Observation -> legacy label-keyword parsing
        if "UNRELIABLE" in label:                              # precondition (seed) failed -> not a grant/deny cell; flag it
            unreliable_msgs.append(label)
            _lowu = label.lower()
            _cmdu = next((c for c in _CMDS4 if c in label.upper()), None)
            _idu = ("anon" if "anon" in _lowu else "other" if any(k in _lowu for k in ("not authoriz", "other user", "non-owner", "unauthorized")) else "authorized")
            if _cmdu: unreliable_cells.add((_cmdu, _idu))
            continue
        if "[transition-leak]" in label:                       # value-space leak; tracked separately, not a per-command cell
            if not passed: leak_msgs.append(label.replace(" [transition-leak]", ""))
            continue
        cmd = next((c for c in _CMDS4 if label.upper().startswith(c)), None)
        if not cmd: continue
        low = label.lower()
        side = "deny" if any(k in low for k in _DENY_WORDS) else "grant"
        d = cells.setdefault(cmd, {}); d[side] = d.get(side, True) and passed
        # per-identity classification (for the access matrix)
        if "out of scope" in low:        # sub-deny on an authorized row; not a primary cell
            continue
        # identity from the label
        if "anon" in low:
            ident = "anon"
        elif any(k in low for k in ("not authoriz", "other user", "non-owner", "unauthorized")):
            ident = "other"   # authenticated but NOT authorized by the policy
        else:
            ident = "authorized"
        # can/blocked from the observed outcome (probe labels) or the derived wording (fallback)
        if any(k in low for k in ("denied", " 0 row", "sees nothing", "blocks", "blocked", "cannot")):
            exp = False
        elif any(k in low for k in ("sees all", "public", "permits", "row(s)", "may ", " can ")):
            exp = True
        else:
            exp = True
        g = idgrid.setdefault(cmd, {}).setdefault(ident, {"exp": exp, "pass": True})
        g["exp"] = exp; g["pass"] = g["pass"] and passed
    cur.execute("SELECT c.relrowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s AND c.relname=%s", (schema, table))
    r = cur.fetchone(); rls_on = bool(r and r[0])
    cur.execute("SELECT cmd FROM pg_policies WHERE schemaname=%s AND tablename=%s", (schema, table))
    pol = set()
    for (cmd,) in cur.fetchall():
        pol |= set(_CMDS4) if cmd == "ALL" else {cmd}
    notes = list(ctx["notes"])
    if any("[mocked" in ln for ln in taplines):
        notes.append("opaque policy function(s) were MOCKED to prove the policy delegates correctly (wiring) — the function's own logic is NOT verified here; test it separately")
    if any("42P17" in ln or "infinite recursion" in ln.lower() for ln in taplines):
        notes.append("BROKEN POLICY: a policy queries its own table (self-referential) -> Postgres raises 'infinite recursion detected in policy' -> the table is UNREADABLE by everyone. Use a SECURITY DEFINER helper function instead.")
    if leak_msgs:
        notes.append("SECURITY HOLE - cross-policy WITH CHECK leak (Postgres OR-combines every permissive policy's WITH CHECK, so an authorized identity can write a value only a DIFFERENT policy intended): " + "; ".join(sorted(set(leak_msgs))))
    if unreliable_msgs:
        notes.append("UNRELIABLE TEST(S) - the test precondition (seed) could not be established for some identity/command, so the result is NOT trustworthy and the suite fails loudly rather than asserting a possibly-wrong outcome (investigate seeding): " + "; ".join(sorted(set(s.replace("UNRELIABLE - ", "") for s in unreliable_msgs))))
    if "UPDATE" in pol and not idgrid.get("UPDATE", {}).get("authorized") and ("UPDATE", "authorized") not in unreliable_cells:
        notes.append("UPDATE not fully tested - no policy-neutral column to modify AND nothing safely self-assignable (every column is identity/generated or unique), so the UPDATE permission could not be probed by SETting a harmless column or by SET col=col. The '-' for UPDATE is a coverage gap, not a pass; review manually.")
    rep = {"table": table, "rls_enabled": rls_on, "policied": sorted(pol),
           "cells": cells, "idgrid": idgrid, "footguns": notes, "coverage": [ctx["cov"], ctx["tot"]],
           "transition_leaks": leak_msgs, "unreliable": sorted(set(unreliable_msgs)), "unreliable_cells": unreliable_cells}
    # Explain EVERY '–' (not-tested) cell so a dash is never silent (NT-atom note + catch-all). See _explain_dashes.
    notes.extend(_explain_dashes(rep, ctx["per"], notes))
    return rep



# identities shown as rows in each table's access grid (key, display label)
# Rows in each table's access grid: (internal key, display label).
# NOTE: 'authorized' and 'other' are NOT Postgres roles — both connect as the `authenticated`
# role and differ only by JWT identity/claims. Only service_role / authenticated / anon are real
# DB roles. Labels say so explicitly so the grid isn't misread as a per-role matrix.
_ID_ROWS = [("service_role", "service_role"), ("authorized", "authenticated, authorized"),
            ("other", "authenticated, not authorized"), ("anon", "anon")]



def _id_cell(rep, ident, cmd):
    """One identity x command cell -> (glyph, css-class, title).
    glyph: ✓ can · blocked ✗ should-be-allowed-but-blocked.  class 'danger' = can-but-shouldn't (hole)."""
    rls_on = rep["rls_enabled"]; policied = rep.get("policied", []); exposed = rep.get("exposed")
    if ident == "service_role":
        # service_role bypasses RLS, but BYPASSRLS does NOT grant table privileges — it still needs the GRANT.
        # PREFER the tested observation (the battery probes service_role like every other identity);
        # the grants-map inference below remains only as the fallback when no test could be constructed.
        if (cmd, "service_role") in rep.get("unreliable_cells", set()):
            return ("‼", "unrel", "UNRELIABLE — the service_role test's precondition (seed) could not be established")
        g0 = rep.get("idgrid", {}).get(cmd, {}).get("service_role")
        if g0:
            exp, passed = g0["exp"], g0["pass"]
            observed_can = exp if passed else (not exp)
            if passed:
                return ("✓", "svc", "service_role — full access (observed and tested)") if observed_can else \
                       ("·", "none", f"service_role has no {cmd} grant on this table — denied (observed and tested; grant it if your backend needs it)")
            if observed_can:
                return ("✓", "danger", "service_role CAN act but the suite recorded a denial — the database drifted since generation; investigate")
            return ("✗", "fail", "service_role SHOULD have access but is blocked — the database drifted since generation (revoked grant?); investigate")
        g = rep.get("grants")
        if g is not None and not g.get(("service_role", cmd), True):
            return ("·", "none", f"service_role has no {cmd} grant on this table — even the service key is denied (grant it if your backend needs it)")
        return ("✓", "svc", "service_role bypasses RLS — full, unfiltered access")
    if not rls_on:
        # RLS off -> access is governed PURELY by GRANTs. A command is an unfiltered hole ONLY if the role
        # actually holds that command's privilege; a missing grant blocks it. Use the per-command grant map
        # (both authenticated identities are the SAME `authenticated` role) rather than a blanket flag.
        role = "anon" if ident == "anon" else "authenticated"
        g = rep.get("grants")
        if g is not None:
            if g.get((role, cmd)):
                return ("✓", "danger", f"RLS off and {role} holds the {cmd} grant — every row is {('readable' if cmd=='SELECT' else 'writable')} unfiltered (no policy constrains it)")
            return ("·", "none", f"RLS off, but {role} has no {cmd} grant — blocked for this command")
        # fallback (no grant map): the old table-level heuristic
        if ident == "anon":
            return ("✓", "danger", "RLS off — anon can read every row") if (exposed and cmd == "SELECT") else ("·", "none", "anon has no grant for this command")
        return ("✓", "danger", "RLS off — any authenticated user has unfiltered access") if exposed else ("·", "none", "RLS off, but no client grant — unreachable via the API")
    if cmd not in policied:
        return ("·", "none", "no policy for this command (implicit deny)")
    if (cmd, ident) in rep.get("unreliable_cells", set()):
        return ("‼", "unrel", "UNRELIABLE — the test precondition (seed) could not be established, so this result is NOT trustworthy (the suite fails loudly here; see notes)")
    g = rep.get("idgrid", {}).get(cmd, {}).get(ident)
    if not g:
        if ident == "anon" and cmd != "SELECT":
            return ("·", "none", "anon has no write grant")
        return ("–", "na", "not tested")
    exp, passed = g["exp"], g["pass"]
    observed_can = exp if passed else (not exp)
    if passed:
        return ("✓", "pass", "can — enforced as declared") if observed_can else ("·", "none", "blocked — enforced as declared")
    if observed_can:
        return ("✓", "danger", "SHOULD be blocked but CAN act — security hole")
    return ("✗", "fail", "SHOULD be allowed but is blocked — policy too strict")



def _explain_dashes(rep, per, notes):
    """Explain EVERY '–' (not-tested) cell so a dash is NEVER silent. Returns the note(s) to append.
    Two kinds, keyed on the ACTUAL matrix (`_id_cell` 'na') so cells the solver/mock DID cover never trip it:
      (a) the command carries an unhandled-class `reason` (an operator/atom we can't witness soundly:
          `~`/`LIKE`, an opaque expression, an unsatisfiable NOT-IN, …) -> the NOT TESTABLE note; and
      (b) a '–' with NO known reason on an otherwise-handled command -> the catch-all note: a seed row the
          engine couldn't synthesize, or an identity a fallback emitter didn't probe. The UPDATE-no-neutral
          case is excluded (it prints its own note, already in `notes`).
    This is the report-side guarantee behind 'NT can never go silent': pair it with the loud UNRELIABLE /
    BROKEN paths (which fail the gate) and every untested cell is accounted for."""
    if not rep.get("rls_enabled"):
        return []
    out = []
    nt_cells = [(cmd, idr) for (idr, _l) in _ID_ROWS if idr != "service_role"
                for cmd in _CMDS4 if _id_cell(rep, idr, cmd)[1] == "na"]
    nt_cmds = sorted({c for (c, _i) in nt_cells})
    cmd_reasons = {cmd: sorted({c.get("reason") for c in per.get(cmd, {}).get("classes", [])
                                if not c.get("handled") and c.get("reason")}) for cmd in nt_cmds}
    nt_reasons = sorted({r for rs in cmd_reasons.values() for r in rs})
    if nt_reasons:
        out.append("NOT TESTABLE ('–' cells): the engine could not construct a sound witness for part of the "
                   "policy, so it left those cells UNTESTED rather than guess (never a fabricated pass) -> "
                   + "; ".join(nt_reasons) + ". Run `--debug-unhandled` for the exact branch(es) and test them separately.")
    _upd_noneutral = any("no policy-neutral column" in f for f in notes)
    unexplained = sorted({c for (c, _i) in nt_cells
                          if not cmd_reasons.get(c) and not (c == "UPDATE" and _upd_noneutral)})
    if unexplained:
        out.append("UNTESTED ('–') with no established cause on: " + ", ".join(unexplained)
                   + ". The engine could not establish a sound test for these cells — most often a seed row it "
                   "could not synthesize (an unsatisfiable CHECK/FK, a UNIQUE collision, or a column type the "
                   "filler doesn't know), occasionally a coverage gap. Treat them as NOT verified (never a pass); "
                   "inspect the table's constraints, seed a row by hand, or run `--debug-unhandled`.")
    return out



def _table_status(r):
    if not r["rls_enabled"]:
        return ("⛔ RLS OFF — exposed", "danger") if r.get("exposed") else ("⚠ RLS OFF (no client grant)", "warn")
    return ("RLS on", "on")



def render_report_text(reps):
    out = []
    exposed = [r["table"] for r in reps if not r["rls_enabled"] and r.get("exposed")]
    if exposed:
        out.append("⛔ EXPOSED — RLS OFF and readable/writable by anon/authenticated: " + ", ".join(exposed))
        out.append("")
    for r in reps:
        st, _ = _table_status(r)
        out.append(f"{r['table']}  [{st}]")
        out.append(f"  {'identity':<31}" + "".join(f"{c:<9}" for c in _CMDS4))
        _rows = _ID_ROWS + [(k, f"{k[5:]} (custom role)") for k in sorted(
            {i for cm in r.get("idgrid", {}).values() for i in cm if isinstance(i, str) and i.startswith("role:")})]
        for key, lbl in _rows:
            line = f"  {lbl:<31}"
            for c in _CMDS4:
                g, cls, _ = _id_cell(r, key, c)
                glyph = g + ("!" if cls == "danger" else "")   # ! = behaves wrong (hole)
                line += f"{glyph:<9}"
            out.append(line)
        for fn in r["footguns"]:
            out.append(f"    ! footgun: {fn}")
        out.append("")
    out.append("legend: ✓ can · blocked/none ✗ should-be-allowed-but-blocked  ✓! = should be blocked but CAN (security hole)  ‼ UNRELIABLE (seed/precondition failed — not trustworthy)  – not tested")
    out.append("service_role bypasses RLS by design (always full access).")
    out.append("note: 'authenticated, authorized' and 'authenticated, not authorized' are the SAME Postgres role (authenticated) under different JWT identities/claims — NOT separate DB roles. Only service_role, authenticated and anon are real Postgres roles; 'authorized' vs 'not authorized' is the policy outcome for that identity.")
    out.append("")
    out.append(_TAGLINE + " " + _TAGLINE2)
    return "\n".join(out)



def render_report_html(reps, schema):
    import html as _h
    esc = _h.escape
    exposed = [r["table"] for r in reps if not r["rls_enabled"] and r.get("exposed")]
    offsafe = [r["table"] for r in reps if not r["rls_enabled"] and not r.get("exposed")]
    def has_hole(r):
        return any(_id_cell(r, k, c)[1] in ("danger", "fail", "unrel") for k, _ in _ID_ROWS for c in _CMDS4)
    holes = [r["table"] for r in reps if has_hole(r)]
    ok_tables = [r for r in reps if r["rls_enabled"] and not has_hole(r)]
    # order: tables with holes/exposure first, then the rest
    order = sorted(reps, key=lambda r: (not has_hole(r), r["table"]))
    blocks = []
    for r in order:
        st, stcls = _table_status(r)
        grid_rows = []
        _hrows = _ID_ROWS + [(k, f"{k[5:]} (custom role)") for k in sorted(
            {i for cm in r.get("idgrid", {}).values() for i in cm if isinstance(i, str) and i.startswith("role:")})]
        for key, lbl in _hrows:
            tds = []
            for c in _CMDS4:
                g, cls, title = _id_cell(r, key, c)
                tds.append(f'<td class="c {cls}" title="{esc(title)}">{g}</td>')
            note = ' <span class="rolenote">bypasses RLS</span>' if key == "service_role" else ""
            grid_rows.append(f'<tr><td class="idn">{esc(lbl)}{note}</td>{"".join(tds)}</tr>')
        flags = "".join(f'<li>{esc(f)}</li>' for f in r.get("footguns", []))
        flags_html = f'<ul class="flags">{flags}</ul>' if flags else ""
        blocks.append(
            f'<section class="tbl"><h2>{esc(r["table"])} <span class="chip {stcls}">{esc(st)}</span></h2>'
            f'<table class="grid"><thead><tr><th>identity</th>'
            + "".join(f"<th>{c}</th>" for c in _CMDS4) + "</tr></thead><tbody>"
            + "".join(grid_rows) + f"</tbody></table>{flags_html}</section>")
    banner = ""
    if exposed:
        banner += f'<div class="ban danger"><b>⛔ Exposed</b> — RLS is OFF and these tables are readable/writable by anon/authenticated: {esc(", ".join(exposed))}</div>'
    if offsafe:
        banner += f'<div class="ban warn"><b>⚠ RLS off</b> (no client grant, but unprotected): {esc(", ".join(offsafe))}</div>'
    summary = (f'{len(reps)} table(s) &middot; '
               f'<span class="kpi {"bad" if exposed else "good"}">{len(exposed)} exposed</span> &middot; '
               f'<span class="kpi {"bad" if holes else "good"}">{len(holes)} with problems</span> &middot; '
               f'<span class="kpi good">{len(ok_tables)} enforced as declared</span>')
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>rlsautotest — RLS report ({esc(schema)})</title>
<style>
 body{{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;color:#1a1a1a}}
 h1{{font-size:1.4rem;margin:0 0 .25rem}} .sub{{color:#666;margin:0 0 1rem}}
 .summary{{margin:.5rem 0 1rem}} .kpi{{font-weight:600}} .good{{color:#15803d}} .bad{{color:#b91c1c}}
 .ban{{padding:.6rem .8rem;border-radius:6px;margin:.4rem 0}}
 .ban.danger{{background:#fee2e2;border:1px solid #fca5a5;color:#7f1d1d}} .ban.warn{{background:#fef3c7;border:1px solid #fcd34d;color:#92400e}}
 section.tbl{{margin:1.5rem 0}}
 section.tbl h2{{font-size:1.05rem;margin:0 0 .4rem}}
 .chip{{font-size:.72rem;font-weight:600;padding:.1rem .5rem;border-radius:999px;vertical-align:middle}}
 .chip.on{{background:#e0f2fe;color:#075985}} .chip.danger{{background:#fee2e2;color:#b91c1c}} .chip.warn{{background:#fef3c7;color:#92400e}}
 table.grid{{border-collapse:collapse;min-width:32rem}}
 .grid th,.grid td{{border:1px solid #e5e7eb;padding:.4rem .7rem}}
 .grid th{{background:#f9fafb;font-weight:600;text-align:center}} .grid th:first-child{{text-align:left}}
 td.idn{{font-weight:600;white-space:nowrap}} .rolenote{{font-weight:400;color:#888;font-size:.78rem}}
 td.c{{text-align:center;font-size:1.05rem}}
 .pass{{background:#dcfce7;color:#15803d}} .none{{color:#94a3b8}} .na{{color:#94a3b8}}
 .svc{{background:#f1f5f9;color:#475569}}
 .danger{{background:#dc2626;color:#fff;font-weight:700}} .fail{{background:#fee2e2;color:#b91c1c;font-weight:700}}
 .unrel{{background:#fde68a;color:#92400e;font-weight:700}}
 ul.flags{{margin:.4rem 0 0;padding-left:1.1rem;color:#92400e;font-size:.85rem}}
 .legend{{color:#666;font-size:.85rem;margin-top:1.5rem;max-width:48rem}}
 .footer{{color:#888;font-size:.8rem;margin-top:1.2rem;border-top:1px solid #eee;padding-top:.6rem}}
</style></head><body>
<h1>RLS access report</h1>
<p class="sub">schema <code>{esc(schema)}</code> &middot; generated by <a href="{_HOME}">rlsautotest</a></p>
<div class="summary">{summary}</div>
{banner}
{"".join(blocks)}
<p class="legend"><b>Each row is an identity, each column a command.</b>
 <span class="c pass">✓</span> can &middot; <span class="c none">·</span> blocked &middot;
 <span class="c danger">✓</span> can but <b>should be blocked</b> (security hole) &middot;
 <span class="c fail">✗</span> should be allowed but is blocked &middot;
 <span class="c unrel">‼</span> UNRELIABLE — seed/precondition failed, result not trustworthy &middot; – not tested.
 <b>service_role</b> bypasses RLS by design. “Enforced as declared” means the database behaves the way your
 policies say — not that the policies are what you intended.</p>
<p class="legend"><b>About the identities:</b> <code>authenticated, authorized</code> and
 <code>authenticated, not authorized</code> are the <b>same Postgres role</b> (<code>authenticated</code>)
 under different JWT identities/claims — they are <b>not</b> separate database roles. Only
 <code>service_role</code>, <code>authenticated</code> and <code>anon</code> are real Postgres roles;
 “authorized” vs “not authorized” is simply whether that identity passes the table’s policies.</p>
<p class="footer">{esc(_TAGLINE)} <a href="{_HOME}">Need it for SQL Server (tSQLt), Oracle, or Azure?</a></p>
</body></html>
"""



# ── as-user probe ─────────────────────────────────────────────────────────────
def _as_user_report(conn, cur, schema, table, user_id, app_meta, user_meta):
    """Quick per-command probe as a specific auth.users identity."""
    claims = json.dumps({"sub": str(user_id), "role": "authenticated",
                          "app_metadata": app_meta or {}, "user_metadata": user_meta or {}})
    CMDS4 = ["SELECT", "INSERT", "UPDATE", "DELETE"]
    results = {}
    for cmd in CMDS4:
        sp = f"_asuser_{cmd.lower()}"
        try:
            if cmd == "SELECT":
                action = f"SELECT count(*) FROM {schema}.{table}"
            elif cmd == "INSERT":
                cur.execute(f"SELECT attname, format_type(atttypid,atttypmod) FROM pg_attribute a "
                            f"JOIN pg_class c ON c.oid=a.attrelid "
                            f"JOIN pg_namespace n ON n.oid=c.relnamespace "
                            f"WHERE n.nspname=%s AND c.relname=%s AND a.attnum>0 AND NOT a.attisdropped "
                            f"LIMIT 1", (schema, table))
                col_row = cur.fetchone()
                if not col_row:
                    results[cmd] = "–"
                    continue
                col, typ = col_row
                action = f"INSERT INTO {schema}.{table}({col}) VALUES (NULL::text::{typ}) RETURNING 1"
            elif cmd == "UPDATE":
                cur.execute(f"SELECT attname FROM pg_attribute a "
                            f"JOIN pg_class c ON c.oid=a.attrelid "
                            f"JOIN pg_namespace n ON n.oid=c.relnamespace "
                            f"WHERE n.nspname=%s AND c.relname=%s AND a.attnum>0 AND NOT a.attisdropped "
                            f"AND format_type(a.atttypid,a.atttypmod) IN ('text','varchar','character varying') "
                            f"LIMIT 1", (schema, table))
                col_row = cur.fetchone()
                if not col_row:
                    results[cmd] = "–"
                    continue
                action = f"UPDATE {schema}.{table} SET {col_row[0]}={col_row[0]} RETURNING 1"
            else:  # DELETE
                action = f"DELETE FROM {schema}.{table} RETURNING 1"

            cur.execute("SAVEPOINT " + sp)
            cur.execute("SELECT set_config('request.jwt.claims', %s, true)", (claims,))
            cur.execute("SET LOCAL ROLE authenticated")
            try:
                cur.execute(action)
                if cmd == "SELECT":
                    n = (cur.fetchone() or [0])[0]
                    results[cmd] = f"✓ ({n} row{'s' if n != 1 else ''})"
                else:
                    rows_affected = cur.rowcount
                    results[cmd] = f"✓ ({rows_affected} row{'s' if rows_affected != 1 else ''})"
            except Exception as e:
                sqlstate = getattr(e, "sqlstate", None) or str(e)[:8]
                results[cmd] = f"✗ blocked ({sqlstate})"
            finally:
                cur.execute("ROLLBACK TO SAVEPOINT " + sp)
                cur.execute("RELEASE SAVEPOINT " + sp)
                cur.execute("RESET ROLE")
        except Exception:
            results[cmd] = "–"
    return results

