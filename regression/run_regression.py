#!/usr/bin/env python3
"""rlsautotest regression harness.

Builds (or refreshes) ONE dedicated regression database that holds every example schema we test
against, generates the RLS suite for each schema, runs it, and records per-file pass/fail results
in two places:

  1. a results table inside the regression DB  ->  regression.results
  2. committed artifacts in the repo root       ->  REGRESSION.md  +  regression_results.json

Run:
  python regression/run_regression.py

Environment:
  REGRESSION_DB_URL  full libpq URL of the regression DB
                     (default postgresql://postgres@127.0.0.1:5432/rls_regression)
  ADMIN_DB_URL       a DB to connect to so the regression DB can be CREATEd if missing
                     (default: the REGRESSION_DB_URL with the database swapped to 'postgres')
  PSQL               path to the psql binary (default 'psql')

The DB password must be supplied via the URL or the standard PGPASSWORD env var — it is never
written to disk by this script.
"""
import os, re, sys, json, subprocess, datetime, pathlib, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"

# (fixture file, schema it defines). schema.sql MUST load first: it creates the auth shim
# (auth.jwt/uid/role + auth.users) and the anon/authenticated/service_role roles the others need.
FIXTURES = [("schema.sql", "public"), ("tenancy.sql", "tenancy"),
            ("exotic.sql", "exotic"), ("rbac.sql", "rbac")]
SCHEMAS = [s for _, s in FIXTURES]

PSQL = os.environ.get("PSQL", "psql")
PY = sys.executable
REG = os.environ.get("REGRESSION_DB_URL", "postgresql://postgres@127.0.0.1:5432/rls_regression")
DBNAME = REG.rsplit("/", 1)[1].split("?")[0]
ADMIN = os.environ.get("ADMIN_DB_URL", REG.rsplit("/", 1)[0] + "/postgres")


def _psql(url, sql=None, file=None):
    cmd = [PSQL, url, "-X", "-q", "-v", "ON_ERROR_STOP=0"]
    if sql:
        cmd += ["-c", sql]
    if file:
        cmd += ["-f", str(file)]
    return subprocess.run(cmd, capture_output=True, text=True)


def main():
    env = dict(os.environ)
    env.setdefault("PGOPTIONS", "-c client_min_messages=warning")

    # 1) create the regression DB if it doesn't exist
    chk = _psql(ADMIN, sql=f"SELECT 1 FROM pg_database WHERE datname='{DBNAME}'")
    if "1" not in (chk.stdout or ""):
        _psql(ADMIN, sql=f'CREATE DATABASE "{DBNAME}"')
        print(f"created database {DBNAME}")

    # 2) clean rebuild of the fixtures (drop our schemas, reload from examples/)
    _psql(REG, sql="CREATE EXTENSION IF NOT EXISTS pgtap")
    for s in ("rbac", "exotic", "tenancy"):
        _psql(REG, sql=f"DROP SCHEMA IF EXISTS {s} CASCADE")
    _psql(REG, sql="DROP TABLE IF EXISTS public.profiles, public.notes CASCADE")
    for f, _ in FIXTURES:
        r = _psql(REG, file=EXAMPLES / f)
        if "ERROR" in (r.stderr or ""):
            print(f"!! loading {f}:\n{r.stderr}")

    # 3) results table
    _psql(REG, sql="CREATE SCHEMA IF NOT EXISTS regression")
    _psql(REG, sql=("CREATE TABLE IF NOT EXISTS regression.results ("
                    "run_at timestamptz, schema_name text, test_file text, "
                    "tests int, ok_count int, not_ok_count int, status text)"))
    _psql(REG, sql="TRUNCATE regression.results")

    run_at = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="rlsa_reg_"))
    results, totals = [], {"files": 0, "tests": 0, "not_ok": 0}

    # 4) generate + run each schema's suite, parse the TAP, record per file
    for s in SCHEMAS:
        out = tmp / s
        gen = subprocess.run([PY, "-m", "rlsautotest", "--schema", s, "--no-helpers",
                              "--emit", str(out), "--db-url", REG],
                             cwd=str(ROOT), capture_output=True, text=True, env=env)
        d = out / "tests" / "database" / "rls"
        if not d.exists():
            print(f"!! no suite emitted for schema {s}\n{gen.stderr}")
            continue
        for fp in sorted(d.glob("*.sql")):
            tap = _psql(REG, file=fp).stdout or ""
            m = re.search(r"1\.\.(\d+)", tap)
            tests = int(m.group(1)) if m else 0
            not_ok = len(re.findall(r"not ok", tap))
            ok = tests - not_ok
            status = "PASS" if not_ok == 0 else "FAIL"
            results.append({"schema": s, "file": fp.name, "tests": tests,
                            "ok": ok, "not_ok": not_ok, "status": status})
            totals["files"] += 1; totals["tests"] += tests; totals["not_ok"] += not_ok
            esc = fp.name.replace("'", "''")
            _psql(REG, sql=("INSERT INTO regression.results VALUES "
                            f"('{run_at}','{s}','{esc}',{tests},{ok},{not_ok},'{status}')"))

    # 5) committed artifacts: JSON + Markdown
    payload = {"run_at": run_at, "database": DBNAME, "totals": totals, "results": results}
    (ROOT / "regression_results.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    lines = [f"# Regression results", "",
             f"- Run (UTC): `{run_at}`",
             f"- Database: `{DBNAME}` (rebuilt from `examples/` by `regression/run_regression.py`)",
             f"- Schemas: {', '.join(SCHEMAS)}",
             f"- Totals: **{totals['files']} files, {totals['tests']} tests, "
             f"{totals['not_ok']} failed**", "",
             "| schema | test file | tests | ok | not ok | status |",
             "|---|---|--:|--:|--:|---|"]
    for r in results:
        lines.append(f"| {r['schema']} | {r['file']} | {r['tests']} | {r['ok']} | "
                     f"{r['not_ok']} | {'✅' if r['status']=='PASS' else '❌'} {r['status']} |")
    lines += ["", "Results are also stored in the regression DB: `SELECT * FROM regression.results;`."]
    (ROOT / "REGRESSION.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    (ROOT / "regression_report.html").write_text(_html(run_at, DBNAME, SCHEMAS, totals, results), encoding="utf-8")

    print(f"{totals['files']} files, {totals['tests']} tests, {totals['not_ok']} failed "
          f"-> REGRESSION.md + regression_report.html + regression_results.json + regression.results")
    return 1 if totals["not_ok"] else 0


def _html(run_at, dbname, schemas, totals, results):
    import html
    ok_overall = totals["not_ok"] == 0
    pill_bg, pill_tx = ("#dcfce7", "#166534") if ok_overall else ("#fee2e2", "#991b1b")
    pill = "ALL GREEN" if ok_overall else f"{totals['not_ok']} FAILED"
    rows = []
    for r in results:
        passed = r["status"] == "PASS"
        bg, tx = ("#dcfce7", "#166534") if passed else ("#fee2e2", "#991b1b")
        badge = ("&#10003; PASS" if passed else "&#10007; FAIL")
        rows.append(
            f"<tr><td class='sch'>{html.escape(r['schema'])}</td>"
            f"<td class='mono'>{html.escape(r['file'])}</td>"
            f"<td class='num'>{r['tests']}</td><td class='num'>{r['ok']}</td>"
            f"<td class='num'>{r['not_ok']}</td>"
            f"<td><span class='badge' style='background:{bg};color:{tx}'>{badge}</span></td></tr>")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>rlsautotest — regression results</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font: 15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
         margin: 0; padding: 2rem; background:#f8fafc; color:#0f172a; }}
  .wrap {{ max-width: 920px; margin: 0 auto; }}
  h1 {{ font-size: 1.5rem; margin: 0 0 .25rem; }}
  .meta {{ color:#64748b; font-size:.9rem; margin-bottom:1rem; }}
  .meta code {{ background:#e2e8f0; padding:.05rem .35rem; border-radius:4px; }}
  .pill {{ display:inline-block; font-weight:700; padding:.3rem .8rem; border-radius:999px;
          background:{pill_bg}; color:{pill_tx}; margin-bottom:1.25rem; }}
  table {{ width:100%; border-collapse:collapse; background:#fff; border:1px solid #e2e8f0;
          border-radius:10px; overflow:hidden; box-shadow:0 1px 2px rgba(0,0,0,.04); }}
  th,td {{ text-align:left; padding:.55rem .8rem; border-bottom:1px solid #f1f5f9; }}
  th {{ background:#f1f5f9; font-size:.78rem; letter-spacing:.04em; text-transform:uppercase; color:#475569; }}
  td.num {{ text-align:right; font-variant-numeric:tabular-nums; }}
  td.sch {{ font-weight:600; }}
  .mono {{ font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:.85rem; color:#334155; }}
  .badge {{ font-size:.78rem; font-weight:700; padding:.12rem .5rem; border-radius:6px; }}
  tr:last-child td {{ border-bottom:none; }}
  .foot {{ color:#94a3b8; font-size:.8rem; margin-top:1rem; }}
</style></head><body><div class="wrap">
  <h1>rlsautotest — regression results</h1>
  <div class="meta">Run (UTC) <code>{html.escape(run_at)}</code> &middot; database <code>{html.escape(dbname)}</code>
    &middot; schemas {html.escape(', '.join(schemas))}</div>
  <div class="pill">{pill} &middot; {totals['files']} files &middot; {totals['tests']} tests</div>
  <table><thead><tr><th>schema</th><th>test file</th><th>tests</th><th>ok</th><th>not ok</th><th>status</th></tr></thead>
  <tbody>{''.join(rows)}</tbody></table>
  <p class="foot">Generated by <span class="mono">regression/run_regression.py</span> from the
  <span class="mono">examples/</span> fixtures. Results also stored in the regression DB
  (<span class="mono">regression.results</span>).</p>
</div></body></html>"""


if __name__ == "__main__":
    sys.exit(main())
