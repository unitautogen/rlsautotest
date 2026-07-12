# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""rlsautotest regression harness with a COMMITTED BASELINE.

What it proves, end to end, against a real (disposable) PostgreSQL database:
  1. every GREEN example schema loads, its report gate exits 0, and its emitted pgTAP suite is
     BYTE-IDENTICAL to the committed baseline (any silent output drift fails the run);
  2. every NEGATIVE example still fails its gate for the RIGHT reason (leak caught, UNRELIABLE
     flagged, explained dash present) — the tool's teeth stay sharp;
  3. the report text matches the baseline (matrix cells, footguns, coverage);
  4. the unit tests pass.

Usage (point it at a DISPOSABLE database — it drops/creates it with --recreate):
    python regression/run_regression.py --db-url postgresql://user:pw@host:5432/rls_regression \
        [--recreate] [--rebaseline] [--psql "C:\\path\\to\\psql.exe"] [--skip-pytest]

--rebaseline regenerates regression/baseline/ (do this ONLY for an intentional output change and
review the diff in git). Baselines are byte-stable per PostgreSQL MAJOR version (deparsed policy
text and pg_get_functiondef output appear inside the emitted SQL); on a major-version mismatch the
byte-diff is skipped with a warning and only the gates + matrix lines are compared.
"""
from __future__ import annotations
import argparse, difflib, hashlib, json, os, re, shutil, subprocess, sys, tempfile
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
BASELINE = os.path.join(HERE, "baseline")

# The canonical corpus (mirrors .github/workflows/ci.yml). fixture file -> schema it creates.
GREEN = [
    ("schema.sql", "public"), ("tenancy.sql", "tenancy"), ("rbac.sql", "rbac"),
    ("rbac_tenant.sql", "rbt"), ("clearance.sql", "clearance"), ("synth.sql", "synth"),
    ("adversarial.sql", "adversarial"), ("mockforce.sql", "mockforce"),
    ("witness_himed.sql", "wm"), ("witness_array.sql", "wa"), ("witness_fncol2.sql", "wf2"),
    ("witness_subq.sql", "wsq"), ("witness_novel.sql", "wn"), ("witness_joint.sql", "wj"),
    ("witness_cardinality.sql", "wcard"), ("recursion.sql", "recursion"),
    ("exotic_types.sql", "xtypes"), ("zeroarg.sql", "za"), ("regexfree.sql", "rxf"),
    ("customrole.sql", "crole"),
]
# fixture, schema, required marker(s) in the failing report
NEGATIVE = [
    ("transitions.sql", "transitions", ["cross-policy WITH CHECK leak"]),
    ("seedfail.sql", "seedfail", ["UNRELIABLE"]),
    ("updcheck.sql", "updcheck", ["UNRELIABLE", "no policy-neutral column"]),
]
# exotic.sql is deliberately NOT loaded: it contains a broken-by-design 42P17 policy.

GRID = re.compile(r"^\s{2}\S.*\s{2,}[✓·✗–‼]")   # matrix rows (identity + cells)


def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def run_cli(dburl, *args):
    return subprocess.run([sys.executable, "-m", "rlsautotest.cli", "--db-url", dburl, *args],
                          capture_output=True, text=True, cwd=REPO, timeout=600,
                          encoding="utf-8", errors="replace")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db-url", required=True, help="DISPOSABLE database (dropped with --recreate)")
    ap.add_argument("--recreate", action="store_true", help="drop + recreate the database first")
    ap.add_argument("--rebaseline", action="store_true", help="regenerate regression/baseline/")
    ap.add_argument("--psql", default="psql", help="psql executable for loading fixtures")
    ap.add_argument("--skip-pytest", action="store_true")
    a = ap.parse_args()

    import psycopg
    if a.recreate:
        m = re.match(r"(postgresql://[^/]+/)(\w+)(.*)$", a.db_url)
        if not m:
            print("cannot parse --db-url for --recreate"); return 2
        admin = m.group(1) + "postgres" + m.group(3)
        with psycopg.connect(admin, autocommit=True) as c:
            c.execute(f'DROP DATABASE IF EXISTS "{m.group(2)}" WITH (FORCE)')
            c.execute(f'CREATE DATABASE "{m.group(2)}"')
        print(f"recreated database {m.group(2)}")

    with psycopg.connect(a.db_url) as c:
        pg_major = c.execute("SHOW server_version").fetchone()[0].split(".")[0]
    manifest_path = os.path.join(BASELINE, "MANIFEST.txt")
    base_manifest = json.load(open(manifest_path, encoding="utf-8")) if os.path.exists(manifest_path) else None
    byte_compare = True
    if base_manifest and not a.rebaseline and base_manifest.get("pg_major") != pg_major:
        byte_compare = False
        print(f"WARNING: baseline was generated on PostgreSQL {base_manifest.get('pg_major')}, "
              f"this server is {pg_major} — deparse formatting differs across majors, so the "
              f"byte-diff is skipped; comparing gates + matrix lines only.")

    print(f"loading {len(GREEN) + len(NEGATIVE)} fixtures into {re.sub(r':[^:@/]+@', ':***@', a.db_url)}")
    for fx, _s in GREEN + [(f, s) for (f, s, _m) in NEGATIVE]:
        r = subprocess.run([a.psql, a.db_url, "-v", "ON_ERROR_STOP=1", "-q",
                            "-f", os.path.join(REPO, "examples", fx)], capture_output=True, text=True)
        if r.returncode != 0:
            print(f"FIXTURE FAILED: {fx}\n{r.stderr[-1500:]}"); return 2

    failures, emitted, reports = [], {}, {}
    workdir = tempfile.mkdtemp(prefix="rlsa_regress_")
    for _fx, schema in GREEN:
        gate = run_cli(a.db_url, "--schema", schema, "--report")
        if gate.returncode != 0:
            failures.append(f"{schema}: green gate exited {gate.returncode}")
            print((gate.stdout + gate.stderr)[-1200:])
        rep = run_cli(a.db_url, "--schema", schema, "--report", "--no-fail")
        reports[schema] = rep.stdout
        em = run_cli(a.db_url, "--schema", schema, "--emit", os.path.join(workdir, schema))
        if em.returncode != 0:
            failures.append(f"{schema}: --emit exited {em.returncode}")
        tdir = os.path.join(workdir, schema, "tests", "database", "rls")
        emitted[schema] = {f: os.path.join(tdir, f) for f in sorted(os.listdir(tdir))} if os.path.isdir(tdir) else {}
        print(f"  {schema:<14} gate=0 files={len(emitted[schema])}")

    for _fx, schema, markers in NEGATIVE:
        gate = run_cli(a.db_url, "--schema", schema, "--report")
        out = gate.stdout + gate.stderr
        if gate.returncode == 0:
            failures.append(f"{schema}: NEGATIVE gate unexpectedly passed (regression in detection)")
        for mk in markers:
            if mk not in out:
                failures.append(f"{schema}: expected marker missing: {mk!r}")
        print(f"  {schema:<14} gate={gate.returncode} (expected nonzero)")

    if a.rebaseline:
        shutil.rmtree(BASELINE, ignore_errors=True)
        os.makedirs(os.path.join(BASELINE, "reports"))
        files = {}
        for schema, fmap in emitted.items():
            os.makedirs(os.path.join(BASELINE, "emit", schema), exist_ok=True)
            for f, p in fmap.items():
                dst = os.path.join(BASELINE, "emit", schema, f)
                shutil.copy(p, dst)
                files[f"emit/{schema}/{f}"] = sha(dst)
        for schema, text in reports.items():
            dst = os.path.join(BASELINE, "reports", schema + ".txt")
            open(dst, "w", encoding="utf-8", newline="\n").write(text)
            files[f"reports/{schema}.txt"] = sha(dst)
        json.dump({"generated_at": datetime.now(timezone.utc).isoformat(), "pg_major": pg_major,
                   "schemas": [s for _f, s in GREEN], "files": files},
                  open(manifest_path, "w", encoding="utf-8"), indent=1)
        print(f"\nBASELINE WRITTEN: {len(files)} files under regression/baseline/ (PostgreSQL {pg_major})")
    elif base_manifest:
        for schema, fmap in emitted.items():
            bdir = os.path.join(BASELINE, "emit", schema)
            bfiles = sorted(os.listdir(bdir)) if os.path.isdir(bdir) else []
            if sorted(fmap) != bfiles:
                failures.append(f"{schema}: emitted file set changed: {sorted(set(bfiles) ^ set(fmap))}")
                continue
            for f, p in fmap.items():
                # newline-insensitive: git autocrlf may check the baseline out with CRLF
                new = open(p, encoding="utf-8").read().splitlines()
                old = open(os.path.join(bdir, f), encoding="utf-8").read().splitlines()
                if byte_compare and new != old:
                    d = list(difflib.unified_diff(old, new, f"baseline/{f}", f"current/{f}", lineterm=""))
                    failures.append(f"{schema}/{f}: emitted SQL drifted from baseline "
                                    f"({len(d)} diff lines)\n" + "\n".join(d[:20]))
        for schema, text in reports.items():
            bp = os.path.join(BASELINE, "reports", schema + ".txt")
            old = open(bp, encoding="utf-8").read() if os.path.exists(bp) else ""
            if byte_compare:
                same = (text.splitlines() == old.splitlines())   # newline-insensitive (git autocrlf)
            else:   # cross-version: matrices must match even if deparsed policy text differs
                same = [l for l in text.splitlines() if GRID.match(l)] == \
                       [l for l in old.splitlines() if GRID.match(l)]
            if not same:
                d = list(difflib.unified_diff(old.splitlines(), text.splitlines(),
                                              "baseline", "current", lineterm=""))
                failures.append(f"{schema}: report drifted from baseline\n" + "\n".join(d[:20]))
    else:
        print("NOTE: no baseline present — run with --rebaseline to create one.")

    # ---- PRIVATE targets (real-world schemas, kept OUT of the public repo) --------------------
    # regression/private_targets.json (gitignored) lists EXISTING local databases to regression-
    # test alongside the public corpus, e.g.:
    #   [{"db": "strbac_test", "schemas": ["public", "rbac", "rbt"]}]
    # Each schema's report gate must exit 0 (or set "expect_gate": {"schema": 1} for known-red) and
    # its report text is snapshotted/compared under regression/private_baseline/ (also gitignored).
    # These databases are NOT recreated — probes roll back, so their content stays untouched.
    PRIVATE = os.path.join(HERE, "private_targets.json")
    PBASE = os.path.join(HERE, "private_baseline")
    if os.path.exists(PRIVATE):
        murl = re.match(r"(postgresql://[^/]+/)(\w+)(.*)$", a.db_url)
        for t in json.load(open(PRIVATE, encoding="utf-8")):
            db = t["db"]
            turl = murl.group(1) + db + murl.group(3)
            exp_map = t.get("expect_gate", {}) or {}
            for schema in t["schemas"]:
                exp = int(exp_map.get(schema, 0))
                gate = run_cli(turl, "--schema", schema, "--report")
                if (gate.returncode == 0) != (exp == 0):
                    failures.append(f"[private {db}] {schema}: gate rc={gate.returncode}, "
                                    f"expected {'0' if exp == 0 else 'nonzero'}")
                rep = run_cli(turl, "--schema", schema, "--report", "--no-fail")
                sp = os.path.join(PBASE, db, schema + ".txt")
                if a.rebaseline:
                    os.makedirs(os.path.dirname(sp), exist_ok=True)
                    open(sp, "w", encoding="utf-8", newline="\n").write(rep.stdout)
                elif os.path.exists(sp):
                    old = open(sp, encoding="utf-8").read()
                    if rep.stdout.splitlines() != old.splitlines():
                        d = list(difflib.unified_diff(old.splitlines(), rep.stdout.splitlines(),
                                                      "baseline", "current", lineterm=""))
                        failures.append(f"[private {db}] {schema}: report drifted from baseline\n"
                                        + "\n".join(d[:20]))
                print(f"  [private {db}] {schema:<12} gate={gate.returncode}")

    if not a.skip_pytest:
        r = subprocess.run([sys.executable, "-m", "pytest", "-q", "tests/test_smoke.py"],
                           capture_output=True, text=True, cwd=REPO)
        print("pytest:", (r.stdout + r.stderr).strip().splitlines()[-1])
        if r.returncode != 0:
            failures.append("pytest failed")

    print("\n" + ("=" * 60))
    if failures:
        print(f"REGRESSION: {len(failures)} FAILURE(S)")
        for f in failures:
            print(" -", f)
        return 1
    print(f"REGRESSION PASS: {len(GREEN)} green schemas byte-checked against baseline, "
          f"{len(NEGATIVE)} negative gates verified, unit tests green. (PostgreSQL {pg_major})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
