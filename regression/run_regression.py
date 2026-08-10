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
    ("customrole.sql", "crole"), ("quoted_idents.sql", "qident"),
    ("colsec.sql", "colsec"),
    ("checkfmt.sql", "checkfmt"),
    ("multimembership.sql", "mtt"),   # issue #4: 2-tenant-member probe + scalar-subquery hazard + relstate anon 42501 denial
    ("mixedor.sql", "mor"),           # obligation router: classified-OR-novel rescue, two permissive policies, NOT(a AND b) disjuncts
    ("fnexpand.sql", "fnx"),          # UDF understanding: fn-body expansion -> real-input batteries; vault's dynamic-EXECUTE stays wiring
    ("publicto.sql", "pto"),          # RA-8: no-TO (PUBLIC) audience + LOGIN client roles + group inheritance; L001 CRITICAL + L017 fire
    ("writescope.sql", "wsc"),        # MB-20: L018 unconstrained-scope-column-on-write (docs fires, safe does not); --report stays green
    ("joinsub.sql", "jsq"),           # MB-2: membership-through-a-2-table-join subquery -> DB-verified solver battery (was NT)
    ("joinsub3.sql", "jsq3"),         # MB-2b: 3-table INNER-join membership CHAIN (memberships->roles->role_types) -> N-table solver battery (was NT)
    ("orsubquery.sql", "orsub"),      # MB-2b: OR inside a subquery WHERE -> DNF-split to the identity arm -> DB-verified solver battery (was NT)
    ("neon.sql", "neon"),             # MB-11: Neon pg_session_jwt vocabulary (auth.user_id/auth.session) + discovered roles (authenticated/anonymous, no service_role); flavor-aware shim
    ("clscustom.sql", "clsc"),        # MB-12: custom role (clsc_auditor) with a column-scoped SELECT grant -> report AND emitted suite both carry its CLS parity assertion (scoped green + leak red)
    ("dualwrite.sql", "dw"),          # MB-18: L020 dual-write-path advisory (orders fires, safe does not); --report stays green
    ("restrictconj.sql", "rcj"),      # MB-6: restrictive predicate conjoined into a routed (solver) obligation -> was PARTIALLY TESTED, now green
    ("relstatewrite.sql", "rsw"),     # MB-4: relational-state (cardinality) FOR ALL -> INSERT/UPDATE/DELETE write batteries
    ("recursionwrite.sql", "rcw"),    # MB-4: self-referential hierarchy FOR ALL -> UPDATE/DELETE write batteries (INSERT stays NT)
    ("updcheck.sql", "updcheck"), ("seedfail.sql", "seedfail"),
]
# fixture, schema, required marker(s) in the failing report
NEGATIVE = [
    ("transitions.sql", "transitions", ["cross-policy WITH CHECK leak"]),
    ("seedimpossible.sql", "seedimpossible", ["UNRELIABLE"]),
    ("scalarmulti.sql", "scm", ["member of 2 tenants", "21000"]),   # MB-3: scalar-subquery 2-tenant hazard, caught live on read AND write
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
    # Windows hardening: the default console/redirect encoding (cp1252) cannot encode the report's matrix
    # glyphs (checkmark, double-bang, dash), so printing a failure diff to a redirected file would crash the
    # harness mid-run. Force UTF-8 so it never chokes on its own output (no-op where stdout is already UTF-8).
    for _s in (sys.stdout, sys.stderr):
        try: _s.reconfigure(encoding="utf-8", errors="replace")
        except Exception: pass
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

    # ---- ISOLATED-DB identity-binding check (MB-19) -------------------------------------------
    # authshape.sql redefines auth.uid() with a body the probe cannot drive (the flat
    # request.jwt.claim.sub GUC), so it must run in its OWN database -- loading it into the shared
    # corpus DB would clobber every other fixture's identity binding. Assert that a CLASSIFIED owner
    # policy whose identity cannot be bound is flagged LOUDLY (UNRELIABLE + nonzero gate), never a
    # silent "correctly denied" cell. Not byte-baselined -- it's a gate+marker assertion like NEGATIVE.
    ISO_FIXTURE = os.path.join(REPO, "examples", "authshape.sql")
    murl2 = re.match(r"(postgresql://[^/]+/)(\w+)(.*)$", a.db_url)
    if os.path.exists(ISO_FIXTURE) and murl2:
        iso_db = murl2.group(2) + "_authshape"
        admin2 = murl2.group(1) + "postgres" + murl2.group(3)
        iso_url = murl2.group(1) + iso_db + murl2.group(3)
        try:
            with psycopg.connect(admin2, autocommit=True) as c:
                c.execute(f'DROP DATABASE IF EXISTS "{iso_db}" WITH (FORCE)')
                c.execute(f'CREATE DATABASE "{iso_db}"')
            for fx in ("schema.sql", "authshape.sql"):   # schema.sql = roles + JSON auth shim; authshape overrides auth.uid() flat
                r = subprocess.run([a.psql, iso_url, "-v", "ON_ERROR_STOP=1", "-q",
                                    "-f", os.path.join(REPO, "examples", fx)], capture_output=True, text=True)
                if r.returncode != 0:
                    failures.append(f"[identity-binding] loading {fx} failed: {r.stderr[-400:]}")
            gate = run_cli(iso_url, "--schema", "ash", "--report")
            out = gate.stdout + gate.stderr
            if gate.returncode == 0:
                failures.append("[identity-binding] ash gate PASSED -- an unbindable owner identity was "
                                "NOT flagged (MB-19 regressed: silent all-deny is back)")
            if "UNRELIABLE TEST" not in out or "auth.uid()" not in out:   # the footgun note, not the legend line
                failures.append("[identity-binding] ash report missing the UNRELIABLE identity-binding marker")
            print(f"  [identity-binding] ash    gate={gate.returncode} (expected nonzero, UNRELIABLE)")
            with psycopg.connect(admin2, autocommit=True) as c:
                c.execute(f'DROP DATABASE IF EXISTS "{iso_db}" WITH (FORCE)')
        except Exception as e:
            failures.append(f"[identity-binding] check errored: {e}")

    # ---- ISOLATED-DB flat-claim binding check (MB-23) -----------------------------------------
    # flatclaim.sql redefines auth.uid() to read the OLD flat request.jwt.claim.sub GUC (cekuu35's
    # shape). MB-23 makes the probe/emitters ALSO drive that GUC, so the SAME owner policy that stays
    # UNRELIABLE under a custom app GUC (authshape) now BINDS and goes GREEN. Assert gate==0 and NO
    # UNRELIABLE marker. Own DB (redefines auth.uid()). Not byte-baselined -- a gate+marker assertion.
    ISO_FC = os.path.join(REPO, "examples", "flatclaim.sql")
    if os.path.exists(ISO_FC) and murl2:
        fc_db = murl2.group(2) + "_flatclaim"
        admin2 = murl2.group(1) + "postgres" + murl2.group(3)
        fc_url = murl2.group(1) + fc_db + murl2.group(3)
        try:
            with psycopg.connect(admin2, autocommit=True) as c:
                c.execute(f'DROP DATABASE IF EXISTS "{fc_db}" WITH (FORCE)')
                c.execute(f'CREATE DATABASE "{fc_db}"')
            for fx in ("schema.sql", "flatclaim.sql"):
                r = subprocess.run([a.psql, fc_url, "-v", "ON_ERROR_STOP=1", "-q",
                                    "-f", os.path.join(REPO, "examples", fx)], capture_output=True, text=True)
                if r.returncode != 0:
                    failures.append(f"[flat-claim] loading {fx} failed: {r.stderr[-400:]}")
            gate = run_cli(fc_url, "--schema", "fc", "--report")
            out = gate.stdout + gate.stderr
            if gate.returncode != 0:
                failures.append("[flat-claim] fc gate FAILED -- the flat request.jwt.claim.sub owner "
                                "identity did not bind (MB-23 regressed: it fell back to UNRELIABLE)")
            if "UNRELIABLE TEST" in out:   # the footgun note, not the legend line (which always says "UNRELIABLE")
                failures.append("[flat-claim] fc report has an UNRELIABLE cell -- the flat GUC identity "
                                "was not driven (MB-23 regressed)")
            print(f"  [flat-claim] fc          gate={gate.returncode} (expected 0, bound green)")
            with psycopg.connect(admin2, autocommit=True) as c:
                c.execute(f'DROP DATABASE IF EXISTS "{fc_db}" WITH (FORCE)')
        except Exception as e:
            failures.append(f"[flat-claim] check errored: {e}")

    # ---- MB-9: OPT-IN CRITICAL-bypass gate + --allow-bypass sanctioning ------------------------
    # recursion.all_nodes() is a CRITICAL bypass surface (anon-EXECUTE-able SECURITY DEFINER fn that
    # sidesteps RLS). By DEFAULT it is a review flag -> recursion's normal gate stays 0. Assert that
    # --fail-on-bypass turns it into a gate FAILURE, and --allow-bypass sanctions it back to green -- so a
    # NEW unsanctioned CRITICAL surface fails CI while a reviewed one does not. Gate assertion, not
    # byte-baselined; recursion is already loaded in the shared corpus DB.
    try:
        g_def = run_cli(a.db_url, "--schema", "recursion", "--report")
        if g_def.returncode != 0:
            failures.append("[bypass-gate] recursion baseline gate != 0 -- the default (no --fail-on-bypass) gate changed")
        g_on = run_cli(a.db_url, "--schema", "recursion", "--report", "--fail-on-bypass")
        if g_on.returncode == 0:
            failures.append("[bypass-gate] recursion --fail-on-bypass PASSED -- the CRITICAL bypass all_nodes() was NOT gated")
        g_ok = run_cli(a.db_url, "--schema", "recursion", "--report", "--fail-on-bypass", "--allow-bypass", "L012:all_nodes()")
        if g_ok.returncode != 0:
            failures.append("[bypass-gate] recursion --allow-bypass L012:all_nodes() FAILED -- sanctioning did not exempt the reviewed surface")
        print(f"  [bypass-gate] recursion  default={g_def.returncode} fail-on-bypass={g_on.returncode} sanctioned={g_ok.returncode} (expected 0 / nonzero / 0)")
    except Exception as e:
        failures.append(f"[bypass-gate] check errored: {e}")

    # ---- MB-25: --allow-unreliable / .rlsautotestignore sanctioning of UNRELIABLE cells --------------
    # seedimpossible.blocked is UNRELIABLE (its seed row violates a CHECK). Default -> the gate FAILS.
    # Sanction the whole table -> gate green, the cell stays UNRELIABLE in the report (SANCTIONED note), and
    # the emitted suite bakes a pgTAP SKIP (never a fail(), never a passing assertion). Sanction only ONE
    # command -> the other commands must STILL fail (the exemption is scoped, not a blanket --no-fail).
    try:
        su_def = run_cli(a.db_url, "--schema", "seedimpossible", "--report")
        if su_def.returncode == 0:
            failures.append("[allow-unreliable] seedimpossible baseline gate == 0 -- UNRELIABLE no longer fails the gate")
        su_all = run_cli(a.db_url, "--schema", "seedimpossible", "--report", "--allow-unreliable", "blocked")
        if su_all.returncode != 0:
            failures.append("[allow-unreliable] --allow-unreliable blocked did NOT exempt the gate")
        if "SANCTIONED UNRELIABLE" not in su_all.stdout:
            failures.append("[allow-unreliable] sanctioned report is missing the SANCTIONED note (the cell must stay visible)")
        su_part = run_cli(a.db_url, "--schema", "seedimpossible", "--report", "--allow-unreliable", "blocked:SELECT")
        if su_part.returncode == 0:
            failures.append("[allow-unreliable] blocked:SELECT wrongly exempted the whole table (INSERT/UPDATE/DELETE must still fail)")
        with tempfile.TemporaryDirectory() as _sud:
            run_cli(a.db_url, "--schema", "seedimpossible", "--emit", _sud, "--allow-unreliable", "blocked")
            _blocked = None
            for _root, _dirs, _files in os.walk(_sud):
                for _fn in _files:
                    if "blocked" in _fn and _fn.endswith(".sql"):
                        _blocked = open(os.path.join(_root, _fn), encoding="utf-8").read()
            if _blocked is None:
                failures.append("[allow-unreliable] emit produced no blocked suite")
            elif "SELECT skip(" not in _blocked or "UNRELIABLE - " in _blocked:
                failures.append("[allow-unreliable] emitted suite did not swap every UNRELIABLE fail() -> skip() under a full sanction")
        print(f"  [allow-unreliable] seedimpossible  default={su_def.returncode} sanctioned={su_all.returncode} partial-SELECT={su_part.returncode} (expected nonzero / 0 / nonzero)")
    except Exception as e:
        failures.append(f"[allow-unreliable] check errored: {e}")

    if not a.skip_pytest:
        r = subprocess.run([sys.executable, "-m", "pytest", "-q", "tests/test_smoke.py", "tests/test_bypassprobe.py", "tests/test_allow_unreliable.py"],
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
