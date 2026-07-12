# Regression testing (committed baseline)

The regression harness proves, against a real disposable PostgreSQL database, that the engine
still does exactly what it did at the last blessed state — and that its failure detection still
has teeth.

## What a run checks

1. **Green corpus.** Every example schema loads, its `--report` CI gate exits 0, and the emitted
   pgTAP suite for every table is **byte-identical** to `regression/baseline/emit/`. Any silent
   drift in generated SQL fails the run with a unified diff.
2. **Report stability.** The `--report --no-fail` text for every schema matches
   `regression/baseline/reports/` (matrix cells, footguns, coverage).
3. **Negative gates.** The deliberately-broken examples must still FAIL for the right reason:
   `transitions` (cross-policy WITH CHECK leak caught), `seedfail` (UNRELIABLE flagged),
   `updcheck` (UNRELIABLE + the explained no-neutral-column dash). A negative gate passing is a
   regression in detection.
4. **Unit tests** (`tests/test_smoke.py`).

`examples/exotic.sql` is deliberately excluded: it contains a broken-by-design self-referential
policy (42P17) used for detection demos.

## Running it

Point it at a database you can destroy (never a real one — probes execute real statements,
rolled back, and `--recreate` drops the whole DB):

```
python regression/run_regression.py --db-url postgresql://postgres:PW@127.0.0.1:5432/rls_regression \
    --recreate --psql "D:\Program Files\PostgreSQL\18\bin\psql.exe"
```

Exit 0 = pass. Exit 1 prints every failure with a diff head.

## Updating the baseline

When an output change is INTENTIONAL (new strategy, wording change, new fixture):

```
python regression/run_regression.py --db-url ... --recreate --rebaseline
```

then **review `git diff regression/baseline/` like source code** — that diff is the exact,
reviewable statement of what the engine's output changed. Commit it together with the change
that caused it.

## Version note

Baselines are byte-stable per PostgreSQL **major** version (deparsed policy text and
`pg_get_functiondef` output appear inside emitted SQL). The manifest records the major it was
generated on; on a mismatch the harness skips the byte-diff with a warning and compares gate
exit codes + matrix lines only. Current baseline: see `regression/baseline/MANIFEST.txt`.

## Private targets (real-world schemas)

`regression/private_targets.json` (gitignored, like everything real-world here) can list EXISTING
local databases to regression-test alongside the public corpus:

```json
[{"db": "strbac_test", "schemas": ["public", "rbac", "rbt"]}]
```

Each schema's report gate must exit 0 (use `"expect_gate": {"schema": 1}` for a known-red one) and
its report text is snapshotted/compared under `regression/private_baseline/` (also gitignored).
These databases are NOT recreated; probes roll back, so their content stays untouched. This is how
the real supabase-tenant-rbac v5.2.1 install — the schema that drove the 0.1.7 engine fixes — stays
under regression without its third-party SQL ever entering the public repo.

## Semantic audit (is the matrix RIGHT, not just stable?)

The baseline proves output stability; `regression/semantic_audit.py` hunts for cells that may
point the wrong way. It cross-checks every table's report against the catalog and flags:
`A?` authorized deny/untested where a client policy AND grant exist (the signature of the
`profiles` wrong-direction bug — review each; a principled NOT_TESTABLE with its footgun is
fine), and `B?` authorized CAN where no client policy exists (a hard contradiction, exit 1).

```
python regression/semantic_audit.py --db-url postgresql://...   [--schemas a,b,c]
```

Run it after any emitter/identity change and against real databases occasionally. Current
status across the full corpus + the private targets: zero B?, one known A?
(`wcard.events UPDATE` — the relational-state floor witnesses SELECT only, documented NT).

## Relationship to CI

`.github/workflows/ci.yml` runs the same corpus end-to-end (emit + execute + gate) on every
push, but without the byte-diff. The baseline harness is the stronger local pre-release check:
run it before publishing and whenever touching the emitters, seeding, or the report.
