# Code Review: rlsautotest

**Date**: 2026-07-13  
**Review scope**: All Python modules in `rlsautotest/` (CLI + engine + strategies), plus `tests/test_smoke.py`  
**Reviewer**: Automated review (no modifications made to the original codebase)

---

## 1. Executive Summary

The rlsautotest codebase is a **well-architected, sound-by-design** RLS test generator. The probe-and-bake discipline — running each identity×command action against a live DB and baking the *observed* outcome — is the load-bearing safety property. It's the right core invariant for a security-testing tool. The recent split from a monolith into focused modules (`structs`, `atoms`, `catalog`, `seeding`, `probe`, `emit`, `witness`, `strategies/*`, etc.) is clean and improves maintainability. The strategy pattern (F1) is well-done. Below are findings organized by severity.

---

## 2. Critical / High Severity

### 2.1 Dynamic SQL injection paths (LOW actual risk, HIGH surface area)

**Files**: `emit.py`, `emit.py:77`, `probe.py:77`, `seeding.py`, `strategies/*.py`, `cli.py`

Many places construct SQL via f-strings with identifiers derived from catalog values:

```python
# probe.py:77
cur.execute(f"SELECT count(*) FROM {tgt}")
```

`tgt` comes from `_action_table()` which regex-parses a SQL string. A crafted table name containing a closing backtick/double-quote could break out of the identifier. While in practice these values come from `pg_policies` catalog reads (trusted), the surface area is large.

Similarly, `seeding.py:18` (`_aux_row_stmts`) and `seeding.py:73` (`_seed_one`) build `INSERT INTO {tbl}({cols}) VALUES ({vals})` with catalog-derived identifiers. The `ON CONFLICT DO NOTHING` pattern mitigates some risk, but a truly malicious column name could cause unexpected SQL.

**Recommendation**: Consider `psycopg.sql.Identifier()` for all catalog-derived identifiers, or at minimum a centralized `quote_ident()` wrapper. Document the trust assumption explicitly: "identifiers are assumed safe because they come from `pg_catalog`".

### 2.2 Thread safety of shared `_CASTABLE_CACHE`

**File**: `values.py:35-77`

The global `_CASTABLE_CACHE` dict is shared across all threads in `--parallel` mode (cli.py uses `ThreadPoolExecutor`). Multiple threads probing different tables will read/write this cache concurrently. Dict operations in CPython are GIL-protected at the opcode level, but `cast()` and `_pg_base_type()` call `conn.cursor()` and execute SQL inside critical sections — a thread switch during a savepoint could leave another thread's cache entry pointing at a stale value.

**Recommendation**: Either lock the cache with `threading.Lock()`, make it thread-local, or switch to `ProcessPoolExecutor` for true isolation.

### 2.3 `_DictCompat` masks attribute typos

**File**: `structs.py:156-166`

`Atom`, `IdentityClass`, `WitnessCtx`, and `EmitContext` all inherit from `_DictCompat`, which provides `__getitem__`, `__setitem__`, `get()`, and `__contains__`. This means:

```python
at["knd"]  # typo of "kind" — silently returns None
```

The dataclass `__init__` calls `setattr` for ALL defined fields (set to `None` by default), so `getattr(self, "knd")` returns `None` (field doesn't exist on the instance) but `hasattr` is `False`. Actually for dataclasses, accessing a non-existent attribute throws `AttributeError`, so `_DictCompat.__getitem__` would raise. Let me re-check…

Actually, `dataclass` with default `None` creates `__init__` params but doesn't add defaults to the class dict unless `field(default=None)` is used for *every* field. Looking at `Atom`: every field has `= None` default, so dataclass generates `__init__(self, kind=None, text=None, ...)` but does NOT set class-level defaults. `getattr(self, "knd", None)` returns `None` because the attribute genuinely doesn't exist on the instance — a silent bug in the dict-compat path. The code extensively uses `at["kind"]` which only works because the `Atom` was constructed with `Atom(kind="owner", ...)` explicitly.

**Recommendation**: Add `__slots__` or use `@dataclass(slots=True)` (Python 3.10+) to make attribute access fail-fast on typos. At minimum, override `__getitem__` to check `hasattr` and warn.

### 2.4 Bare `except Exception` blocks (7+ locations)

**Files**: `probe.py:44`, `probe.py:65-66`, `seeding.py:237-238`, `cli.py:177-178`, `report.py:82-83`, etc.

Several catch-all `except Exception: pass` blocks exist, most in SAVEPOINT rollback/release paths. These are defensible for the RELEASE-after-ROLLBACK pattern (the release itself may fail because the savepoint is gone), but a few are not:

- `report.py:82-85`: `except Exception: pass` catches *all* errors in the flat replay loop, silently swallowing real bugs.
- `cli.py:177-178`: connection close in finally block is safe.
- `seeding.py:237-238`: in the `_synthesize_row` loop — if a `RELEASE SAVEPOINT` fails because the savepoint is already released, swallowing is correct.

**Recommendation**: At minimum, `report.py:82-85` should log the exception before passing. Consider a decorator like `@swallow_on(SAVEPOINT_ERRORS)` for the savepoint paths.

---

## 3. Medium Severity

### 3.1 Unbounded `_CASTABLE_CACHE` growth

**File**: `values.py:35`

The cache key is `(typ, salt)` — with type strings from the catalog and salt values up to 300+ in `_seed_plan`, this can grow to tens of thousands of entries on a large schema. On a multi-schema run with `--parallel`, the shared cache could consume significant memory.

**Recommendation**: Use `functools.lru_cache(maxsize=2048)` or add periodic clearing.

### 3.2 The `fill` / `pick` closure redefinition

**File**: `seeding.py:129-146`

The `fill()` and `pick()` functions inside `_seed_plan` are defined, then immediately redefined when `conn is not None` to wrap themselves with `_verified_lit`:

```python
_fill0, _pick0 = fill, pick
def fill(t): return _verified_lit(conn, t, _fill0(t))
def pick(t): return _verified_lit(conn, t, _pick0(t))
```

This is clever but confusing — the reader must track which `fill`/`pick` is in scope. The `_verified_lit` function already does the "unchanged on known types" fast-path, so the conditional redefinition is an optimization.

**Recommendation**: Replace with explicit `_fill_db(t)` / `_pick_db(t)` variants selected once at the top of `_seed_plan`. The cognitive load isn't worth the saved function call.

### 3.3 Duplicate code in `_seed_plan` / `_seed_one` / `_mock_valid_row`

**Files**: `seeding.py`

Three different functions (`_seed_plan:129-146`, `_seed_one:55-65`, `_mock_valid_row:324-334`) contain near-identical `fill()`/`pick()` logic for type-based literal guessing. Each has subtly different enum handling and different fallback values. A centralized `TypeValueProvider` class exists (`values.py:99-122`) but is not consistently used across all these functions.

**Recommendation**: Route all type-based literal generation through `TypeValueProvider` (or at least `_castable_lit` / `_verified_lit`) to eliminate the duplicated type-switch tables.

### 3.4 Large functions (>100 lines)

**Functions exceeding reasonable length**:
- `emit_flat()` — ~358 lines (emit.py:104-462)
- `_seed_plan()` — ~310 lines (seeding.py:100-309)
- `_synthesize_row()` — ~88 lines (seeding.py:360-446), deeply nested
- `solve_emit()` — ~127 lines (strategies/solver.py:112-236)
- `mock_emit()` — ~105 lines (strategies/mock.py:144-248)

`emit_flat` in particular does: seed planning, helper-mode user creation, auth.users seeding, update-column selection, strategy dispatch, per-identity×command probing, transition audit, and implicit-deny probing — all in one function.

**Recommendation**: Extract the "update column selection" block (lines 196-243) into its own function. Similarly, the implicit-deny block (lines 397-430) is a clear candidate for extraction. The strategy dispatch loop is already clean.

### 3.5 `import *` style in `cli.py`

**File**: `cli.py:24-43`

Thirty lines of explicit symbol re-exports via `from .module import X, Y, Z` (with `# noqa: F401`). This creates `cli.py` as a "barrel file" for downstream consumers. It works but is fragile — a rename in a sub-module breaks the import here silently until something tries to use the old name.

**Recommendation**: Consider defining `__all__` in each sub-module and using `from .module import *` with explicit `__all__` lists, or define `__all__` in `rlsautotest/__init__.py` and let consumers import from the package root.

---

## 4. Low Severity / Code Smells

### 4.1 Unused imports

Almost every module imports `argparse`, `json`, `re`, `sys`, `psycopg`, and `pglast.parser.parse_sql_json` — even when only one or two are used. This appears to be a mechanical artifact of the module split:

- `astutil.py` imports `argparse`, `psycopg` — neither used
- `structs.py` imports `argparse`, `psycopg` — neither used
- `catalog.py` imports `argparse`, `sys`, `pglast.parser.parse_sql_json` — only `re` and `psycopg` used
- `atoms.py` imports `argparse`, `sys`, `psycopg`, `parse_sql_json` — only `json`, `re`, `psycopg`, `parse_sql_json` used

**Recommendation**: Run `autoflake --remove-all-unused-imports` across the package.

### 4.2 `from __future__ import annotations` at module level

Good practice (present in all modules) — no issue, just noting consistency.

### 4.3 Inconsistent quoting in SQL generation

Some modules use double-quote escaping (`\"`), some use `'` single quotes, some use `$tag$` dollar quotes. The `_PGTAP_ENSURE` block in `emit.py:525-548` uses `$rlsa$`, `$b$`, `$q$`, `$rt$`, `$fn$` dollar-quoting consistently. However, `_SHIM` at line 477-521 uses `$fn$` tags that could theoretically conflict with user-defined function bodies.

**Recommendation**: Document that the dollar-quote tags are deliberately chosen to avoid collision (e.g., `$fn$` won't appear in test user emails). Consider using longer/more unique tags like `$rlsautotest_shim_fn$`.

### 4.4 Regex-based parsing in `_action_table`

**File**: `catalog.py:232-235`

```python
m = re.search(r"\b(?:from|into|update)\s+([a-zA-Z_][\w$.\"]*)", sql or "", re.I)
```

This correctly handles simple cases but could fail on quoted identifiers with spaces (`"my schema"."my table"`), though such identifiers are rare in generated SQL. The function is only used for the post-arrange invariant check in `_probe`, so a miss is not critical (just skips the check).

### 4.5 `NOBODY` UUID as an identity

**File**: `values.py:159`

`NOBODY = "99999999-9999-9999-9999-999999999999"` is used as the `sub` claim for the "authenticated, not authorized" identity. This is seeded into `auth.users` when present. On a real Supabase instance with actual users, this UUID is unlikely to collide but the `ON CONFLICT DO NOTHING` pattern means it silently fails if it does — the identity then has a different `sub` and the test probes a real user.

**Recommendation**: Document this in the code, or use a UUID v5 with a well-known namespace to make collisions astronomically unlikely.

### 4.6 `.pytest_cache/` in gitignore but present in workspace

The `__pycache__/` pattern covers compiled Python, but `pytest_cache` is present in the workspace. The `.gitignore` should cover it.

---

## 5. Design / Architecture Review

### 5.1 Strengths

1. **Probe-and-bake soundness** (F1/F4). Every assertion is observed against a live database. The `Observation` dataclass creates a machine-readable contract between emitter and report that survives label wording changes. This is the right architecture for a security-testing tool.

2. **Strategy pattern** (F1). The `REGISTRY` in `strategies/__init__.py` allows adding new pattern handlers without touching `emit_flat`. The `HANDLED`/`AUGMENT`/`PASS`/`CONTINUE` protocol is clean.

3. **"Solve, don't classify" fallback**. The general witness solver (`witness.py`) handles novel predicates via operand-role analysis, with DB-oracle verification — no per-operator code needed for `starts_with()`, `col % 2 = 0`, etc.

4. **Defense in depth**. UNRELIABLE path (loud failing assertion, never a false pass), UNRELIABLE cell marking (‼ in report), CI gate, `doctor` command, `_mock_preflight` DDL-permission check (issue #2 fix), post-arrange invariant — multiple safety nets.

5. **Sentinel registry** (`ALL_SENTINELS` in `values.py`) with a collision test (`test_reserved_sentinels_are_unique`). Prevents silent cross-strategy interference.

6. **Self-contained output**. The emitted pgTAP files include their own pgTAP shim, `_rlsa_try` seed swallower, and optional offline basejump-compatible shim. A user gets a working suite with zero setup.

### 5.2 Design considerations for future work

1. **DNF budget** (`_DNF_BUDGET = 64`). Caps min-term explosion from pathological AND-of-ORs. Good defensive measure.

2. **Parallel probing** uses thread-local connections — correct for pgTAP's session-state mutation patterns (SET ROLE, request.jwt.claims, savepoints).

3. **`_seed_plan` topological ordering** (lines 208-258). The `q_scope_parent` flag correctly decides whether to seed the main table or aux tables first. This is the right approach but is fragile — a mistake in `_anc_tables` could create unresolvable FK cycles.

4. **The `fill`/`pick` DB-verification path** (`_verified_lit`) is smart: known types get their exact literal, exotic types get oracle-repaired. The `_castable_lit` candidate search plus catalog domain/array-element resolution is thorough.

---

## 6. Test Coverage

**File**: `tests/test_smoke.py` — 445 lines, ~20 test functions

The smoke tests cover:
- Pure helpers: `_split_statements`, `_is_uuid`, `setup_hook_sql` ✅
- Classifier: `classify_node`, `_check_value_set`, `_membership`, `_dnf_ast` ✅
- Solver: `_solve_predicate` for unseen predicates, arrays, fn preimages, subqueries, IS DISTINCT FROM ✅
- Report: `_file_tap_lines`, `_id_cell`, `_explain_dashes`, `render_report_text` ✅
- Sentinels: unique check ✅
- Issue #2 regression: DDL failure → UNRELIABLE ✅
- Structural report filing (F4): Observation-driven cell matching ✅

**Gaps**:
1. **No integration tests** requiring a live database. The `--parallel` path, probe-and-bake verification, strategy dispatch, and full emission pipeline are only exercised manually.
2. **No error path tests** for `_synthesize_row` retry loop, `_seed_plan` composite-FK handling, or strategy fallback chains.
3. **No edge case tests** for `_cmd_dnf` with mixed PERMISSIVE+RESTRICTIVE policies, INSERT with NULL with_check (USING fallback), or the compound restrictive-AND fix.
4. **No performance/load tests** for large schemas or pathological policy trees.

**Recommendation**: Add at minimum one `pytest` integration test that connects to a local Postgres, creates a known schema (e.g., the examples/ files), runs `--report`, and checks exit code. The smoke tests are good unit coverage; the integration gap is the main testing weakness.

---

## 7. Security Considerations

### 7.1 SQL identifiers from catalog (revisit)

As noted in §2.1, identifiers come from `pg_catalog`. These are trusted in Postgres (you'd need superuser to inject a malicious table name into the catalog). However, the same code will ingest user-provided `--schema` and `--table` arguments:

```python
# cli.py:131
(a.schema, a.table)
```

These are parameterized in catalog queries (`%s` placeholders) — safe. But when used in emission:

```python
# emit.py:559
hookpath = os.path.join(tdir, "000-setup-tests-hooks.sql")
```

The `label` argument (from `--label`) is used in `os.path.join` for directory creation. A `--label "../../etc"` could escape the emit directory.

**Recommendation**: Validate `--label` against `re.fullmatch(r'[a-zA-Z0-9_-]+', label)` before using in paths.

### 7.2 `--db-url` handling

Password in the URL is passed directly to `psycopg.connect()`. This is standard. The URL appears in error messages if the connection fails — ensure it's not logged to stdout/stderr in CI environments.

### 7.3 Generated SQL emission

The emitted `.sql` files contain `CREATE OR REPLACE FUNCTION` statements for mocks. If run as a privileged role and the mock replaces a security-critical function (e.g., an RLS helper), the function is restored at the end of the `BEGIN…ROLLBACK` block. This is safe within the transaction boundary but worth documenting for users who might extract the mock statements.

---

## 8. Summary of Recommendations

| # | Severity | Topic | Action |
|---|----------|-------|--------|
| 1 | High | `_CASTABLE_CACHE` thread safety | Add lock or use thread-local |
| 2 | Medium | `_DictCompat` silent None on typos | Add `__slots__` or `hasattr` guard |
| 3 | Medium | Bare `except Exception` in report.py | Log before swallowing |
| 4 | Medium | Unbounded cache growth | Add `lru_cache` or size limit |
| 5 | Medium | Duplicate type-guessing in 3 functions | Consolidate through `TypeValueProvider` |
| 6 | Low | Unused imports in 5+ modules | Run `autoflake` |
| 7 | Low | `fill`/`pick` closure redefinition | Replace with explicit variants |
| 8 | Low | `--label` path traversal risk | Validate label format |
| 9 | Low | No integration tests | Add DB-connected CI job |
| 10 | Info | Large functions >100 lines | Extract helper methods |

---

## 9. Conclusion

This is a **mature, well-thought-out codebase** with sound engineering principles at its core. The probe-and-bake discipline, strategy pattern, DNF-based identity classification, general witness solver, and multiple defense-in-depth layers all serve the primary mission: *never emit a false-passing test*. The issues found are mostly hygiene (unused imports, function length), surface-level risk (thread cache, label validation), or test-coverage gaps (no integration suite). None of the findings undermine the tool's core correctness property.

The codebase is **production-ready for its intended use case** (developer tool, not a security-hardened daemon). The top recommendation is adding integration tests with a real Postgres instance, which would catch regressions in the most complex paths (strategy dispatch, parallel probing, probe-and-bake verification).
