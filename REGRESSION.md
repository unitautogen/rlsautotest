# Regression results

- Run (UTC): `2026-06-22T14:00:01+00:00`
- Database: `rls_regression` (rebuilt from `examples/` by `regression/run_regression.py`)
- Schemas: public, tenancy, exotic, rbac
- Totals: **16 files, 115 tests, 0 failed**

| schema | test file | tests | ok | not ok | status |
|---|---|--:|--:|--:|---|
| public | 010-rls-enabled.test.sql | 2 | 2 | 0 | ✅ PASS |
| public | 101-rls-notes.test.sql | 12 | 12 | 0 | ✅ PASS |
| public | 102-rls-profiles.test.sql | 9 | 9 | 0 | ✅ PASS |
| tenancy | 010-rls-enabled.test.sql | 4 | 4 | 0 | ✅ PASS |
| tenancy | 101-rls-invoices.test.sql | 12 | 12 | 0 | ✅ PASS |
| tenancy | 102-rls-memberships.test.sql | 3 | 3 | 0 | ✅ PASS |
| tenancy | 103-rls-orgs.test.sql | 3 | 3 | 0 | ✅ PASS |
| tenancy | 104-rls-projects.test.sql | 12 | 12 | 0 | ✅ PASS |
| exotic | 010-rls-enabled.test.sql | 5 | 5 | 0 | ✅ PASS |
| exotic | 101-rls-documents.test.sql | 12 | 12 | 0 | ✅ PASS |
| exotic | 102-rls-folders.test.sql | 3 | 3 | 0 | ✅ PASS |
| exotic | 103-rls-items.test.sql | 9 | 9 | 0 | ✅ PASS |
| exotic | 104-rls-posts.test.sql | 11 | 11 | 0 | ✅ PASS |
| exotic | 105-rls-projects.test.sql | 3 | 3 | 0 | ✅ PASS |
| rbac | 010-rls-enabled.test.sql | 1 | 1 | 0 | ✅ PASS |
| rbac | 101-rls-creditors.test.sql | 14 | 14 | 0 | ✅ PASS |

Results are also stored in the regression DB: `SELECT * FROM regression.results;`.
