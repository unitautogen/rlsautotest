# The "looks owner-scoped, isn't" footgun — a 30-second rlsautotest demo

You ship what looks like an owner-only policy on your `documents` table:

```sql
create policy documents_select on documents for select to authenticated
  using ( owner_id = (select auth.uid()) or status = 'active' );
```

Intent: *"a user sees only their own active documents."* You point rlsautotest at a **copy** of the database:

```bash
pip install rlsautotest
rlsautotest --db-url "$COPY_URL" --schema demo --report
```

### Before — the access matrix

```
documents  [RLS on]
  identity                       SELECT   INSERT   UPDATE   DELETE
  service_role                   ✓        ✓        ✓        ✓
  authenticated, authorized      ✓        ·        ·        ·
  authenticated, not authorized  ✓        ·        ·        ·     ←  ⚠ a non-owner can READ
  anon                           ·        ·        ·        ·
legend: ✓ can · blocked  ✓! should-be-blocked-but-can  – not tested
```

That ✓ on **`authenticated, not authorized`** is the bug. `OR status = 'active'` is a *standalone* grant — it depends on the row, not the user — so **every authenticated user can read every active document**, not just their own. The policy reads as owner-scoped; the matrix shows its real reach. (INSERT/UPDATE/DELETE are `·` because the policy only covers SELECT, so those commands are denied — which is correct.)

### The fix is one word: `OR` → `AND`

```sql
alter policy documents_select on documents
  using ( owner_id = (select auth.uid()) and status = 'active' );
```

### After — re-run, the matrix flips

```
documents  [RLS on]
  identity                       SELECT   INSERT   UPDATE   DELETE
  service_role                   ✓        ✓        ✓        ✓
  authenticated, authorized      ✓        ·        ·        ·     ←  owner still reads their own
  authenticated, not authorized  ·        ·        ·        ·     ←  non-owner now BLOCKED
  anon                           ·        ·        ·        ·
```

The leak is closed: the owner keeps access, the non-owner is blocked.

### Why this is the honest version

rlsautotest doesn't guess your intent — it can't know whether you *meant* `status = 'active'` to be public, so it doesn't scream "BUG." It seeds the rows, runs the real `SELECT` as each identity, and **shows you the policy's true reach** (and emits the pgTAP tests + seed data that prove it), then hands you the judgment. The before/after above is real and reproducible — `demo_or_footgun.sql` plus the two HTML reports are in this bundle.
