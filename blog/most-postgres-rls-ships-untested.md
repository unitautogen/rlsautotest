# Most Postgres RLS ships untested. Here's how to test it with pgTAP.

Row-Level Security is the security boundary of most Postgres and Supabase apps. It's the one thing standing between "users see their own data" and a cross-tenant leak. And yet most RLS I see in the wild has zero tests — not because people don't care, but because testing RLS well is fiddly, and a test that *looks* like it passes often proves nothing at all.

This post is about how to actually test RLS with [pgTAP](https://pgtap.org): the mechanics, the traps, and the handful of cases that bite you. No tooling required to follow along — just `psql` and pgTAP (which Supabase ships, and you can `CREATE EXTENSION pgtap` anywhere else).

## Why RLS is hard to test

Four things make RLS testing different from normal unit testing:

**1. You have to *become* each identity.** A policy like `USING (owner = auth.uid())` behaves completely differently depending on who's asking. So a real test has to impersonate each one — anonymous, authenticated user A, authenticated user B, the service role — and check what each can actually do. In Postgres/Supabase terms that's `SET ROLE` plus setting the request's JWT claims.

**2. `USING` and `WITH CHECK` are not the same thing.** `USING` controls which rows you can *see/affect* (SELECT, UPDATE, DELETE). `WITH CHECK` controls which rows you're allowed to *write* (INSERT, and the new value on UPDATE). A table can be perfectly locked down for reads and wide open for writes, or vice versa. You have to test both directions.

**3. "Denied" has two completely different shapes.** When someone can't do something, it's either:
- **filtered to zero rows** — RLS silently hides rows (no error), or
- **a hard permission error** (`42501`) — the role doesn't even have the table grant.

These mean different things, and conflating them hides bugs. A test that just checks "got an error" will miss an RLS policy that's silently returning everyone's rows, because that path doesn't error — it returns data.

**4. The seed-data trap — this is the big one.** A test only proves something if the data driving it actually exercises the policy. If your table is empty, "user B sees 0 rows" passes whether or not the policy works. If the row you seeded isn't actually owned by the user you're impersonating, "owner sees their row" fails — or worse, accidentally passes for the wrong reason. The data has to match the identity and the predicate, or the green checkmark is a lie.

## A real pgTAP RLS test

Here's an owner-scoped `documents` table tested by hand. The shape is Arrange → Act → Assert, wrapped in a transaction that rolls back so tests don't pollute each other.

```sql
begin;
select plan(3);

-- ARRANGE: seed as the test-runner role (superuser/owner — bypasses RLS).
-- Two users, one document owned by user A.
insert into auth.users (id) values
  ('00000000-0000-0000-0000-00000000000a'),
  ('00000000-0000-0000-0000-00000000000b');
insert into documents (owner, title)
  values ('00000000-0000-0000-0000-00000000000a', 'A''s doc');

-- ACT/ASSERT as user A (the owner) — should see exactly their row
set local role authenticated;
select set_config('request.jwt.claims',
  '{"sub":"00000000-0000-0000-0000-00000000000a","role":"authenticated"}', true);
select is( (select count(*) from documents)::int, 1, 'owner sees their own row' );

-- as user B (a *different* authenticated user) — should see nothing
select set_config('request.jwt.claims',
  '{"sub":"00000000-0000-0000-0000-00000000000b","role":"authenticated"}', true);
select is( (select count(*) from documents)::int, 0, 'another user sees nothing' );

-- as anon — should see nothing
reset role;
set local role anon;
select set_config('request.jwt.claims', '', true);
select is( (select count(*) from documents)::int, 0, 'anon sees nothing' );

select * from finish();
rollback;
```

Notice the two things that make this *mean* something: we seeded a row that is genuinely owned by user A (so "owner sees their row" is a real assertion, not a fluke against empty data), and the negative case is a real, different authenticated user — not just "logged out."

## The cases that bite you

Once the basic shape is in place, these are the ones that catch people:

**INSERT is governed by `WITH CHECK`, which constrains the row, not the caller.** A user who can't see another tenant's data can usually still insert *their own* row — and that's correct, not a hole. The actual hole is `WITH CHECK (true)` (anyone can write anything) or RLS being off entirely. So an INSERT test should assert two things: the caller *can* insert a row that satisfies the check, and *cannot* insert one that violates it (e.g. a row attributed to someone else).

```sql
-- a different user inserting their OWN row: allowed (WITH CHECK passes)
select lives_ok(
  $$ insert into documents (owner, title) values (auth.uid(), 'mine') $$,
  'user can insert their own row'
);
-- inserting a row owned by someone ELSE: must be rejected
select throws_ok(
  $$ insert into documents (owner, title)
       values ('00000000-0000-0000-0000-00000000000a', 'not mine') $$,
  '42501', null, 'user cannot insert a row for another owner'
);
```

**Tenant isolation needs a real rival tenant.** The meaningful negative test for `org_id = (auth.jwt() -> 'app_metadata' ->> 'org_id')::uuid` isn't an outsider with no org — it's a legitimate user of a *different* org. That's the test that catches a subtly-wrong predicate like `org_id IS NOT NULL`, which a no-org outsider would pass right through.

**RBAC via SECURITY DEFINER functions.** Policies that delegate to `authorize('documents.read')` or `has_role('admin')` are opaque to a black-box test — you can't always drive them through the JWT. You test the *wiring*: set up the state the function reads (or control the function), then assert that the policy is allowed when it returns true and denied when it returns false.

**Self-referential policies.** A policy that queries its own table (a recursive folder tree, say) can throw `infinite recursion detected in policy`, which locks out *every* client role. Worth an explicit "the table is even readable" test.

## Doing this for a whole schema

None of the above is hard for one table. The problem is that a real app has dozens of tables, four commands each, and several identities — and every single combination needs its own seeded precondition to mean anything. That's a lot of careful, repetitive SQL, and the failure mode is silent: a test that passes against the wrong data tells you you're safe when you're not.

That repetition is exactly what pushed me to write a generator — [rlsautotest](https://github.com/unitautogen/rlsautotest) reads your policies straight from the catalog and emits this pgTAP for you, including the seed data that matches each policy and identity. It's free and open source. But whether you generate the tests or hand-write them, the principles above are the part that matters: become each identity, test both `USING` and `WITH CHECK`, distinguish "0 rows" from "denied," and make sure your seed data actually exercises the policy.

Your RLS is your security boundary. Test it like one.
