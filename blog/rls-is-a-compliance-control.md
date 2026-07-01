# Your Postgres RLS is a compliance control. Is it tested?

If you're building on PostgreSQL (Supabase, RDS, Neon, or your own server) and touching health data, customer records, or anything an auditor cares about, Row-Level Security isn't just a nice-to-have. It's your access-control safeguard: the mechanism that keeps each patient, tenant, or customer to their own rows. Which means the moment you're under HIPAA or SOC 2, your RLS policies aren't just code. They're *controls*, and controls get audited.

Here's the uncomfortable part: most RLS ships untested. And an untested access control isn't a control. It's an assumption.

## RLS is literally the safeguard the frameworks ask for

HIPAA's Security Rule requires technical access controls that allow access "only to those persons or software programs that have been granted access rights" ([45 CFR §164.312(a)(1)](https://www.law.cornell.edu/cfr/text/45/164.312)). That's RLS's job description, and RLS is native PostgreSQL, enforced in the database on every deployment. If you're on Supabase, [their HIPAA guidance](https://supabase.com/docs/guides/security/hipaa-compliance) points to RLS as the way to guarantee each provider, clinic, or patient sees only their own data; the same mechanism does the same job on RDS, Neon, or a self-hosted cluster.

[SOC 2](https://supabase.com/docs/guides/security/soc-2-compliance) says the same thing in different words. Common Criteria CC6.1 requires that logical access to protected information be restricted to authorized users. RLS is that restriction, enforced in the database, where an application bug can't route around it.

So the compliance question isn't "do you use RLS?" Everyone says yes. The question is "can you show it works?"

## "We use RLS" is a claim. An auditor wants evidence

This is where untested RLS quietly fails. A policy with the wrong column, an `OR` that's too generous, a `USING (true)` left in from debugging: all of these pass code review and sit in production looking fine. Nothing errors. The dashboard is green. And a different tenant can read PHI.

You won't catch that by reading the policy. You catch it by *exercising* it: becoming each identity (the owner, another tenant, an anonymous visitor) and checking what each one can actually `SELECT`, `INSERT`, `UPDATE`, and `DELETE`. That's the difference between asserting a control exists and demonstrating that it enforces.

## What auditable evidence looks like

Evidence for an access-control safeguard is concrete and repeatable:

- a per-identity, per-table, per-command result showing exactly who can touch which rows, including who's blocked;
- a test suite committed alongside your migrations, so the evidence regenerates on every change;
- a CI gate that turns the build red the instant a policy leaks or a table ships without RLS.

That's not a screenshot of a settings page. That's a test run you can hand to a reviewer: dated and reproducible.

## Where rlsautotest fits

`rlsautotest` generates exactly that evidence, without you hand-writing test SQL. Point it at a disposable copy of your database; it reads your RLS policies, generates both the tests *and* the seed data that make them mean something, probes each policy as each identity, and emits a native [pgTAP](https://pgtap.org) suite plus a per-identity access report and a CI gate. (pgTAP ships on Supabase and loads on any other Postgres; the tool handles it for you.)

```bash
pip install rlsautotest
rlsautotest --db-url "$DATABASE_URL" --schema public --html rls-report.html
```

One command produces the access matrix. `--emit` writes the committable suite; wire it into CI and every pull request re-proves your access controls.

## The honest boundary

`rlsautotest` verifies one thing well: that your database *enforces what your policies declare*. That's the access-control safeguard: a real, checkable piece of your HIPAA and SOC 2 posture. It is not your whole compliance program. Your BAA (with Supabase, your cloud provider, or however you host), encryption, audit logging, and the rest remain yours to own. And it proves declared-versus-enforced, not intent: a policy that's wrong on purpose will be faithfully, greenly confirmed.

But within its lane, it turns "we use RLS" into "here's the test run that shows our RLS restricts access as designed." For a control that's one misplaced predicate away from a breach notification, that's the difference that matters.

---

*`rlsautotest` is the free, open-source PostgreSQL member of [UnitAutogen](https://github.com/unitautogen): automated database test generators. Apache-2.0.*
