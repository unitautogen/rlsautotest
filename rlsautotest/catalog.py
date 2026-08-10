# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""Postgres catalog loaders: columns, FKs, constraints, grants, RLS table discovery.

Split out of the original single-module cli.py; behavior-preserving.
"""
from __future__ import annotations
import re
from .astutil import _CMDS4, _and_conjuncts, _array_consts, _colname, _const, _list_consts, _names, _t, _unwrap, _v, _where
from .checkwitness import _fmt_check_witness



# ---------- catalog helpers (self-contained; no external module deps) ----------
def _columns(cur, schema, table):
    cur.execute("""
        SELECT a.attname, format_type(a.atttypid, a.atttypmod),
               a.attnotnull, (a.atthasdef OR a.attidentity <> '') AS hasdef
        FROM pg_attribute a
        JOIN pg_class c ON c.oid = a.attrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname=%s AND c.relname=%s AND a.attnum>0 AND NOT a.attisdropped
        ORDER BY a.attnum""", (schema, table))
    return cur.fetchall()



def _fk_of(cur, schema, table, col):
    cur.execute("""
        SELECT nf.nspname, cf.relname, af.attname
        FROM pg_constraint k
        JOIN pg_class c   ON c.oid  = k.conrelid
        JOIN pg_namespace n  ON n.oid  = c.relnamespace
        JOIN pg_class cf  ON cf.oid = k.confrelid
        JOIN pg_namespace nf ON nf.oid = cf.relnamespace
        JOIN pg_attribute a  ON a.attrelid = k.conrelid  AND a.attnum  = k.conkey[1]
        JOIN pg_attribute af ON af.attrelid = k.confrelid AND af.attnum = k.confkey[1]
        WHERE n.nspname=%s AND c.relname=%s AND k.contype='f'
              AND array_length(k.conkey,1)=1 AND a.attname=%s
        LIMIT 1""", (schema, table, col))
    return cur.fetchone()



def _check_seed_meta(cdef):
    """One CHECK definition -> the first seedable fact in it (AST, no regex on SQL):
      ("col", value)            for  col = 'str'  /  col = ANY(ARRAY['a',...])  /  col IN ('a',...)
      or a relcheck tuple       for  a <op> b     (cross-column / column-vs-integer comparison)
    Mirrors the old regex semantics: string-valued equalities only, first match wins."""
    body = cdef or ""
    if body.upper().startswith("CHECK"):
        body = body[5:].strip()
    w = _where(body)
    if w is None:
        return None, None
    conjs = _and_conjuncts(w)
    if conjs is None:
        conjs = [w]
    rel = None
    for cj in conjs:
        if _t(cj) != "A_Expr":
            continue
        op = _names(_v(cj).get("name"))
        l, r = _v(cj).get("lexpr"), _v(cj).get("rexpr")
        if op == "=":
            for a, b in ((l, r), (r, l)):
                col = _colname(a)
                if not col:
                    continue
                bu = _unwrap(b)
                if _t(bu) == "A_Const" and "sval" in _v(bu):            # col = 'string'
                    return (col, _v(bu)["sval"].get("sval", "")), None
                vals = _array_consts(b) or _list_consts(b)              # col = ANY(ARRAY[...]) / IN (...)
                if vals and isinstance(vals[0], str):
                    return (col, vals[0]), None
        elif op in ("<", "<=", ">", ">=") and rel is None:
            a = _colname(l); b = _colname(r)
            if a is None and _const(l) is not None and str(_const(l)).lstrip("-").isdigit(): a = str(_const(l))
            if b is None and _const(r) is not None and str(_const(r)).lstrip("-").isdigit(): b = str(_const(r))
            if a and b:
                rel = (a, op, b)   # cross-column comparison (both sides resolved to columns at fill time)
    return None, rel


def _constraint_meta(cur, schema, table):
    """Per-table constraint metadata for seeding:
      checks    {col: 'literal'}            -- value-set CHECK (role/status) -> a CHECK-satisfying value
      cuniques  [[cols], ...]               -- composite UNIQUE/PK col-sets -> keep seeded rows distinct
      relchecks [(colA, op, colB), ...]     -- cross-column CHECK (lo < hi) -> fill an ordered pair
      compfks   [{cols, parent, pcols}, ...]-- composite FK -> seed the composite parent tuple"""
    cur.execute("""
        SELECT c.contype, pg_get_constraintdef(c.oid),
               (SELECT array_agg(a.attname ORDER BY k.ord) FROM unnest(c.conkey)  WITH ORDINALITY k(attnum, ord) JOIN pg_attribute a ON a.attrelid = c.conrelid  AND a.attnum = k.attnum),
               (SELECT array_agg(a.attname ORDER BY k.ord) FROM unnest(c.confkey) WITH ORDINALITY k(attnum, ord) JOIN pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = k.attnum),
               (SELECT n2.nspname || '.' || r2.relname FROM pg_class r2 JOIN pg_namespace n2 ON n2.oid = r2.relnamespace WHERE r2.oid = c.confrelid)
        FROM pg_constraint c
        JOIN pg_class r ON r.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = r.relnamespace
        WHERE n.nspname = %s AND r.relname = %s AND c.contype IN ('c', 'u', 'p', 'f')""", (schema, table))
    checks, cuniques, relchecks, compfks = {}, [], [], []
    for (contype, cdef, cols, fcols, parent) in cur.fetchall():
        if contype == 'c':
            # F6: read the CHECK definition's parse tree, not regexes over its text — a cast-wrapped
            # column ((status)::text = 'live') no longer mis-files the value under the CAST NAME
            # ("text"), which left the real column unfilled and the seed row failing its own CHECK.
            ck, rel = _check_seed_meta(cdef)
            if ck:
                checks[ck[0]] = "'" + str(ck[1]).replace("'", "''") + "'"
            elif rel:
                relchecks.append(rel)
            else:
                # Single-column FORMAT / LENGTH CHECK (regex `~`/`~*`, LIKE, or a length bound): construct
                # ONE conforming value (checkwitness) so the column seeds instead of failing its own CHECK
                # and dragging the row to UNRELIABLE. The seed probe still verifies it downstream, so a value
                # that does not actually satisfy the CHECK just re-fails and the cell stays honestly
                # UNRELIABLE -- this can only ever turn an UNRELIABLE cell into a real, probe-baked green.
                fw = _fmt_check_witness(cdef)
                if fw and fw[0] not in checks:
                    checks[fw[0]] = "'" + str(fw[1]).replace("'", "''") + "'"
        elif contype in ('u', 'p') and cols and len(cols) > 1:
            cuniques.append(list(cols))
        elif contype == 'f' and cols and len(cols) > 1 and parent and fcols:
            compfks.append({"cols": list(cols), "parent": parent, "pcols": list(fcols)})
    return checks, cuniques, relchecks, compfks



def _fk_by_name(cur, cname):
    """Resolve a FK constraint (by name) -> {parent: 'schema.table', cols: [...], pcols: [...]}. Composite-aware."""
    cur.execute("""SELECT (SELECT n.nspname||'.'||r.relname FROM pg_class r JOIN pg_namespace n ON n.oid=r.relnamespace WHERE r.oid=c.confrelid),
                          (SELECT array_agg(a.attname ORDER BY k.ord) FROM unnest(c.conkey)  WITH ORDINALITY k(an,ord) JOIN pg_attribute a ON a.attrelid=c.conrelid  AND a.attnum=k.an),
                          (SELECT array_agg(a.attname ORDER BY k.ord) FROM unnest(c.confkey) WITH ORDINALITY k(an,ord) JOIN pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.an)
                   FROM pg_constraint c WHERE c.conname=%s AND c.contype='f' LIMIT 1""", (cname,))
    r = cur.fetchone()
    return {"parent": r[0], "cols": list(r[1]), "pcols": list(r[2])} if r and r[0] else None



def _single_unique_col(cur, table_fqn, col):
    """True when `col` ALONE is unique in table_fqn (a single-column PK/UNIQUE constraint, or a full —
    non-partial, non-expression — unique index on exactly that column). Two rows sharing that column
    value CANNOT coexist. Consumers: the member-of-2-tenants probe (a membership table whose user
    column is unique enforces at most ONE membership per user BY SCHEMA, so the two-membership state
    cannot exist in production — nothing to test) and the scalar-subquery lint (a lookup keyed on a
    unique column returns at most one row — the classic profile-lookup shape — and is NOT a hazard)."""
    try:
        cur.execute("""SELECT count(*) FROM pg_index i
                       WHERE i.indrelid = to_regclass(%s) AND i.indisunique
                         AND i.indnkeyatts = 1 AND i.indpred IS NULL AND i.indexprs IS NULL
                         AND (SELECT a.attname FROM pg_attribute a
                              WHERE a.attrelid = i.indrelid AND a.attnum = i.indkey[0]) = %s""",
                    (table_fqn, col))
        r = cur.fetchone()
        return bool(r and r[0])
    except Exception:
        return False



def _check_bool_udfs(cur, cname):
    """Boolean UDFs the named CHECK constraint actually calls -> [(qualified_signature, original_functiondef)].
    Resolved EXACTLY via pg_depend (the constraint's recorded dependency on the function) so a same-named
    function in a different schema is never picked by mistake; falls back to schema-aware parsing of the def.
    These can be neutralized (replaced with SELECT true) to seed past a function-delegated CHECK, then restored."""
    cur.execute("""SELECT n.nspname, p.proname, pg_get_function_identity_arguments(p.oid), pg_get_functiondef(p.oid)
                   FROM pg_constraint c
                   JOIN pg_depend d ON d.classid='pg_constraint'::regclass AND d.objid=c.oid AND d.refclassid='pg_proc'::regclass
                   JOIN pg_proc p ON p.oid=d.refobjid
                   JOIN pg_namespace n ON n.oid=p.pronamespace
                   JOIN pg_type t ON t.oid=p.prorettype
                   WHERE c.conname=%s AND c.contype='c' AND t.typname='bool' AND n.nspname NOT IN ('pg_catalog','information_schema')""", (cname,))
    out = [(f"{nsp}.{pname}({args})", fdef) for (nsp, pname, args, fdef) in cur.fetchall()]
    if out: return out
    cur.execute("SELECT pg_get_constraintdef(oid), connamespace::regnamespace::text FROM pg_constraint WHERE conname=%s AND contype='c' LIMIT 1", (cname,))
    r = cur.fetchone()
    if not r or not r[0]: return []
    cdef, conschema = r[0], r[1]
    for sch, fn in set(re.findall(r"(?:([a-zA-Z_]\w*)\.)?([a-zA-Z_]\w*)\s*\(", cdef)):
        if sch:
            cur.execute("SELECT n.nspname,p.proname,pg_get_function_identity_arguments(p.oid),pg_get_functiondef(p.oid) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_type t ON t.oid=p.prorettype WHERE n.nspname=%s AND p.proname=%s AND t.typname='bool' LIMIT 1", (sch, fn))
        else:
            cur.execute("SELECT n.nspname,p.proname,pg_get_function_identity_arguments(p.oid),pg_get_functiondef(p.oid) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_type t ON t.oid=p.prorettype WHERE p.proname=%s AND t.typname='bool' AND n.nspname=%s LIMIT 1", (fn, conschema))
        fr = cur.fetchone()
        if fr:
            nsp, pname, args, fdef = fr
            out.append((f"{nsp}.{pname}({args})", fdef))
    return out



_FK_SQL = """SELECT a.attname, nf.nspname, cf.relname, af.attname
FROM pg_constraint k
JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace
JOIN pg_class cf ON cf.oid=k.confrelid JOIN pg_namespace nf ON nf.oid=cf.relnamespace
JOIN pg_attribute a ON a.attrelid=k.conrelid AND a.attnum=k.conkey[1]
JOIN pg_attribute af ON af.attrelid=k.confrelid AND af.attnum=k.confkey[1]
WHERE n.nspname=%s AND c.relname=%s AND k.contype='f' AND array_length(k.conkey,1)=1"""



def _basejump_present(cur):
    cur.execute("SELECT to_regprocedure('tests.authenticate_as(text)') IS NOT NULL")
    return bool(cur.fetchone()[0])



def auth_profile(cur, schema):
    """DISCOVER this schema's client-role model from the catalog -- provider-agnostic, no brand switch.

    The engine needs three role slots: the authenticated client, the unauthenticated (public) client, and
    an OPTIONAL RLS-bypass role. Instead of branching on "is this Supabase/Neon", it discovers them:

      * client roles = non-superuser roles that are NOLOGIN (assumed via SET ROLE, the PostgREST model) OR
        referenced by a policy here, AND are actually GRANTED table access in THIS schema. Schema-scoped, so
        a role that merely EXISTS on a shared cluster (an unrelated database's anon/service_role) is ignored;
        connection/owner login roles are excluded.
      * bypass role   = the client role carrying rolbypassrls (Supabase's service_role has it; Neon has none;
        a generic database has one only if it defined one). Emitted as the top row IFF present.
      * authenticated = the conventional `authenticated` role (Supabase/Neon/PostgREST/pg_session_jwt all use
        it), else a policy-referenced client role, else the sole client role.
      * unauth        = the conventional `anon`/`anonymous`, else a granted client role no policy scopes to.

    Yields Supabase's (service_role, authenticated, anon) and Neon's (authenticated, anonymous) with zero
    brand logic, and understands an unknown provider on its own terms. `flavor` is derived from the identity/
    claims function VOCABULARY and is ADVISORY only (for provider quirks like the helper shim), never a gate.
    Returns role NAMES; `service_role` is None when no bypass role is reachable here."""
    # RA-1 + RA-5: a policy with no TO clause is stored as polroles = {0} -- OID 0 is the PUBLIC
    # pseudo-role, has NO row in pg_roles, and therefore can never satisfy a literal OID match. In a
    # schema whose policies all omit TO (very common in the wild), a literal-only match reads every
    # role as "no policy references it". `haspub` carries that fact explicitly. Group inheritance is
    # the same bug class reached through the role graph: a policy `TO admins` applies to every member
    # that inherits admins' privileges, so membership is tested with pg_has_role (what Postgres itself
    # checks), not OID equality. LOGIN roles reachable only via PUBLIC are admitted as client-role
    # candidates, EXCEPT the connecting role and the schema owner (keeps the docstring's contract that
    # connection/owner login roles are excluded).
    cur.execute("""
        WITH sc AS (SELECT oid, nspowner FROM pg_namespace WHERE nspname = %s),
        polr AS (
            SELECT DISTINCT t.roid AS roid
            FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid,
                 LATERAL unnest(p.polroles) AS t(roid)
            WHERE c.relnamespace = (SELECT oid FROM sc) AND t.roid <> 0
        ),
        haspub AS (
            SELECT EXISTS (SELECT 1 FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid
                           WHERE c.relnamespace = (SELECT oid FROM sc)
                             AND p.polroles @> ARRAY[0]::oid[]) AS yes
        )
        SELECT r.rolname, r.rolbypassrls,
               (EXISTS (SELECT 1 FROM polr WHERE pg_has_role(r.oid, polr.roid, 'USAGE'))
                OR (SELECT yes FROM haspub)) AS in_policy
        FROM pg_roles r
        WHERE NOT r.rolsuper AND left(r.rolname, 3) <> 'pg_'
          AND has_schema_privilege(r.oid, (SELECT oid FROM sc), 'USAGE')
          AND (NOT r.rolcanlogin
               OR EXISTS (SELECT 1 FROM polr WHERE pg_has_role(r.oid, polr.roid, 'USAGE'))
               OR ((SELECT yes FROM haspub)
                   AND r.rolname <> current_user
                   AND r.oid <> (SELECT nspowner FROM sc)))
          AND EXISTS (SELECT 1 FROM pg_class c WHERE c.relnamespace = (SELECT oid FROM sc) AND c.relkind = 'r'
                        AND (has_table_privilege(r.oid, c.oid, 'SELECT') OR has_table_privilege(r.oid, c.oid, 'INSERT')
                             OR has_table_privilege(r.oid, c.oid, 'UPDATE') OR has_table_privilege(r.oid, c.oid, 'DELETE')))
        ORDER BY r.rolname
    """, (schema,))
    client = cur.fetchall()                                   # [(rolname, rolbypassrls, in_policy)]
    # MB-9b: a conventionally-named PROBED client role (authenticated/anon/anonymous) that itself carries
    # rolbypassrls must NOT be absorbed into the sanctioned service_role slot -- it is a role we PROBE AS,
    # and probing as a BYPASSRLS role sees every row regardless of policy. Absorb only a NON-probed bypass
    # role (Supabase's service_role); a bypassing client role stays in its slot -> emit bakes it UNRELIABLE.
    bypass = next((n for (n, b, _ip) in client if b and n not in ("authenticated", "anon", "anonymous")), None)   # rolbypassrls role; else None
    rest = [(n, ip) for (n, b, ip) in client if n != bypass]
    names = [n for (n, _ip) in rest]
    if "authenticated" in names:
        authed = "authenticated"
    else:
        authed = next((n for (n, ip) in rest if ip), None) or (names[0] if names else "authenticated")
    unauth = next((n for n in ("anon", "anonymous") if n in names), None)
    if unauth is None:
        unauth = next((n for (n, ip) in rest if n != authed and not ip), None)
    if unauth is None:
        unauth = next((n for n in names if n != authed), "anon")
    cur.execute("SELECT (to_regprocedure('auth.user_id()') IS NOT NULL OR to_regprocedure('auth.session()') IS NOT NULL), "
                "(to_regprocedure('auth.uid()') IS NOT NULL OR to_regprocedure('auth.jwt()') IS NOT NULL)")
    neon_fns, sb_fns = cur.fetchone()
    flavor = "neon" if (neon_fns and not sb_fns) else ("supabase" if sb_fns else "generic")
    # MB-23: does auth.uid()/auth.jwt()/auth.role() read the OLD flat per-claim GUC
    # `request.jwt.claim.<key>` (older GoTrue / hand-rolled) rather than the `request.jwt.claims`
    # JSON the probe sets? The trailing dot distinguishes it from `request.jwt.claims`. If so, the
    # identity emitters ALSO drive the flat GUCs so the identity binds (else it would read NULL).
    cur.execute("""SELECT coalesce(string_agg(pg_get_functiondef(p.oid), ' '), '')
        FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'auth' AND p.proname IN ('uid','jwt','role')""")
    _bodies = (cur.fetchone() or [""])[0] or ""
    claim_style = "flat" if "request.jwt.claim." in _bodies else "json"
    return {"flavor": flavor, "authenticated": authed, "unauth": unauth, "service_role": bypass,
            "claim_style": claim_style}


def probed_bypassrls(cur, roles):
    """MB-9b: which of these PROBED client roles carry rolbypassrls? Probing the row-level matrix AS such a
    role sees every row regardless of policy, so its observations are UNRELIABLE (never a green cell) -- a
    passing read there cannot tell a correct policy from a broken one. auth_profile already excludes
    superusers, so rolbypassrls is the only role-level bypass to catch here; the sanctioned service_role
    slot is NOT passed in (its bypass IS the point of that row). Returns the subset of `roles` that bypass."""
    rs = [r for r in dict.fromkeys(roles) if r]   # de-dup (preserve order), drop falsy/None
    if not rs:
        return set()
    cur.execute("SELECT rolname FROM pg_roles WHERE rolname = ANY(%s) AND rolbypassrls", (rs,))
    return {r[0] for r in cur.fetchall()}



def rls_tables(cur, schema):
    """Every RLS-enabled table in the schema that has at least one policy (test-generation targets)."""
    cur.execute("""SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname=%s AND c.relkind='r' AND c.relrowsecurity
          AND EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid)
        ORDER BY c.relname""", (schema,))
    return [r[0] for r in cur.fetchall()]



def all_tables(cur, schema):
    """Every base table in the schema, with (name, rls_enabled, has_policy) — for the exposure scan."""
    cur.execute("""SELECT c.relname, c.relrowsecurity,
                          EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid)
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname=%s AND c.relkind='r' ORDER BY c.relname""", (schema,))
    return [(r[0], bool(r[1]), bool(r[2])) for r in cur.fetchall()]



def _exposed(cur, schema, table):
    """True if anon/authenticated holds any table privilege (i.e. RLS-off here = readable/writable via API)."""
    cur.execute("SELECT rolname FROM pg_roles WHERE rolname IN ('anon','anonymous','authenticated')")
    roles = [r[0] for r in cur.fetchall()]
    for role in roles:
        cur.execute("SELECT bool_or(has_table_privilege(%s, format('%%I.%%I', %s::text, %s::text), priv)) FROM unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE']) AS priv",
                    (role, schema, table))
        if cur.fetchone()[0]:
            return True
    return False



def _effective_grants(cur, schema, table):
    """Real effective table access for the client roles: schema USAGE AND the per-command table privilege.
    Reads the catalog (no mutation). A missing grant => that command is denied regardless of RLS."""
    cur.execute("SELECT rolname FROM pg_roles WHERE rolname IN ('authenticated','anon','anonymous','service_role')")
    present = {r[0] for r in cur.fetchall()}
    g = {}
    for role in ("authenticated", "anon", "anonymous", "service_role"):
        if role not in present:
            for cmd in _CMDS4: g[(role, cmd)] = False
            continue
        cur.execute("SELECT has_schema_privilege(%s, %s, 'USAGE')", (role, schema))
        usage = bool(cur.fetchone()[0])
        for cmd in _CMDS4:
            if not usage:
                g[(role, cmd)] = False; continue
            cur.execute("SELECT has_table_privilege(%s, format('%%I.%%I', %s::text, %s::text), %s)", (role, schema, table, cmd))
            g[(role, cmd)] = bool(cur.fetchone()[0])
    return g



def _action_table(sql):
    """Best-effort table the action runs against (FROM/INTO/UPDATE x) — used for the post-arrange invariant."""
    m = re.search(r"\b(?:from|into|update)\s+([a-zA-Z_][\w$.\"]*)", sql or "", re.I)
    return m.group(1) if m else None

