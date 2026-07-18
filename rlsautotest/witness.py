# Copyright 2026 Munaf Ibrahim Khatri
# SPDX-License-Identifier: Apache-2.0
"""The general witness solver: per-leaf (sat, fal) builders, DB-verified by the emitter's solve_emit.

Split out of the original single-module cli.py; behavior-preserving.
"""
from __future__ import annotations
import json
import re
from .structs import WitnessCtx
from .values import WV_UID
from .astutil import _array_consts, _colname, _const, _is_func, _jwt_keys, _names, _t, _unwrap, _v, _subquery_sig
from .atoms import _membership, _scalar_lookup



# ---------- general witness solver (solve, don't classify) ----------
# When the named-shape catalog can't classify a predicate, derive inputs that make it TRUE and FALSE by
# reading only the OPERAND ROLES of each comparison (column / const / auth.uid / jwt-claim / GUC / subquery /
# function) and composing across AND/OR/NOT. The witness is VERIFIED against the live DB before any test is
# baked (see solve_emit), so an incomplete guess degrades to NOT_TESTABLE — never a false pass.
_WV_UID = WV_UID   # canonical home: values.ALL_SENTINELS (F10)


def _wv_some(typ, enums):
    """A canonical value of `typ` (for a matching pair)."""
    base = (typ or "text").split("(")[0].strip(); t = (typ or "").lower()
    if base in enums and enums[base]: return enums[base][0]
    if "uuid" in t: return "5ce1a000-0000-4000-8000-0000000000aa"
    if any(k in t for k in ("int", "serial", "numeric", "real", "double", "decimal", "money")): return "100"
    if "bool" in t: return "true"
    if "timestamp" in t: return "2020-01-01 00:00:00+00"
    if "date" in t: return "2020-01-01"
    if "time" in t: return "00:00:00"
    return "rls_a"


def _wv_other(typ, enums, avoid=None):
    """A value of `typ` distinct from `avoid` (for falsifiers / not-in-set)."""
    base = (typ or "text").split("(")[0].strip(); t = (typ or "").lower()
    if base in enums and enums[base]: return next((l for l in enums[base] if l != avoid), enums[base][0])
    if "uuid" in t:
        a = "5ce1a000-0000-4000-8000-0000000000bb"
        return a if avoid != a else "5ce1a000-0000-4000-8000-0000000000cc"
    if any(k in t for k in ("int", "serial", "numeric", "real", "double", "decimal", "money")):
        return "0" if str(avoid) != "0" else "7"
    if "bool" in t: return "false" if str(avoid).lower() == "true" else "true"
    if "timestamp" in t: a = "2021-06-15 12:00:00+00"; return a if str(avoid) != a else "2019-03-03 03:03:03+00"
    if "date" in t: a = "2021-06-15"; return a if str(avoid) != a else "2019-03-03"
    if "time" in t: a = "12:34:56"; return a if str(avoid) != a else "06:06:06"
    return "rls_x" if avoid != "rls_x" else "rls_y"


def _wv_lit(typ, raw):
    if raw is None: return "NULL"
    t = (typ or "").lower()
    if any(k in t for k in ("int", "serial", "numeric", "real", "double", "decimal", "money")) and re.fullmatch(r"-?\d+(\.\d+)?", str(raw)): return str(raw)
    if "bool" in t and str(raw).lower() in ("true", "false"): return str(raw).lower()
    if any(k in t for k in ("timestamp", "date", "time", "interval")):   # cast date/time literals to the column type
        return "'" + str(raw).replace("'", "''") + "'::" + typ
    return "'" + str(raw).replace("'", "''") + "'"


def _wv_ctx(): return WitnessCtx()   # F8: typed, dict-compatible (see structs)


def _candidate_values(ct, enums):
    """A small, type-appropriate set of candidate values to drive a free column true/false for the DB oracle."""
    base = (ct or "text").split("(")[0].strip(); t = (ct or "").lower()
    if base in enums and enums[base]: return list(enums[base]) + [None]
    if any(k in t for k in ("int", "serial", "numeric", "real", "double", "decimal", "money")):
        return ["0", "1", "2", "42", "100", None]
    if "bool" in t: return ["true", "false", None]
    if "uuid" in t: return [_WV_UID, "5ce1a000-0000-4000-8000-0000000000bb", None]
    if "timestamp" in t or "date" in t: return ["2020-01-01", "2099-12-31", None]
    return ["", "A", "Admin", "rls_a", "rls_x", None]   # text: empty / prefix-y / generic


def _candidate_sessions(cpaths):
    """Bounded candidate SESSIONS for the joint search: always the plain authenticated identity (no extra
    claims), plus — when the predicate reads JWT claims — that identity with every referenced claim path set to
    each of a few candidate values. Returns list of (sub, [(keys,val),…])."""
    base = (_WV_UID, [])
    if not cpaths:
        return [base]
    out = [base]
    for v in ("Admin", "A", "rls_a", "rls_x", "0", "1"):     # a few text-ish claim candidates
        out.append((_WV_UID, [(p, v) for p in cpaths]))
    return out


def _subquery_tables(node):
    """BL-12 demand extraction: every subquery in `node` that reads a SINGLE base table -> a spec for how to
    seed ONE row the subquery would count (identity col `= auth.uid()`, correlation cols `= outer col`, extra
    equality/boolean conditions, and the aggregated column if the subquery is sum/avg/min/max). The relational-
    state floor then VARIES HOW MANY such rows it seeds and lets Postgres evaluate the real aggregate. Returns
    a list of specs, or [] (and bails on multi-table joins / OR / unmappable conjuncts -> stays NT).
    F2: a thin adapter over the shared `_subquery_sig` reader — the shape grammar lives there, once."""
    out = []
    def walk(n):
        if isinstance(n, list):
            for x in n: walk(x)
            return
        if not isinstance(n, dict):
            return
        if _t(n) == "SubLink":
            sig = _subquery_sig(_v(n).get("subselect"))
            if sig is not None and not sig["unmodeled"] and not sig["fns"]:
                out.append({"mtable": sig["mtable"], "uid": sig["uid"], "corr": sig["corr"],
                            "extras": sig["extras"], "num": sig["agg"],
                            "scope": "5c0d0000-0000-4000-8000-000000000001"})
            return                                          # don't recurse into the subquery's own subqueries
        for v in n.values(): walk(v)
    walk(node); return out



def _wv_merge(a, b):
    """Combine two witness contexts; None on a contradiction (e.g. a column needs two different values)."""
    if a is None or b is None: return None
    if a["sub"] is not None and b["sub"] is not None and a["sub"] != b["sub"]: return None
    out = {"sub": a["sub"] if a["sub"] is not None else b["sub"], "claims": a["claims"] + b["claims"],
           "guc": dict(a["guc"]), "row": dict(a["row"]), "aux": a["aux"] + b["aux"], "role": a["role"]}
    for c, val in b["row"].items():
        if c in out["row"] and out["row"][c] != val: return None
        out["row"][c] = val
    for k, val in b["guc"].items():
        if k in out["guc"] and out["guc"][k] != val: return None
        out["guc"][k] = val
    seen = {}
    for keys, val in out["claims"]:
        kk = tuple(keys)
        if kk in seen and seen[kk] != val: return None
        seen[kk] = val
    return out


def _side_role(node):
    """Operand role of one side of a comparison: ('col',name)/('const',v)/('uid',)/('claim',keys)/('guc',name)/(None,)."""
    if _is_func(node, "auth.uid"): return ("uid", None)
    k = _jwt_keys(node)
    if k: return ("claim", k)
    u = _unwrap(node)
    if _t(u) == "FuncCall" and _names(_v(u).get("funcname")).split(".")[-1] == "current_setting":
        a = _v(u).get("args", []); nm = _const(a[0]) if a else None
        if nm: return ("guc", nm)
    c = _colname(node)
    if c: return ("col", c)
    cv = _const(node)
    if cv is not None: return ("const", cv)
    return (None, None)


def _solve_eq(L, R, coltypes, enums):
    lr, rr = _side_role(L), _side_role(R)
    for x, y in ((lr, rr), (rr, lr)):                       # claim/GUC compared to a const (no column): e.g. an OR admin escape hatch
        if x[0] == "claim" and y[0] == "const":
            sat, fal = _wv_ctx(), _wv_ctx()
            sat["claims"].append((x[1], y[1])); fal["claims"].append((x[1], _wv_other("text", enums, y[1]))); return (sat, fal)
        if x[0] == "guc" and y[0] == "const":
            sat, fal = _wv_ctx(), _wv_ctx()
            sat["guc"][x[1]] = y[1]; fal["guc"][x[1]] = _wv_other("text", enums, y[1]); return (sat, fal)
    if rr[0] == "col" and lr[0] in ("col", "const", "uid", "claim", "guc"): lr, rr = rr, lr   # put the column on the left
    if lr[0] != "col": return None
    col = lr[1]; ct = coltypes.get(col, "text"); sat, fal = _wv_ctx(), _wv_ctx()
    if rr[0] == "const":
        sat["row"][col] = rr[1]; fal["row"][col] = _wv_other(ct, enums, rr[1]); return (sat, fal)
    if rr[0] == "uid":
        sat["sub"] = _WV_UID; sat["row"][col] = _WV_UID; fal["sub"] = _WV_UID; fal["row"][col] = _wv_other("uuid", enums, _WV_UID); return (sat, fal)
    if rr[0] == "claim":
        V = _wv_some(ct, enums); sat["claims"].append((rr[1], V)); sat["row"][col] = V
        fal["claims"].append((rr[1], V)); fal["row"][col] = _wv_other(ct, enums, V); return (sat, fal)
    if rr[0] == "guc":
        V = _wv_some(ct, enums); sat["guc"][rr[1]] = V; sat["row"][col] = V
        fal["guc"][rr[1]] = V; fal["row"][col] = _wv_other(ct, enums, V); return (sat, fal)
    if rr[0] == "col":
        V = _wv_some(ct, enums); sat["row"][col] = V; sat["row"][rr[1]] = V
        fal["row"][col] = V; fal["row"][rr[1]] = _wv_other(coltypes.get(rr[1], "text"), enums, V); return (sat, fal)
    return None


def _solve_ineq(op, L, R, coltypes, enums):
    lr, rr = _side_role(L), _side_role(R)
    _num = lambda c: any(k in (coltypes.get(c, "") or "").lower() for k in ("int", "numeric", "real", "double", "decimal", "serial", "money"))
    if lr[0] == "col" and rr[0] == "col":                   # cross-column inequality (a < b): seed both to satisfy / violate
        a, b = lr[1], rr[1]
        if not (_num(a) and _num(b)): return None
        hi = op in (">", ">=")
        sat, fal = _wv_ctx(), _wv_ctx()
        sat["row"][a], sat["row"][b] = ("9", "1") if hi else ("1", "9")
        fal["row"][a], fal["row"][b] = ("1", "9") if hi else ("9", "1")
        return (sat, fal)
    if lr[0] == "col" and rr[0] in ("claim", "guc", "const"): col, inp, col_left = lr[1], rr, True
    elif rr[0] == "col" and lr[0] in ("claim", "guc", "const"): col, inp, col_left = rr[1], lr, False
    else: return None
    if not _num(col): return None
    eff = op if col_left else {">": "<", "<": ">", ">=": "<=", "<=": ">="}[op]
    hi_col = eff in (">", ">=")
    sat, fal = _wv_ctx(), _wv_ctx()
    def put(ctx, cv, iv):
        ctx["row"][col] = cv
        if inp[0] == "claim" and iv is not None: ctx["claims"].append((inp[1], iv))
        elif inp[0] == "guc" and iv is not None: ctx["guc"][inp[1]] = iv
    if inp[0] == "const":
        try: c = int(float(inp[1]))
        except Exception: return None
        pairs = {">=": (c, c - 1), ">": (c + 1, c), "<=": (c, c + 1), "<": (c - 1, c)}[eff]
        put(sat, str(pairs[0]), None); put(fal, str(pairs[1]), None); return (sat, fal)
    if hi_col: put(sat, "1000000", "1"); put(fal, "1", "1000000")
    else:      put(sat, "1", "1000000"); put(fal, "1000000", "1")
    return (sat, fal)


def _class_pick(cls):
    """A single char satisfying a regex character-class body `cls` (the text between [ ])."""
    if not cls: return None
    if cls[0] == '^':                                   # negated class -> a char unlikely to be excluded
        return next((ch for ch in ('z', 'q', 'x', '0', 'a') if ch not in cls[1:]), None)
    if len(cls) >= 3 and cls[1] == '-': return cls[0]   # range a-z / 0-9 -> low end
    return cls[0]


def _regex_match(pat):
    """A string that MATCHES POSIX regex `pat` (heuristic; common constructs only), or None if unsure.
    DB-verified downstream, so a wrong guess degrades to NOT_TESTABLE — never a false pass."""
    p = pat
    if p.startswith('^'): p = p[1:]
    if p.endswith('$') and not p.endswith('\\$'): p = p[:-1]
    out, i, n = [], 0, len(p)
    while i < n:
        c = p[i]; q = p[i + 1] if i + 1 < n else ''
        if c == '\\' and i + 1 < n:
            out.append({'d': '0', 'w': 'a', 's': ' '}.get(p[i + 1], p[i + 1])); i += 2; continue
        if c == '.':
            if q in ('*', '?'): i += 2; continue
            out.append('x'); i += 2 if q == '+' else 1; continue
        if c == '[':
            j = p.find(']', i + 1)
            if j == -1: return None
            ch = _class_pick(p[i + 1:j])
            if ch is None: return None
            q2 = p[j + 1] if j + 1 < n else ''
            if q2 in ('*', '?'): i = j + 2; continue
            out.append(ch); i = j + (2 if q2 == '+' else 1); continue
        if c in ('(', ')'): i += 1; continue
        if c == '|': break                              # take the first alternative
        if c in ('*', '?', '+'): i += 1; continue       # quantifier on prior literal: one copy already emitted
        if c in ('{', '}'): return None                 # bounded repetition -> bail (rare)
        out.append(c); i += 1
    s = "".join(out)
    return s if s else "x"


def _like_match(pat):
    """A string that MATCHES a LIKE/ILIKE pattern `pat`  (% -> empty, _ -> one char, \\x -> literal x)."""
    out, i, n = [], 0, len(pat)
    while i < n:
        c = pat[i]
        if c == '\\' and i + 1 < n: out.append(pat[i + 1]); i += 2; continue
        if c == '%': i += 1; continue
        if c == '_': out.append('a'); i += 1; continue
        out.append(c); i += 1
    s = "".join(out)
    return s if s else "a"


def _solve_pattern(op, L, R, coltypes, enums):
    """`col ~ / ~* / !~ / LIKE / ILIKE pattern` -> seed a text value that matches / one that doesn't.
    DB-verified by solve_emit, so an imperfect generator just falls back to NOT_TESTABLE."""
    lr, rr = _side_role(L), _side_role(R)
    if lr[0] == "col" and rr[0] == "const": col, pat = lr[1], rr[1]
    elif rr[0] == "col" and lr[0] == "const": col, pat = rr[1], lr[1]
    else: return None
    ct = (coltypes.get(col, "text") or "").lower()
    if not any(k in ct for k in ("text", "char", "citext")): return None   # patterns apply to text-ish cols
    m = _like_match(pat) if "~~" in op else _regex_match(pat)
    if m is None: return None
    nm = _wv_other(coltypes.get(col, "text"), enums)                       # generic value: ~never matches
    sat, fal = _wv_ctx(), _wv_ctx()
    if op.startswith("!"): sat["row"][col] = nm; fal["row"][col] = m       # negated: true when NOT matching
    else:                  sat["row"][col] = m;  fal["row"][col] = nm
    return (sat, fal)


def _solve_between(kind, L, R, coltypes, enums):
    """`col BETWEEN lo AND hi` -> a value in range (sat) / below lo (fal). Numeric exact; dates best-effort + DB-verify."""
    col = _colname(L)
    if not col: return None
    items = R if isinstance(R, list) else (_v(R).get("items", []) if _t(R) == "List" else [])
    if len(items) < 2: return None
    lo, hi = _const(items[0]), _const(items[1])
    if lo is None or hi is None: return None
    ct = (coltypes.get(col, "") or "").lower(); sat, fal = _wv_ctx(), _wv_ctx()
    if any(k in ct for k in ("int", "numeric", "real", "double", "decimal", "serial", "money")):
        try: loi = int(float(lo))
        except Exception: return None
        sat["row"][col] = str(loi); fal["row"][col] = str(loi - 1)
    else:
        sat["row"][col] = lo; fal["row"][col] = _wv_other(coltypes.get(col, "text"), enums, lo)
    return (sat, fal) if kind == "AEXPR_BETWEEN" else (fal, sat)


def _solve_jsonb(op, L, R, coltypes, enums):
    """`jsoncol @> const` / `jsoncol ? key` / `?|` / `?&` -> seed a JSONB value that satisfies it (else '{}')."""
    lr, rr = _side_role(L), _side_role(R)
    if not (lr[0] == "col" and rr[0] == "const"): return None
    col = lr[1]
    if "json" not in (coltypes.get(col, "") or "").lower(): return None
    sat, fal = _wv_ctx(), _wv_ctx(); fal["row"][col] = "{}"
    if op == "@>":   sat["row"][col] = rr[1]                                   # a @> a is true
    elif op == "?":  sat["row"][col] = json.dumps({rr[1]: True})
    elif op in ("?|", "?&"):
        keys = _array_consts(R)
        if not keys: return None
        sat["row"][col] = json.dumps({k: True for k in keys})
    else: return None
    return (sat, fal)


def _col_textfn(node):
    """An idempotent-on-output text fn/cast over a column -> the column name (seeding col := const makes f(col)=const)."""
    if _t(node) == "TypeCast": return _colname(_v(node).get("arg"))
    if _t(node) == "FuncCall":
        fn = _names(_v(node).get("funcname")).split(".")[-1]
        if fn in ("lower", "upper", "trim", "btrim", "ltrim", "rtrim"):
            a = _v(node).get("args", []); return _colname(a[0]) if a else None
    return None


def _solve_fncol_eq(L, R, coltypes, enums):
    """`lower(col)|upper(col)|trim(col)|col::text = const` -> seed col := const (DB-verified; unsatisfiable -> NT)."""
    for x, y in ((L, R), (R, L)):
        col = _col_textfn(x); c = _const(y)
        if col and c is not None:
            sat, fal = _wv_ctx(), _wv_ctx()
            sat["row"][col] = c; fal["row"][col] = _wv_other(coltypes.get(col, "text"), enums, c)
            return (sat, fal)
    return None


def _flip_first(s):
    return ("Z" if s[:1] != "Z" else "Y") + (s[1:] if len(s) > 1 else "")


def _flip_last(s):
    return (s[:-1] if len(s) > 1 else "") + ("Z" if s[-1:] != "Z" else "Y")


def _fn_preimage(fn, args, T):
    """For a many-to-one `fn(col, …) = <const T>`, return `(col, sat_colval, fal_colval)` — a column value whose
    image equals T (sat) and one whose image differs (fal) — else None. The values are seeded into `ctx["row"]`
    and pass through `_wv_lit` (text quoted; date/time cast to the column type). DB-verified by solve_emit, so a
    wrong construction degrades to NT — never a false pass. Registry kept to cleanly-constructible fns."""
    T = str(T)
    col0 = _colname(args[0]) if args else None
    if fn in ("substring", "substr"):                       # prefix only: substring(col, 1[, n])
        if not col0 or (len(args) >= 2 and _const(args[1]) not in ("1", None)): return None
        return (col0, T + "zzz", _flip_first(T) + "zzz")
    if fn == "left":                                        # left(col, n) -> prefix
        if not col0: return None
        return (col0, T + "zzz", _flip_first(T) + "zzz")
    if fn == "right":                                       # right(col, n) -> suffix
        if not col0: return None
        return (col0, "zzz" + T, "zzz" + _flip_last(T))
    if fn == "split_part" and len(args) >= 3:               # split_part(col, delim, 1) -> first field
        delim = _const(args[1]); field = _const(args[2])
        if not col0 or field != "1" or not delim: return None
        return (col0, T + delim + "x", _flip_first(T) + delim + "x")
    if fn == "date_trunc" and len(args) >= 2:               # date_trunc(unit, col): col is the SECOND arg
        col = _colname(args[1])
        if not col: return None
        fal = "1971-02-03 04:05:06+00" if not T.startswith("1971") else "2087-08-09 10:11:12+00"
        return (col, T, fal)                                # re-truncating an aligned value is idempotent -> sat = T
    if fn == "to_char" and len(args) >= 2:                  # to_char(col, fmt) for common date formats
        fmt = _const(args[1]) or ""
        if not col0: return None
        if   fmt == "YYYY-MM-DD": sat = T
        elif fmt == "YYYY-MM":    sat = T + "-15"
        elif fmt == "YYYY":       sat = T + "-06-15"
        else: return None
        return (col0, sat, "1971-02-03" if not str(sat).startswith("1971") else "2087-08-09")
    return None


def _solve_fncol_preimage(L, R, coltypes, enums):
    """`fn(col, …) = const` for a many-to-one fn (`date_trunc`/`substring`/`left`/`right`/`to_char`/`split_part`)
    -> seed a column value whose image is the target (sat) and one whose image differs (fal). DB-verified -> NT
    on a miss. The idempotent text fns (`lower`/`upper`/`trim`/cast) are handled earlier by `_solve_fncol_eq`."""
    for x, y in ((L, R), (R, L)):
        if _t(x) != "FuncCall": continue
        c = _const(y)
        if c is None: continue
        fn = _names(_v(x).get("funcname")).split(".")[-1].lower()
        plan = _fn_preimage(fn, _v(x).get("args", []) or [], c)
        if plan:
            col, sat_v, fal_v = plan
            sat, fal = _wv_ctx(), _wv_ctx()
            sat["row"][col] = sat_v; fal["row"][col] = fal_v
            return (sat, fal)
    return None


def _solve_subquery(node, coltypes, enums):
    """WB-3: general EXISTS/IN subquery witness. Single base table, AND-only WHERE. Captures ALL correlations
    (subq col = outer col), an optional `auth.uid()` identity, and extra equality/boolean conditions on subquery
    columns (`role='admin'`, `can_read`). SAT seeds the outer row's correlation column(s) + one matching aux row
    (identity + every correlation + every extra); FAL points the outer row's correlation column(s) at a value
    with no matching aux row, so EXISTS is false. Bails (None -> NT) on joins, OR in the WHERE, a non-equality
    correlation, or a column=column it can't map to (subq, outer). DB-verified by solve_emit -> NT on a miss.
    F2: a thin adapter over the shared `_subquery_sig` reader — the shape grammar lives there, once."""
    if _t(node) != "SubLink":
        return None
    sv = _v(node); st = sv.get("subLinkType")
    if st not in ("EXISTS_SUBLINK", "ANY_SUBLINK"):
        return None
    sig = _subquery_sig(sv.get("subselect"), sv.get("testexpr") if st == "ANY_SUBLINK" else None)
    if sig is None or sig["unmodeled"] or sig["fns"] or not sig["corr"]:
        return None
    correlations, muser, extras = sig["corr"], sig["uid"], sig["extras"]
    mtable = sig["mtable"]
    sat, fal = _wv_ctx(), _wv_ctx()
    auxcols = {}
    for i, (mcol, rcol) in enumerate(correlations):
        sc = "5c09e000-0000-4000-8000-%012x" % (i + 1)
        sat["row"][rcol] = sc; auxcols[mcol] = sc
        fal["row"][rcol] = "5c09e000-0000-4000-8000-0000000000ff"   # no matching aux row -> EXISTS false
    if muser:
        sat["sub"] = fal["sub"] = _WV_UID
        auxcols[muser] = _WV_UID
    auxcols.update(extras)
    sat["aux"].append({"table": mtable, "cols": auxcols})
    return (sat, fal)



def _array_elem_type(coltype):
    """`text[]` -> `text`, `uuid[]` -> `uuid`, `integer[]` -> `integer`. None if the column isn't an array type."""
    t = (coltype or "").strip()
    return t[:-2].strip() or None if t.endswith("[]") else None


def _pg_array_literal(elems):
    """Postgres array INPUT text, e.g. `{vip,beta}` (double-quoting an element only when it has a special char);
    empty -> `{}`. This goes through `_wv_lit`, which single-quotes the whole thing, so the column's array type
    casts it on INSERT (the same trick the jsonb witness uses for a `{...}` literal)."""
    out = []
    for e in elems:
        s = str(e)
        if s == "" or re.search(r'[,{}"\\\s]', s):
            s = '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
        out.append(s)
    return "{" + ",".join(out) + "}"


def _solve_array(op, L, R, coltypes, enums):
    """`col && ARRAY[…]` (overlap) / `col @> ARRAY[…]` (col contains all) / `col <@ ARRAY[…]` (col contained in),
    in either operand order -> seed an array-valued row that satisfies the predicate and one that doesn't.
    DB-verified by solve_emit (a wrong guess -> NT, never a false pass); unsatisfiable (e.g. <@ over the whole
    enum) -> the falsifier won't verify -> NT."""
    lcol, rcol = _colname(L), _colname(R)
    lvals, rvals = _array_consts(L), _array_consts(R)
    if lcol and rvals is not None and _array_elem_type(coltypes.get(lcol)):
        col, vals, colleft = lcol, rvals, True
    elif rcol and lvals is not None and _array_elem_type(coltypes.get(rcol)):
        col, vals, colleft = rcol, lvals, False
    else:
        return None
    if not vals:
        return None
    elem = _array_elem_type(coltypes.get(col))
    eff = op
    if not colleft and op in ("@>", "<@"):                  # column on the right: `ARRAY @> col` <=> `col <@ ARRAY`
        eff = "<@" if op == "@>" else "@>"
    sat, fal = _wv_ctx(), _wv_ctx()
    if eff == "&&":                                         # overlap: share one element vs an empty array
        sat["row"][col] = _pg_array_literal([vals[0]]); fal["row"][col] = "{}"
    elif eff == "@>":                                      # col contains all of `vals` vs an empty array
        sat["row"][col] = _pg_array_literal(vals); fal["row"][col] = "{}"
    elif eff == "<@":                                      # col is a subset of `vals` vs a set with an outside element
        sat["row"][col] = _pg_array_literal([vals[0]]); fal["row"][col] = _pg_array_literal(vals + [_wv_other(elem, enums)])
    else:
        return None
    return (sat, fal)


def _solve_leaf(node, coltypes, enums):
    t = _t(node)
    if t == "A_Const": return (_wv_ctx(), None) if _const(node) == "true" else None
    if t == "NullTest":
        v = _v(node); col = _colname(v.get("arg"))
        if not col: return None
        other = _wv_other(coltypes.get(col, "text"), enums); sat, fal = _wv_ctx(), _wv_ctx()
        if v.get("nulltesttype") == "IS_NULL": sat["row"][col] = None; fal["row"][col] = other
        else: sat["row"][col] = other; fal["row"][col] = None
        return (sat, fal)
    if t == "ColumnRef":                                    # bare boolean column as the predicate: USING (is_active)
        col = _colname(node)
        if not col: return None
        sat, fal = _wv_ctx(), _wv_ctx(); sat["row"][col] = "true"; fal["row"][col] = "false"; return (sat, fal)
    if t == "BooleanTest":                                  # col IS TRUE / IS FALSE / IS NOT TRUE / IS NOT FALSE
        v = _v(node); col = _colname(v.get("arg")); bt = v.get("booltesttype")
        if not col or bt not in ("IS_TRUE", "IS_FALSE", "IS_NOT_TRUE", "IS_NOT_FALSE"): return None
        sat, fal = _wv_ctx(), _wv_ctx(); want = bt in ("IS_TRUE", "IS_NOT_FALSE")
        sat["row"][col] = "true" if want else "false"; fal["row"][col] = "false" if want else "true"
        return (sat, fal)
    if t == "SubLink":
        sv = _v(node); st = sv.get("subLinkType")
        if st in ("EXISTS_SUBLINK", "ANY_SUBLINK"):
            g = _solve_subquery(node, coltypes, enums)   # WB-3: general (multi-correlation / extra conditions / IN-subquery)
            if g: return g
            m = _membership(sv.get("subselect"), sv.get("testexpr") if st == "ANY_SUBLINK" else None)
            if m.get("kind") == "membership":
                sat, fal = _wv_ctx(), _wv_ctx(); sat["sub"] = _WV_UID; fal["sub"] = _WV_UID
                sc = "5c09e000-0000-4000-8000-000000000001"
                sat["row"][m["row_scope_col"]] = sc
                sat["aux"].append({"table": m["mtable"], "cols": {m["muser_col"]: _WV_UID, m["mscope_col"]: sc}})
                fal["row"][m["row_scope_col"]] = "5c09e000-0000-4000-8000-0000000000ff"
                return (sat, fal)
        return None
    if t != "A_Expr": return None
    v = _v(node); kind = v.get("kind"); op = _names(v.get("name")); L = v.get("lexpr"); R = v.get("rexpr")
    sl = _scalar_lookup(L, R) or _scalar_lookup(R, L)
    if sl:
        sat, fal = _wv_ctx(), _wv_ctx(); sat["sub"] = _WV_UID; fal["sub"] = _WV_UID
        sat["aux"].append({"table": sl["ltable"], "cols": {sl["lkey"]: _WV_UID, sl["lcol"]: sl["value"]}})
        fal["aux"].append({"table": sl["ltable"], "cols": {sl["lkey"]: _WV_UID, sl["lcol"]: _wv_other("text", enums, sl["value"])}})
        return (sat, fal)
    if kind == "AEXPR_OP_ANY" and op == "=":
        col = _colname(L) or _colname(R); vals = _array_consts(R) if _colname(L) else _array_consts(L)
        if col and vals:
            base = (coltypes.get(col, "") or "").split("(")[0].strip()
            outside = next((l for l in enums.get(base, []) if l not in vals), None)
            sat, fal = _wv_ctx(), _wv_ctx(); sat["row"][col] = vals[0]
            if outside is None: return (sat, None)
            fal["row"][col] = outside; return (sat, fal)
        return None
    if kind == "AEXPR_OP_ALL" and op in ("<>", "!="):
        col = _colname(L) or _colname(R); vals = _array_consts(R) if _colname(L) else _array_consts(L)
        if col and vals:
            base = (coltypes.get(col, "") or "").split("(")[0].strip()
            outside = next((l for l in enums.get(base, []) if l not in vals), None)
            if outside is None: return None
            sat, fal = _wv_ctx(), _wv_ctx(); sat["row"][col] = outside; fal["row"][col] = vals[0]; return (sat, fal)
        return None
    if kind in ("AEXPR_BETWEEN", "AEXPR_NOT_BETWEEN"): return _solve_between(kind, L, R, coltypes, enums)
    if kind == "AEXPR_OP" and op in ("@>", "?", "?|", "?&"):
        return _solve_jsonb(op, L, R, coltypes, enums) or (_solve_array(op, L, R, coltypes, enums) if op == "@>" else None)
    if kind == "AEXPR_OP" and op in ("&&", "<@"): return _solve_array(op, L, R, coltypes, enums)
    if kind == "AEXPR_OP" and op == "=": return _solve_eq(L, R, coltypes, enums) or _solve_fncol_eq(L, R, coltypes, enums) or _solve_fncol_preimage(L, R, coltypes, enums)
    if kind == "AEXPR_NOT_DISTINCT":   # `IS NOT DISTINCT FROM` = null-safe `=` -> equality witness (BL-8)
        return _solve_eq(L, R, coltypes, enums) or _solve_fncol_eq(L, R, coltypes, enums) or _solve_fncol_preimage(L, R, coltypes, enums)
    if kind == "AEXPR_DISTINCT":       # `IS DISTINCT FROM` = null-safe `<>` -> the negation of equality (swap sat/fal)
        eqp = _solve_eq(L, R, coltypes, enums)
        return (eqp[1], eqp[0]) if eqp else None
    if kind == "AEXPR_OP" and op in (">", "<", ">=", "<="): return _solve_ineq(op, L, R, coltypes, enums)
    if kind == "AEXPR_OP" and op in ("<>", "!="):
        lr, rr = _side_role(L), _side_role(R)
        if rr[0] == "col" and lr[0] == "const": lr, rr = rr, lr
        if lr[0] == "col" and rr[0] == "const":
            sat, fal = _wv_ctx(), _wv_ctx()
            sat["row"][lr[1]] = _wv_other(coltypes.get(lr[1], "text"), enums, rr[1]); fal["row"][lr[1]] = rr[1]; return (sat, fal)
        return None
    if op in ("~", "~*", "!~", "!~*", "~~", "~~*", "!~~", "!~~*"):   # regex / LIKE / ILIKE (BL-6)
        return _solve_pattern(op, L, R, coltypes, enums)
    return None


def _range_witness(args, coltypes, enums):
    """An AND that's purely numeric const-bounded comparisons on ONE column (the deparsed form of
    `col BETWEEN lo AND hi`, or `lo <= col AND col <= hi`) -> one in-range value (sat) / one out (fal).
    The generic AND merge can't co-satisfy `>=lo` and `<=hi` (each leaf picks its own boundary) — this does."""
    col = lo = hi = None; lo_inc = hi_inc = True
    for a in args:
        if _t(a) != "A_Expr": return None
        v = _v(a); op = _names(v.get("name"))
        if v.get("kind") != "AEXPR_OP" or op not in (">", ">=", "<", "<="): return None
        lr, rr = _side_role(v.get("lexpr")), _side_role(v.get("rexpr"))
        if lr[0] == "col" and rr[0] == "const": c, val, o = lr[1], rr[1], op
        elif rr[0] == "col" and lr[0] == "const": c, val, o = rr[1], lr[1], {">": "<", "<": ">", ">=": "<=", "<=": ">="}[op]
        else: return None
        if col is None: col = c
        elif c != col: return None
        if not any(k in (coltypes.get(c, "") or "").lower() for k in ("int", "numeric", "real", "double", "decimal", "serial", "money")): return None
        try: nv = int(float(val))
        except Exception: return None
        if o in (">", ">="): lo = nv if lo is None else max(lo, nv); lo_inc = (o == ">=")
        else: hi = nv if hi is None else min(hi, nv); hi_inc = (o == "<=")
    if col is None: return None
    elo = lo if (lo is None or lo_inc) else lo + 1
    ehi = hi if (hi is None or hi_inc) else hi - 1
    if elo is not None and ehi is not None:
        if elo > ehi: return None
        sat_v, fal_v = (elo + ehi) // 2, elo - 1
    elif elo is not None: sat_v, fal_v = elo, elo - 1
    else: sat_v, fal_v = ehi, ehi + 1
    sat, fal = _wv_ctx(), _wv_ctx(); sat["row"][col] = str(sat_v); fal["row"][col] = str(fal_v)
    return (sat, fal)


def _solve_node(node, coltypes, enums):
    if _t(node) == "BoolExpr":
        bo = _v(node).get("boolop"); kids = [_solve_node(a, coltypes, enums) for a in _v(node).get("args", [])]
        if bo == "NOT_EXPR":
            k = kids[0]; return (k[1], k[0]) if (k and k[1] is not None) else None
        if bo == "AND_EXPR":
            _rw = _range_witness(_v(node).get("args", []), coltypes, enums)   # single-col numeric range (deparsed BETWEEN)
            if _rw: return _rw
            sat = _wv_ctx()
            for k in kids:
                if not k: return None
                sat = _wv_merge(sat, k[0])
                if sat is None: return None
            fal = None
            for i, k in enumerate(kids):
                if not k or k[1] is None: continue
                cand = k[1]; ok = True
                for j, k2 in enumerate(kids):
                    if j == i: continue
                    cand = _wv_merge(cand, k2[0]) if k2 else None
                    if cand is None: ok = False; break
                if ok and cand is not None: fal = cand; break
            return (sat, fal)
        if bo == "OR_EXPR":
            sat = next((k[0] for k in kids if k), None)
            if sat is None: return None
            fal = _wv_ctx()
            for k in kids:
                if not k or k[1] is None: fal = None; break
                fal = _wv_merge(fal, k[1])
                if fal is None: break
            return (sat, fal)
        return None
    return _solve_leaf(node, coltypes, enums)


def _solve_predicate(node, coltypes, enums):
    """Entry point: a parsed predicate -> (sat_ctx, fal_ctx) or None. sat makes it true, fal makes it false."""
    if node is None: return None
    return _solve_node(node, coltypes, enums)

