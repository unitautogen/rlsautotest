"""No-DB unit tests for the --all-schemas combined dashboard renderer (rlsautotest.multi).

render_all_schemas_html is pure: it lays an ordered list of per-schema reports into ONE
interactive page (left schema picker, right iframe that swaps in the chosen report). These
tests lock the base64 embedding round-trip, the status roll-up chip, HTML escaping and the
self-contained structure -- no database or probe involved.
"""
import base64
import json
import re

from rlsautotest.multi import render_all_schemas_html


def _reports(doc):
    m = re.search(r"const REPORTS = (\{.*\});", doc)
    assert m, "REPORTS constant not found"
    return json.loads(m.group(1))


SCHEMAS = [
    {"schema": "alpha", "html": "<html><body>ALPHA REPORT</body></html>", "tables": 3, "flags": [], "kind": "ok"},
    {"schema": "beta", "html": "<html><body>BETA \u00e9 REPORT</body></html>", "tables": 2, "flags": ["exposed"], "kind": "warn"},
    {"schema": "gamma", "html": "<html><body>GAMMA REPORT</body></html>", "tables": 1, "flags": ["2 review cell(s)"], "kind": "note"},
]


def test_every_report_is_embedded_and_recovers_exactly():
    doc = render_all_schemas_html(SCHEMAS, db="testdb")
    reports = _reports(doc)
    assert set(reports) == {"alpha", "beta", "gamma"}
    for s in SCHEMAS:
        decoded = base64.b64decode(reports[s["schema"]]).decode("utf-8")
        assert decoded == s["html"]   # byte-for-byte, including non-ASCII


def test_one_button_per_schema_in_order():
    doc = render_all_schemas_html(SCHEMAS, db="testdb")
    assert doc.count('class="item"') == 3
    assert doc.index('data-s="alpha"') < doc.index('data-s="beta"') < doc.index('data-s="gamma"')


def test_chip_rolls_up_to_the_worst_status():
    assert 'class="chip warn"' in render_all_schemas_html(SCHEMAS, db="d")
    only_notes = render_all_schemas_html(
        [{"schema": "n", "html": "<i>x</i>", "tables": 1, "flags": [], "kind": "note"}], db="d")
    assert 'class="chip note"' in only_notes
    all_ok = render_all_schemas_html(
        [{"schema": "a", "html": "<i>x</i>", "tables": 1, "flags": [], "kind": "ok"}], db="d")
    assert 'class="chip ok"' in all_ok


def test_db_name_shown_and_optional():
    assert "testdb" in render_all_schemas_html(SCHEMAS, db="testdb")
    nodb = render_all_schemas_html(SCHEMAS)
    assert "database" not in nodb


def test_flags_render_next_to_the_name():
    doc = render_all_schemas_html(SCHEMAS, db="d")
    assert "exposed" in doc
    assert "2 review cell(s)" in doc


def test_self_contained_no_emdash_and_escapes_names():
    doc = render_all_schemas_html(SCHEMAS, db="d")
    assert "\u2014" not in doc
    assert "const REPORTS" in doc and 'id="detail"' in doc
    assert doc.strip().endswith("</html>")
    esc = render_all_schemas_html(
        [{"schema": "a<b>", "html": "<i>x</i>", "tables": 1, "flags": [], "kind": "ok"}], db="d")
    assert "a&lt;b&gt;" in esc